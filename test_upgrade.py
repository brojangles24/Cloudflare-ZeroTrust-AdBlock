import os
import sys
import asyncio
import aiohttp
import logging
import re
from typing import List, Set, Dict, Any
from pathlib import Path
from datetime import datetime
from subprocess import run, CalledProcessError
from dataclasses import dataclass

# --- 1. Configuration ---

@dataclass
class Config:
    # Cloudflare Settings
    API_TOKEN: str = os.getenv("API_TOKEN", "")
    ACCOUNT_ID: str = os.getenv("ACCOUNT_ID", "")
    PREFIX: str = "Block ads"
    MAX_LIST_SIZE: int = 1000   # Safe limit for Cloudflare Lists
    MAX_LISTS: int = 300        # Cloudflare Account Limit
    CONCURRENCY: int = 5        # Conservative concurrency to avoid 429 errors
    
    # File Settings
    OUTPUT_FILE: str = "Aggregated_List.txt"
    
    # Git Settings
    TARGET_BRANCH: str = os.getenv("GITHUB_REF_NAME") or os.getenv("TARGET_BRANCH") or "main"
    GITHUB_ACTOR: str = os.getenv("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.getenv("GITHUB_ACTOR_ID", "41898282")

    # Sources
    LIST_URLS = [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt",
        # Add your other URLs here
    ]

    @classmethod
    def validate(cls):
        if not cls.API_TOKEN or not cls.ACCOUNT_ID:
            logging.error("❌ Critical: API_TOKEN and ACCOUNT_ID must be set.")
            sys.exit(1)

CFG = Config()

# Logging Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("DNS_Blocklist")

# --- 2. Async Cloudflare Client ---

class AsyncCloudflare:
    """Handles async interactions with Cloudflare API with Rate Limiting support."""
    def __init__(self, session: aiohttp.ClientSession):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{CFG.ACCOUNT_ID}/gateway"
        self.headers = {
            "Authorization": f"Bearer {CFG.API_TOKEN}",
            "Content-Type": "application/json",
        }
        self.session = session
        self.sem = asyncio.Semaphore(CFG.CONCURRENCY) 

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        url = f"{self.base_url}/{endpoint}"
        async with self.sem:
            for attempt in range(1, 4):
                try:
                    async with self.session.request(method, url, headers=self.headers, **kwargs) as resp:
                        if resp.status == 429: # Rate limit hit
                            wait = int(resp.headers.get("Retry-After", 5))
                            logger.warning(f"⚠️ Rate limited. Waiting {wait}s...")
                            await asyncio.sleep(wait)
                            continue
                        
                        resp.raise_for_status()
                        return await resp.json()
                except Exception as e:
                    if attempt == 3:
                        logger.error(f"❌ Failed {method} {url}: {e}")
                        raise
                    await asyncio.sleep(2 * attempt) # Exponential backoff

    async def get_lists(self) -> List[Dict]:
        data = await self._request("GET", "lists")
        return data.get("result", [])

    async def get_list_items(self, list_id: str) -> Set[str]:
        # Fetches items to calculate diffs. Assumes list size < 1000 per chunk.
        data = await self._request("GET", f"lists/{list_id}/items?limit={CFG.MAX_LIST_SIZE}")
        return {item['value'] for item in data.get('result', [])}

    async def create_list(self, name: str, items: List[str]) -> str:
        payload = {"name": name, "type": "DOMAIN", "items": [{"value": i} for i in items]}
        data = await self._request("POST", "lists", json=payload)
        return data['result']['id']

    async def update_list(self, list_id: str, append: List[str], remove: List[str]):
        if not append and not remove:
            return
        payload = {"append": [{"value": i} for i in append], "remove": remove}
        await self._request("PATCH", f"lists/{list_id}", json=payload)

    async def delete_list(self, list_id: str):
        await self._request("DELETE", f"lists/{list_id}")

    async def get_policies(self) -> List[Dict]:
        data = await self._request("GET", "rules")
        return data.get("result", [])

    async def update_policy(self, policy_id: str, payload: Dict):
        await self._request("PUT", f"rules/{policy_id}", json=payload)

    async def create_policy(self, payload: Dict):
        await self._request("POST", "rules", json=payload)

# --- 3. Domain Processing Logic ---

async def download_file(session: aiohttp.ClientSession, url: str) -> str:
    """Async download of a text file."""
    try:
        async with session.get(url, timeout=30) as resp:
            resp.raise_for_status()
            logger.info(f"✅ Downloaded: {url}")
            return await resp.text()
    except Exception as e:
        logger.warning(f"⚠️ Failed to download {url}: {e}")
        return ""

def clean_domains(raw_text: str) -> Set[str]:
    """
    Parses various blocklist formats and extracts ONLY the domain.
    Strips '0.0.0.0', '127.0.0.1', comments, and whitespace.
    """
    valid_domains = set()
    localhost_ips = {'0.0.0.0', '127.0.0.1', '::1', '255.255.255.255'}
    junk_domains = {'localhost', 'broadcasthost', 'local'}

    for line in raw_text.splitlines():
        # Strip comments
        line = line.split('#')[0].strip().lower()
        if not line:
            continue

        parts = line.split()
        candidate = ""

        # CASE A: Hosts Format "0.0.0.0 example.com"
        if len(parts) >= 2 and parts[0] in localhost_ips:
            candidate = parts[1]
        # CASE B: Domain Only "example.com"
        elif len(parts) > 0:
            candidate = parts[0]

        # Validation: Must have a dot, no slash, not be an IP, not be junk
        if '.' in candidate and '/' not in candidate and candidate not in junk_domains:
            # Ensure it's not just an IP address
            if any(c.isalpha() for c in candidate):
                valid_domains.add(candidate)
            
    return valid_domains

# --- 4. Orchestration ---

async def sync_chunk(cf: AsyncCloudflare, list_obj: Dict, new_items: List[str]) -> str:
    """Worker: Syncs a single chunk of domains to a single Cloudflare List."""
    list_id = list_obj.get('id')
    list_name = list_obj.get('name')
    
    if list_id:
        # Calculate Diff
        current_items = await cf.get_list_items(list_id)
        target_items = set(new_items)
        
        to_add = list(target_items - current_items)
        to_remove = list(current_items - target_items)
        
        if to_add or to_remove:
            logger.info(f"🔄 Updating {list_name}: +{len(to_add)} / -{len(to_remove)}")
            await cf.update_list(list_id, to_add, to_remove)
        else:
            logger.info(f"⚡ {list_name} is up to date.")
    else:
        # Create New
        logger.info(f"✨ Creating {list_name}...")
        list_id = await cf.create_list(list_name, new_items)
        
    return list_id

async def main_async():
    CFG.validate()
    
    async with aiohttp.ClientSession() as session:
        cf = AsyncCloudflare(session)
        
        # --- Step 1: Aggregation (Parallel Downloads) ---
        logger.info("⬇️ Starting downloads...")
        download_tasks = [download_file(session, url) for url in CFG.LIST_URLS]
        raw_files = await asyncio.gather(*download_tasks)
        
        final_domains = set()
        for content in raw_files:
            final_domains.update(clean_domains(content))
            
        total_count = len(final_domains)
        logger.info(f"📦 Aggregation complete. Unique domains: {total_count}")
        
        if total_count == 0:
            logger.error("❌ No domains found. Exiting.")
            return 0

        # Save to file
        sorted_domains = sorted(final_domains)
        with open(CFG.OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted_domains))

        # --- Step 2: Cloudflare Sync (Parallel Operations) ---
        
        # Prepare Chunks
        chunks = [sorted_domains[i:i + CFG.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), CFG.MAX_LIST_SIZE)]
        
        if len(chunks) > CFG.MAX_LISTS:
            logger.warning(f"⚠️ Truncating lists: {len(chunks)} chunks exceeds max {CFG.MAX_LISTS}")
            chunks = chunks[:CFG.MAX_LISTS]

        logger.info(f"☁️  Syncing {len(chunks)} lists to Cloudflare...")
        
        # Fetch current lists
        all_lists = await cf.get_lists()
        our_lists = sorted([l for l in all_lists if CFG.PREFIX in l['name']], key=lambda x: x['name'])
        
        # Map chunks to list objects (or placeholders for new ones)
        sync_tasks = []
        for i, chunk in enumerate(chunks):
            list_name = f"{CFG.PREFIX} - {i+1:03d}"
            existing_list = our_lists[i] if i < len(our_lists) else {'name': list_name, 'id': None}
            sync_tasks.append(sync_chunk(cf, existing_list, chunk))
            
        # Execute Sync in Parallel
        active_list_ids = await asyncio.gather(*sync_tasks)
        
        # --- Step 3: Cleanup Excess Lists ---
        if len(our_lists) > len(chunks):
            excess = our_lists[len(chunks):]
            logger.info(f"🗑️  Deleting {len(excess)} excess lists...")
            await asyncio.gather(*[cf.delete_list(l['id']) for l in excess])

        # --- Step 4: Policy Update ---
        logger.info("🛡️  Updating Gateway Policy...")
        
        # Build "OR" expression: any(dns.domains in $list_1) or any(dns.domains in $list_2)...
        or_clauses = [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in active_list_ids]
        expression = {"or": or_clauses} if len(or_clauses) > 1 else or_clauses[0]
        
        policy_payload = {
            "name": CFG.PREFIX,
            "description": f"Blocklist: {total_count} domains. Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
            "enabled": True,
            "action": "block",
            "filters": ["dns"],
            "conditions": [{"type": "traffic", "expression": expression}]
        }

        policies = await cf.get_policies()
        existing_policy = next((p for p in policies if p['name'] == CFG.PREFIX), None)
        
        if existing_policy:
            await cf.update_policy(existing_policy['id'], policy_payload)
        else:
            await cf.create_policy(policy_payload)
            
        logger.info("✅ Cloudflare Sync Finished.")
        return total_count

# --- 5. Git Operations ---

def git_commit(total_lines: int):
    """Commits changes to Git if running in a repo."""
    if not Path(".git").exists():
        logger.warning("🚫 Not a Git repository. Skipping commit.")
        return

    logger.info("🐙 Processing Git operations...")
    
    def git(args: List[str]):
        run(["git"] + args, check=True, capture_output=True, text=True)

    try:
        # Check for changes
        try:
            run(["git", "diff", "--exit-code", CFG.OUTPUT_FILE], check=True, capture_output=True)
            logger.info("🤷 No changes in domain list.")
            return
        except CalledProcessError:
            pass # Changes detected, proceed

        # Config User
        git(["config", "--local", "user.email", f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"])
        git(["config", "--local", "user.name", CFG.GITHUB_ACTOR])
        
        # Add & Commit
        git(["add", CFG.OUTPUT_FILE])
        git(["commit", "-m", f"Update: {total_lines} domains"])
        
        # Pull & Push
        git(["pull", "--rebase", "origin", CFG.TARGET_BRANCH])
        git(["push", "origin", CFG.TARGET_BRANCH])
        logger.info("✅ Git push complete.")
        
    except Exception as e:
        logger.error(f"❌ Git operations failed: {e}")

# --- Entry Point ---

def main():
    try:
        # Windows AsyncIO policy fix
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            
        total = asyncio.run(main_async())
        
        if total > 0:
            git_commit(total)
            
    except KeyboardInterrupt:
        logger.info("🛑 Script interrupted by user.")
    except Exception as e:
        logger.critical(f"☠️ Fatal Error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
