import os
import sys
import tempfile
import shutil
import re
import concurrent.futures
import logging
import argparse
import time
from typing import List, Set, Dict, Optional, Iterable
from pathlib import Path
from subprocess import run, CalledProcessError
from itertools import islice
from dataclasses import dataclass, field

import requests

# --- 1. Configuration & Constants ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- TLD CONSTANTS (Truncated for brevity, same as before) ---
BLOCKED_TLDS = (
    ".zip", ".mov", ".xyz", ".top", ".gdn", ".win", ".loan", ".bid", ".stream", 
    ".tk", ".ml", ".ga", ".cf", ".gq", ".cn", ".ru", ".sbs", ".cfd", ".bond", 
    ".es", ".xn--11b4c3d", ".xn--1ck2e1b", ".xn--1qqw23a", ".xn--2scrj9c",
    # ... (Keep your full list here) ...
)

@dataclass
class FeedConfig:
    name: str
    prefix: str
    policy_name: str
    filename: str
    urls: List[str]

class Config:
    API_TOKEN: str = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID: str = os.environ.get("ACCOUNT_ID", "")
    
    # Global Limits
    MAX_LIST_SIZE: int = 1000
    MAX_LISTS: int = 300 
    MAX_RETRIES: int = 5
    
    # Git
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main" 
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

    # Local Whitelist File (Domains here are NEVER blocked)
    ALLOWLIST_FILE: str = "allowlist.txt"

    # Feeds (Priority Order)
    FEEDS: List[FeedConfig] = [
        FeedConfig(
            name="Ad Block Feed",
            prefix="Block ads",
            policy_name="Block Ads, Trackers and Telemetry",
            filename="HaGeZi_Normal.txt",
            urls=["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt"]
        ),
        FeedConfig(
            name="Security Feed",
            prefix="Block Security",
            policy_name="Block Security Risks",
            filename="HaGeZi_Security.txt",
            urls=[
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/badware-onlydomains.txt",
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt"
            ]
        ),
        FeedConfig(
            name="Threat Intel Feed",
            prefix="TIF Mini",
            policy_name="Threat Intelligence Feed",
            filename="TIF_Mini.txt",
            urls=["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"]
        )
    ]

    @classmethod
    def validate(cls):
        if not cls.API_TOKEN:
            raise ScriptExit("API_TOKEN environment variable is not set.", critical=True)
        if not cls.ACCOUNT_ID:
            raise ScriptExit("ACCOUNT_ID environment variable is not set.", critical=True)

CFG = Config()

# --- 2. Helper Functions ---

VALID_DOMAIN_PATTERN = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1', 'broadcasthost', 'ip6-localhost'}

class ScriptExit(Exception):
    def __init__(self, message, silent=False, critical=False):
        super().__init__(message)
        self.silent = silent
        self.critical = critical

def chunked_iterable(iterable, size):
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk: break
        yield chunk

def run_command(command):
    try:
        result = run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        return result.stdout.strip()
    except CalledProcessError as e:
        logger.debug(f"Command failed: {command}\nSTDERR: {e.stderr}")
        raise RuntimeError(f"Command failed: {e.stderr}")

def load_allowlist(filename: str) -> Set[str]:
    path = Path(filename)
    if not path.exists():
        return set()
    logger.info(f"🔓 Loading allowlist from {filename}...")
    allowed = set()
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                allowed.add(line.lower())
    logger.info(f"   Allowlisted {len(allowed)} domains.")
    return allowed

# --- 3. Cloudflare API Client ---

class CloudflareAPI:
    def __init__(self, account_id, api_token, max_retries, dry_run=False):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
        self.max_retries = max_retries
        self.dry_run = dry_run
        self.session = None

    def __enter__(self):
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=self.max_retries)
        self.session.mount('https://', adapter)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.session: self.session.close()

    def _request(self, method, endpoint, **kwargs):
        if self.dry_run and method not in ['GET']:
            logger.info(f"[DRY RUN] Would execute {method} {endpoint}")
            # Mock responses for create/update/delete
            if method == 'POST': return {'result': {'id': 'dry-run-id'}}
            return {'result': {}}

        url = f"{self.base_url}/{endpoint}"
        retries = 0
        while retries <= self.max_retries:
            try:
                response = self.session.request(method, url, headers=self.headers, **kwargs)
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    time.sleep(retry_after)
                    retries += 1
                    continue
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                if retries == self.max_retries: raise
                retries += 1
                time.sleep(retries * 2)

    def get_lists(self): return self._request("GET", "lists")
    def replace_list_items(self, list_id, items): return self._request("PUT", f"lists/{list_id}", json={"items": items})
    def create_list(self, name, items): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items})
    def delete_list(self, list_id): return self._request("DELETE", f"lists/{list_id}")
    def get_rules(self): return self._request("GET", "rules")
    def create_rule(self, payload): return self._request("POST", "rules", json=payload)
    def update_rule(self, rule_id, payload): return self._request("PUT", f"rules/{rule_id}", json=payload)
    def delete_rule(self, rule_id): return self._request("DELETE", f"rules/{rule_id}")

# --- 4. Logic Functions ---

def download_file(url, path):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        path.write_bytes(r.content)
        return True
    except Exception as e:
        logger.warning(f"Failed to download {url}: {e}")
        return False

def fetch_domains(feed_config: FeedConfig, allowlist: Set[str]) -> Set[str]:
    logger.info(f"--- Fetching: {feed_config.name} ---")
    temp_dir = Path(tempfile.mkdtemp())
    valid_domains = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(download_file, url, temp_dir / f"list_{i}.txt") 
                   for i, url in enumerate(feed_config.urls)]
        concurrent.futures.wait(futures)

    for file_path in temp_dir.glob("list_*.txt"):
        if not file_path.exists(): continue
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    
                    candidate = line.split()[-1].lower()
                    
                    if (candidate in allowlist or 
                        candidate in COMMON_JUNK_DOMAINS or 
                        candidate.endswith(BLOCKED_TLDS)):
                        continue

                    if VALID_DOMAIN_PATTERN.match(candidate):
                        valid_domains.add(candidate)
        except Exception:
            pass

    shutil.rmtree(temp_dir)
    logger.info(f"   Fetched {len(valid_domains)} valid unique domains (post-allowlist).")
    return valid_domains

def sync_feed(cf_client: CloudflareAPI, feed: FeedConfig, domains: Set[str]):
    if not domains:
        logger.warning(f"Feed {feed.name} is empty. Skipping.")
        return

    sorted_domains = sorted(domains)
    chunks = list(chunked_iterable(sorted_domains, CFG.MAX_LIST_SIZE))
    total_needed = len(chunks)

    # Fetch Infrastructure
    all_lists = cf_client.get_lists().get('result') or []
    my_lists = sorted([l for l in all_lists if feed.prefix in l.get('name', '')], key=lambda x: x['name'])
    
    # Check Capacity
    available = CFG.MAX_LISTS - (len(all_lists) - len(my_lists))
    if total_needed > available:
        logger.error(f"❌ Capacity exceeded for {feed.name}! Need {total_needed}, have {available}.")
        return

    used_ids = []
    
    logger.info(f"⚡ Syncing {total_needed} lists (Parallel)...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_map = {}
        for i, chunk in enumerate(chunks):
            list_name = f"{feed.prefix} - {i + 1:03d}"
            payload = [{"value": d} for d in chunk]
            
            if i < len(my_lists):
                lid = my_lists[i]['id']
                used_ids.append(lid)
                future_map[executor.submit(cf_client.replace_list_items, lid, payload)] = f"Update {list_name}"
            else:
                future_map[executor.submit(cf_client.create_list, list_name, payload)] = f"Create {list_name}"
        
        for f in concurrent.futures.as_completed(future_map):
            try:
                res = f.result()
                if "Create" in future_map[f] and not cf_client.dry_run:
                    used_ids.append(res['result']['id'])
                elif "Create" in future_map[f] and cf_client.dry_run:
                    used_ids.append("dry-run-id")
            except Exception as e:
                logger.error(f"{future_map[f]} failed: {e}")

    # Cleanup Excess
    if len(my_lists) > total_needed:
        for lst in my_lists[total_needed:]:
            logger.info(f"Deleting excess list: {lst['name']}")
            cf_client.delete_list(lst['id'])

    # Update Policy
    policies = cf_client.get_rules().get('result') or []
    pid = next((p['id'] for p in policies if p.get('name') == feed.policy_name), None)
    
    # Construct expression
    or_clauses = [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in used_ids]
    expr = {"or": or_clauses} if len(or_clauses) > 1 else (or_clauses[0] if or_clauses else {})
    
    payload = {
        "name": feed.policy_name,
        "conditions": [{"type": "traffic", "expression": expr}],
        "action": "block",
        "enabled": True,
        "description": f"Managed by script: {feed.name}",
        "filters": ["dns"]
    }

    if pid:
        logger.info(f"Updating policy '{feed.policy_name}'...")
        cf_client.update_rule(pid, payload)
    else:
        logger.info(f"Creating policy '{feed.policy_name}'...")
        cf_client.create_rule(payload)

# --- 5. Main ---

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true", help="Simulate without changes")
    p.add_argument("--force", action="store_true", help="Force update regardless of diff")
    args = p.parse_args()

    CFG.validate()
    allowlist = load_allowlist(CFG.ALLOWLIST_FILE)
    
    with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES, args.dry_run) as cf:
        
        # Git Init
        is_git = Path(".git").exists() and not args.dry_run
        if is_git:
            try:
                run_command(["git", "fetch", "origin", CFG.TARGET_BRANCH])
                run_command(["git", "checkout", CFG.TARGET_BRANCH])
                run_command(["git", "reset", "--hard", f"origin/{CFG.TARGET_BRANCH}"])
            except Exception as e: 
                logger.warning(f"Git warning: {e}")

        global_seen = set()
        changed_files = []

        # Waterfall Processing
        for feed in CFG.FEEDS:
            raw = fetch_domains(feed, allowlist)
            unique = raw - global_seen
            
            if len(raw) != len(unique):
                logger.info(f"   Waterfall: Removed {len(raw) - len(unique)} duplicates.")
            
            global_seen.update(unique)
            
            # Local File Check
            out_path = Path(feed.filename)
            new_text = '\n'.join(sorted(unique)) + '\n'
            
            has_diff = True
            if out_path.exists():
                old_text = out_path.read_text(encoding='utf-8')
                if old_text == new_text:
                    has_diff = False
                    logger.info(f"✅ {feed.name}: No local changes.")
            
            if has_diff or args.force:
                # Stats calculation
                old_lines = set(out_path.read_text().splitlines()) if out_path.exists() else set()
                new_lines = set(new_text.splitlines())
                added = len(new_lines - old_lines)
                removed = len(old_lines - new_lines)
                logger.info(f"Diff Stats: +{added} / -{removed} domains")

                if not args.dry_run:
                    out_path.write_text(new_text, encoding='utf-8')
                    changed_files.append(feed.filename)
                    sync_feed(cf, feed, unique)
                else:
                    logger.info("[DRY RUN] Would save file and sync to Cloudflare.")
            else:
                logger.info(f"Skipping sync for {feed.name}.")

        if is_git and changed_files:
            run_command(["git", "config", "--global", "user.email", f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"])
            run_command(["git", "config", "--global", "user.name", f"{CFG.GITHUB_ACTOR}[bot]"])
            run_command(["git", "add"] + changed_files)
            run_command(["git", "commit", "-m", "Update blocklists"])
            run_command(["git", "push", "origin", CFG.TARGET_BRANCH])

if __name__ == "__main__":
    main()
