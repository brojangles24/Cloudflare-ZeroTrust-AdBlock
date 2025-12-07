import os
import sys
import tempfile
import shutil
import re
import concurrent.futures
import json
import logging
import argparse
from pathlib import Path
from subprocess import run, CalledProcessError
from itertools import islice

import requests

# --- 1. Configuration & Setup ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class Config:
    API_TOKEN: str = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID: str = os.environ.get("ACCOUNT_ID", "")
    
    # Global Limits
    MAX_LIST_SIZE: int = 1000
    MAX_LISTS: int = 300 
    MAX_RETRIES: int = 5
    
    # Git Configuration
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main"
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

    # --- DEFINITION OF FEEDS ---
    # Note: The names here are used for the deduplication logic in main()
    FEED_CONFIGS = [
        {
            "name": "Ad Block Feed",
            "prefix": "Block ads",
            "policy_name": "Block ads",
            "filename": "HaGeZi_Light.txt",
            "urls": [
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
            ]
        },
        {
            "name": "Threat Intel Feed",
            "prefix": "TIF Mini",
            "policy_name": "Threat Intelligence Feed",
            "filename": "TIF_Mini.txt",
            "urls": [
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt", 
            ]
        }
    ]

    @classmethod
    def validate(cls):
        if not cls.API_TOKEN:
            raise ScriptExit("API_TOKEN environment variable is not set.", critical=True)
        if not cls.ACCOUNT_ID:
            raise ScriptExit("ACCOUNT_ID environment variable is not set.", critical=True)

CFG = Config()

# --- 2. Helper Functions & Exceptions ---

INVALID_CHARS_PATTERN = re.compile(r'[<>&;\"\'/=\s]')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1', 'broadcasthost'}

class ScriptExit(Exception):
    def __init__(self, message, silent=False, critical=False):
        super().__init__(message)
        self.silent = silent
        self.critical = critical

def domains_to_cf_items(domains):
    return [{"value": domain} for domain in domains if domain]

def chunked_iterable(iterable, size):
    """Yield successive chunks from iterable."""
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk

def run_command(command):
    """Run a shell command. Raises RuntimeError with the actual error output if it fails."""
    command_str = ' '.join(command)
    logger.debug(f"Running command: {command_str}")
    try:
        result = run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        return result.stdout
    except CalledProcessError as e:
        error_msg = f"Command failed: {command_str}\nSTDERR: {e.stderr}\nSTDOUT: {e.stdout}"
        logger.debug(error_msg)
        raise RuntimeError(error_msg)

def download_list(url, file_path):
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    file_path.write_bytes(response.content)

# --- 3. Cloudflare API Client ---

class CloudflareAPI:
    def __init__(self, account_id, api_token, max_retries):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        self.max_retries = max_retries
        self.session = None

    def __enter__(self):
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=self.max_retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.session:
            self.session.close()

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}/{endpoint}"
        try:
            response = self.session.request(method, url, headers=self.headers, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Cloudflare API failed for {method} {url}")
            raise RuntimeError(f"Cloudflare API failed: {e}")

    def get_lists(self): return self._request("GET", "lists")
    def get_list_items(self, list_id, limit): return self._request("GET", f"lists/{list_id}/items?limit={limit}")
    def update_list(self, list_id, append_items, remove_items):
        data = {"append": append_items, "remove": remove_items}
        return self._request("PATCH", f"lists/{list_id}", json=data)
    def create_list(self, name, items):
        data = {"name": name, "type": "DOMAIN", "items": items}
        return self._request("POST", "lists", json=data)
    def delete_list(self, list_id): return self._request("DELETE", f"lists/{list_id}")
    def get_rules(self): return self._request("GET", "rules")
    def create_rule(self, payload): return self._request("POST", "rules", json=payload)
    def update_rule(self, rule_id, payload): return self._request("PUT", f"rules/{rule_id}", json=payload)
    def delete_rule(self, rule_id): return self._request("DELETE", f"rules/{rule_id}")


# --- 4. Workflow Functions ---

def fetch_domains(feed_config):
    """Download and process lists for a feed, returning a SET of domains."""
    logger.info(f"--- Fetching: {feed_config['name']} ---")
    
    list_urls = feed_config['urls']
    temp_dir = Path(tempfile.mkdtemp())
    unique_domains = set()

    # 1. Download Lists
    logger.info(f"Downloading {len(list_urls)} lists...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {
            executor.submit(download_list, url, temp_dir / f"list_{i}.txt"): url
            for i, url in enumerate(list_urls)
        }
        concurrent.futures.wait(future_to_url)

    # 2. Process
    for file_path in temp_dir.glob("list_*.txt"):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    
                    parts = line.split()
                    if not parts: continue
                    candidate = parts[-1].lower() # Assume hosts format (last item), works for pure list too
                    
                    if '.' in candidate and not INVALID_CHARS_PATTERN.search(candidate):
                         if candidate not in COMMON_JUNK_DOMAINS:
                             unique_domains.add(candidate)
        except Exception as e:
            logger.warning(f"Error processing file {file_path}: {e}")

    shutil.rmtree(temp_dir)
    logger.info(f"Fetched {len(unique_domains)} unique domains.")
    return unique_domains

def save_and_sync(cf_client, feed_config, domain_set):
    """Save the set to file and sync to Cloudflare."""
    output_path = Path(feed_config['filename'])
    
    # Sort and Save
    logger.info(f"Saving {len(domain_set)} domains to {output_path}...")
    output_path.write_text('\n'.join(sorted(domain_set)) + '\n', encoding='utf-8')
    
    # Sync Logic
    prefix = feed_config['prefix']
    policy_name = feed_config['policy_name']
    total_lines = len(domain_set)

    if total_lines == 0:
        logger.warning(f"Feed {feed_config['name']} is empty. Skipping Sync.")
        return False

    # Git diff check (Optional optimization)
    try:
        run_command(["git", "diff", "--exit-code", str(output_path)])
        # pass # Proceed anyway to ensure Cloudflare consistency
    except RuntimeError:
        pass 

    total_lists_needed = (total_lines + CFG.MAX_LIST_SIZE - 1) // CFG.MAX_LIST_SIZE
    
    all_current_lists = cf_client.get_lists().get('result', [])
    current_policies = cf_client.get_rules().get('result', [])

    current_lists_with_prefix = [l for l in all_current_lists if prefix in l.get('name', '')]
    other_lists_count = len(all_current_lists) - len(current_lists_with_prefix)
    
    if total_lists_needed > CFG.MAX_LISTS - other_lists_count:
        logger.error(f"Not enough capacity! Needed: {total_lists_needed}, Available: {CFG.MAX_LISTS - other_lists_count}")
        return False

    used_list_ids = []
    excess_list_ids = [l['id'] for l in current_lists_with_prefix]

    # Process chunks
    # Note: We convert set to sorted list for chunking
    sorted_domains = sorted(domain_set)
    for i, domains_chunk in enumerate(chunked_iterable(sorted_domains, CFG.MAX_LIST_SIZE)):
        list_name = f"{prefix} - {i + 1:03d}"
        items_json = domains_to_cf_items(domains_chunk)
        
        if excess_list_ids:
            list_id = excess_list_ids.pop(0)
            logger.info(f"Updating list {list_id} ({list_name})...")
            # Clear old items first (simplified approach for reliability)
            # Fetching old items to remove them is best practice
            old_items = cf_client.get_list_items(list_id, CFG.MAX_LIST_SIZE).get('result', [])
            remove_items = [item['value'] for item in old_items if item.get('value')]
            cf_client.update_list(list_id, append_items=items_json, remove_items=remove_items)
            used_list_ids.append(list_id)
        else:
            logger.info(f"Creating new list: {list_name}...")
            result = cf_client.create_list(list_name, items_json)
            used_list_ids.append(result['result']['id'])
    
    # Update Policy
    policy_id = next((p['id'] for p in current_policies if p.get('name') == policy_name), None)
    
    or_clauses = [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in used_list_ids]
    expression_json = {"or": or_clauses} if len(or_clauses) > 1 else (or_clauses[0] if or_clauses else {"not": {"eq": {"lhs": "dns.domains", "rhs": "null"}}})

    policy_payload = {
        "name": policy_name,
        "conditions": [{"type": "traffic", "expression": expression_json}],
        "action": "block",
        "enabled": True,
        "description": f"Managed by script: {feed_config['name']}",
        "rule_settings": {"block_page_enabled": False},
        "filters": ["dns"]
    }
    
    if policy_id:
        existing_policy = next((p for p in current_policies if p.get('id') == policy_id), {})
        if existing_policy.get('conditions', [{}])[0].get('expression') != expression_json:
            logger.info(f"Updating policy '{policy_name}'...")
            cf_client.update_rule(policy_id, policy_payload)
        else:
            logger.info(f"Policy '{policy_name}' up to date.")
    else:
        logger.info(f"Creating policy '{policy_name}'...")
        cf_client.create_rule(policy_payload)
        
    # Cleanup Excess
    for list_id in excess_list_ids:
        logger.info(f"Deleting excess list {list_id}...")
        try:
            cf_client.delete_list(list_id)
        except Exception as e:
            logger.warning(f"Failed to delete {list_id}: {e}")

    return True

def cleanup_resources(cf_client):
    logger.info("--- ⚠️ CLEANUP MODE: DELETING RESOURCES ⚠️ ---")
    current_policies = cf_client.get_rules().get('result', [])
    all_current_lists = cf_client.get_lists().get('result', [])

    for feed in CFG.FEED_CONFIGS:
        logger.info(f"Cleaning up resources for: {feed['name']}")
        prefix = feed['prefix']
        policy_name = feed['policy_name']

        policy_id = next((p['id'] for p in current_policies if p.get('name') == policy_name), None)
        if policy_id:
            logger.info(f"Deleting Policy: {policy_name} ({policy_id})...")
            try:
                cf_client.delete_rule(policy_id)
            except Exception as e:
                logger.error(f"Failed to delete policy {policy_id}: {e}")

        lists_to_delete = [l for l in all_current_lists if prefix in l.get('name', '')]
        for lst in lists_to_delete:
            logger.info(f"Deleting List: {lst['name']} ({lst['id']})...")
            try:
                cf_client.delete_list(lst['id'])
            except Exception as e:
                logger.error(f"Failed to delete list {lst['id']}: {e}")
    logger.info("--- Cleanup Complete ---")

def git_configure():
    git_user_name = f"{CFG.GITHUB_ACTOR}[bot]"
    git_user_email = f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"
    run_command(["git", "config", "--global", "user.email", git_user_email])
    run_command(["git", "config", "--global", "user.name", git_user_name])

def git_commit_and_push(changed_files):
    logger.info("--- Git Commit & Push ---")
    if not changed_files: return
    for f in changed_files: run_command(["git", "add", f])
    try:
        run_command(["git", "commit", "-m", f"Update blocklists: {', '.join(changed_files)}"])
    except RuntimeError as e:
        if "nothing to commit" in str(e):
            logger.info("Nothing to commit.")
            return
        logger.error(f"Git commit failed with: {e}")
        raise
    
    if run(["git", "remote", "get-url", "origin"], check=False, capture_output=True).returncode == 0:
        logger.info(f"Pushing to {CFG.TARGET_BRANCH}...")
        run_command(["git", "push", "origin", CFG.TARGET_BRANCH])

# --- 5. Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Cloudflare Gateway Blocklist Manager")
    parser.add_argument("--delete", action="store_true", help="Delete all lists and policies defined in config")
    args = parser.parse_args()

    try:
        logger.info("--- 0. Initializing ---")
        CFG.validate()
        
        with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf_client:
            
            if args.delete:
                cleanup_resources(cf_client)
                return

            # --- Git Setup ---
            is_git_repo = Path(".git").exists()
            if is_git_repo:
                try:
                    run_command(["git", "fetch", "origin", CFG.TARGET_BRANCH])
                    run_command(["git", "checkout", CFG.TARGET_BRANCH])
                    run_command(["git", "reset", "--hard", f"origin/{CFG.TARGET_BRANCH}"])
                    git_configure()
                except Exception as e:
                    logger.warning(f"Git init warning: {e}")

            # --- 1. Fetch ALL domains first ---
            # We map the feed name to its dataset so we can manipulate them
            feed_datasets = {}
            for feed in CFG.FEED_CONFIGS:
                feed_datasets[feed['name']] = fetch_domains(feed)

            # --- 2. Deduplication (Overlap Logic) ---
            # "If overlap, keep in Ad Block (Hagezi Normal), remove from TIF"
            ad_feed_name = "Ad Block Feed"
            tif_feed_name = "Threat Intel Feed"
            
            if ad_feed_name in feed_datasets and tif_feed_name in feed_datasets:
                ad_domains = feed_datasets[ad_feed_name]
                tif_domains = feed_datasets[tif_feed_name]
                
                # Calculate Intersection
                overlap = ad_domains.intersection(tif_domains)
                
                if overlap:
                    logger.info(f"🔍 Found {len(overlap)} domains in both lists.")
                    # Remove from TIF (Keep in Ad Block)
                    feed_datasets[tif_feed_name] = tif_domains - overlap
                    logger.info(f"✅ Removed overlapping domains from {tif_feed_name}.")
                else:
                    logger.info("No overlap found between feeds.")

            # --- 3. Save & Sync Loop ---
            changed_files_list = []
            for feed in CFG.FEED_CONFIGS:
                try:
                    dataset = feed_datasets[feed['name']]
                    sync_success = save_and_sync(cf_client, feed, dataset)
                    if sync_success:
                        changed_files_list.append(feed['filename'])
                except Exception as e:
                    logger.error(f"Failed to process feed '{feed['name']}': {e}", exc_info=True)

            # --- 4. Git Push ---
            if is_git_repo and changed_files_list:
                git_commit_and_push(changed_files_list)

        logger.info("✅ Execution complete!")

    except ScriptExit as e:
        if e.silent: sys.exit(0)
        logger.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
