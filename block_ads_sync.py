import os
import sys
import tempfile
import shutil
import re
import concurrent.futures
import json
import logging
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
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/hosts/tif.mini.txt", 
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
DOMAIN_EXTRACT_PATTERN = re.compile(r'^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}\s+)?(.+)$')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1'}

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
    """Run a shell command and raise an error on non-zero exit code."""
    command_str = ' '.join(command)
    logger.debug(f"Running command: {command_str}")
    try:
        run(command, check=True, capture_output=True, text=True, encoding='utf-8')
    except CalledProcessError as e:
        logger.error(f"Command failed: {command_str}")
        logger.debug(f"Stderr: {e.stderr.strip()}")
        raise RuntimeError(f"Command failed: {command_str}")

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


# --- 4. Workflow Functions ---

def run_aggregation(feed_config):
    """Download lists for a specific feed, process, and save to local file."""
    logger.info(f"--- Aggregating: {feed_config['name']} ---")
    
    output_path = Path(feed_config['filename'])
    list_urls = feed_config['urls']
    temp_dir = Path(tempfile.mkdtemp())

    # 1. Download Lists in Parallel
    logger.info(f"Downloading {len(list_urls)} lists...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {
            executor.submit(download_list, url, temp_dir / f"list_{i}.txt"): url
            for i, url in enumerate(list_urls)
        }
        concurrent.futures.wait(future_to_url)

    # 2. Process, Normalize, and Deduplicate
    unique_domains = set()
    for file_path in temp_dir.glob("list_*.txt"):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    match = DOMAIN_EXTRACT_PATTERN.match(line)
                    if match:
                        domain = match.group(1).split()[0].lower()
                        if domain and domain not in COMMON_JUNK_DOMAINS and '.' in domain:
                            if not INVALID_CHARS_PATTERN.search(domain):
                                unique_domains.add(domain)
        except Exception as e:
            logger.warning(f"Error processing file {file_path}: {e}")

    # 3. Save unique entries
    output_path.write_text('\n'.join(sorted(unique_domains)) + '\n', encoding='utf-8')
    logger.info(f"Saved {len(unique_domains)} domains to {output_path}.")
    shutil.rmtree(temp_dir)
    return len(unique_domains)

def sync_cloudflare(cf_client, feed_config, total_lines):
    """Sync the specific feed's domains to Cloudflare Gateway using an existing session."""
    logger.info(f"--- Syncing: {feed_config['name']} ---")
    
    output_path = Path(feed_config['filename'])
    prefix = feed_config['prefix']
    policy_name = feed_config['policy_name']

    # Git diff check to see if we really need to sync
    try:
        run_command(["git", "diff", "--exit-code", str(output_path)])
        # If exit code is 0, no changes. However, we proceed if forced or to ensure CF consistency.
        # Uncomment below to skip sync if local file hasn't changed (optional optimization)
        # logger.info("Local file unchanged. Skipping Cloudflare sync.")
        # return False 
    except RuntimeError:
        pass # Diff found (exit code 1), proceed.

    if total_lines == 0:
        return False

    total_lists_needed = (total_lines + CFG.MAX_LIST_SIZE - 1) // CFG.MAX_LIST_SIZE
    
    # Fetch current state (using the passed client)
    all_current_lists = cf_client.get_lists().get('result', [])
    current_policies = cf_client.get_rules().get('result', [])

    current_lists_with_prefix = [l for l in all_current_lists if prefix in l.get('name', '')]
    other_lists_count = len(all_current_lists) - len(current_lists_with_prefix)
    
    if total_lists_needed > CFG.MAX_LISTS - other_lists_count:
        logger.error(f"Not enough capacity! Needed: {total_lists_needed}, Available: {CFG.MAX_LISTS - other_lists_count}")
        return False

    # Read domains
    domains_content = output_path.read_text(encoding='utf-8').splitlines()
    
    used_list_ids = []
    excess_list_ids = [l['id'] for l in current_lists_with_prefix]

    # Process in chunks
    for i, domains_chunk in enumerate(chunked_iterable(domains_content, CFG.MAX_LIST_SIZE)):
        list_name = f"{prefix} - {i + 1:03d}"
        items_json = domains_to_cf_items(domains_chunk)
        
        if excess_list_ids:
            list_id = excess_list_ids.pop(0)
            logger.info(f"Updating list {list_id} ({list_name})...")
            # Optim: only fetch items if we are updating
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

def git_configure():
    """Configure git user once."""
    git_user_name = f"{CFG.GITHUB_ACTOR}[bot]"
    git_user_email = f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"
    run_command(["git", "config", "--global", "user.email", git_user_email])
    run_command(["git", "config", "--global", "user.name", git_user_name])

def git_commit_and_push(changed_files):
    """Commit all changed files in one go."""
    logger.info("--- Git Commit & Push ---")
    
    if not changed_files:
        logger.info("No files changed. Skipping commit.")
        return

    for f in changed_files:
        run_command(["git", "add", f])
    
    try:
        run_command(["git", "commit", "-m", f"Update blocklists: {', '.join(changed_files)}"])
    except RuntimeError as e:
        if "nothing to commit" in str(e):
            logger.info("Nothing to commit.")
            return
        raise
    
    if run(["git", "remote", "get-url", "origin"], check=False, capture_output=True).returncode == 0:
        logger.info(f"Pushing to {CFG.TARGET_BRANCH}...")
        run_command(["git", "push", "origin", CFG.TARGET_BRANCH])
    else:
        logger.warning("No remote found. Skipping push.")

# --- 5. Main Execution ---
def main():
    try:
        logger.info("--- 0. Initializing ---")
        CFG.validate()
        is_git_repo = Path(".git").exists()
        changed_files_list = []

        if is_git_repo:
            try:
                run_command(["git", "fetch", "origin", CFG.TARGET_BRANCH])
                run_command(["git", "checkout", CFG.TARGET_BRANCH])
                run_command(["git", "reset", "--hard", f"origin/{CFG.TARGET_BRANCH}"])
                git_configure()
            except Exception as e:
                logger.warning(f"Git init warning: {e}")

        # Open Cloudflare Session ONCE for the whole run
        with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf_client:
            
            for feed in CFG.FEED_CONFIGS:
                try:
                    # 1. Aggregate
                    total_lines = run_aggregation(feed)
                    
                    # 2. Sync (Passing the open client)
                    sync_success = sync_cloudflare(cf_client, feed, total_lines)
                    
                    if sync_success:
                        changed_files_list.append(feed['filename'])
                        
                except Exception as e:
                    logger.error(f"Failed to process feed '{feed['name']}': {e}", exc_info=True)

        # 3. Final Commit (One commit for everything)
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
