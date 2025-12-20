import os
import sys
import tempfile
import shutil
import re
import concurrent.futures
import json
import logging
import argparse
import time
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

    # --- 50 CONSERVATIVE BLOCKED TLDs ---
    BLOCKED_TLDS = (
        ".zip", ".mov", ".su", ".kp", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
        ".top", ".icu", ".gdn", ".xin", ".bond", ".sbs", ".cfd", ".quest", ".motorcycles", ".ooo",
        ".win", ".bid", ".loan", ".qpon", ".cheap", ".deals", ".forsale", ".bargains", ".jewelry", ".accountant",
        ".download", ".flash", ".click", ".surf", ".stream", ".monster", ".bar", ".rest", ".boats", ".yachts",
        ".faith", ".degree", ".rip", ".webcam", ".pink", ".country", ".mom", ".men", ".party", ".yokohama"
    )

    # --- DEFINITION OF FEEDS ---
    FEED_CONFIGS = [
        {
            "name": "Ad Block Feed",
            "prefix": "Block ads",
            "policy_name": "Block Ads, Trackers and Telemetry",
            "filename": "HaGeZi_Normal.txt",
            "urls": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt"]
        },
        {
            "name": "Security Feed",
            "prefix": "Block Security",
            "policy_name": "Block Security Risks",
            "filename": "HaGeZi_Security.txt",
            "urls": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt"]
        },
        {
            "name": "Threat Intel Feed",
            "prefix": "TIF Mini",
            "policy_name": "Threat Intelligence Feed",
            "filename": "TIF_Mini.txt",
            "urls": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"]
        }
    ]

    @classmethod
    def validate(cls):
        if not cls.API_TOKEN:
            raise ScriptExit("API_TOKEN environment variable is not set.", critical=True)
        if not cls.ACCOUNT_ID:
            raise ScriptExit("ACCOUNT_ID environment variable is not set.", critical=True)

# Initialize Config instance
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
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk

def run_command(command):
    command_str = ' '.join(command)
    try:
        result = run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        return result.stdout
    except CalledProcessError as e:
        error_msg = f"Command failed: {command_str}\nSTDERR: {e.stderr}\nSTDOUT: {e.stdout}"
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
        retries = 0
        while retries <= self.max_retries:
            try:
                response = self.session.request(method, url, headers=self.headers, **kwargs)
                if response.status_code < 500:
                    response.raise_for_status()
                    return response.json()
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                status_code = e.response.status_code if e.response is not None else 0
                if status_code >= 500 or status_code == 429:
                    retries += 1
                    sleep_time = retries * 2
                    logger.warning(f"Cloudflare API Error ({status_code}). Retrying...")
                    time.sleep(sleep_time)
                else:
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
    logger.info(f"--- Fetching: {feed_config['name']} ---")
    list_urls = feed_config['urls']
    temp_dir = Path(tempfile.mkdtemp())
    unique_domains = set()
    tld_filtered_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {
            executor.submit(download_list, url, temp_dir / f"list_{i}.txt"): url
            for i, url in enumerate(list_urls)
        }
        concurrent.futures.wait(future_to_url)

    for file_path in temp_dir.glob("list_*.txt"):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    parts = line.split()
                    candidate = parts[-1].lower() 
                    
                    if candidate.endswith(CFG.BLOCKED_TLDS):
                        tld_filtered_count += 1
                        continue 
                    
                    if '.' in candidate and not INVALID_CHARS_PATTERN.search(candidate):
                         if candidate not in COMMON_JUNK_DOMAINS:
                             unique_domains.add(candidate)
        except Exception as e:
            logger.warning(f"Error processing file {file_path}: {e}")

    shutil.rmtree(temp_dir)
    logger.info(f"   [TLD Filter] Removed {tld_filtered_count} junk domains.")
    return unique_domains

def save_and_sync(cf_client, feed_config, domain_set, force_update=False):
    output_path = Path(feed_config['filename'])
    new_content = '\n'.join(sorted(domain_set)) + '\n'
    
    if output_path.exists() and not force_update:
        if output_path.read_text(encoding='utf-8') == new_content:
            logger.info(f"✅ [No Changes] {feed_config['name']} up to date.")
            return True 

    output_path.write_text(new_content, encoding='utf-8')
    prefix = feed_config['prefix']
    policy_name = feed_config['policy_name']

    if not domain_set:
        return False

    all_current_lists = cf_client.get_lists().get('result') or []
    current_policies = cf_client.get_rules().get('result') or []
    current_lists_with_prefix = [l for l in all_current_lists if prefix in l.get('name', '')]

    used_list_ids = []
    excess_list_ids = [l['id'] for l in current_lists_with_prefix]

    for i, domains_chunk in enumerate(chunked_iterable(sorted(domain_set), CFG.MAX_LIST_SIZE)):
        list_name = f"{prefix} - {i + 1:03d}"
        items_json = domains_to_cf_items(domains_chunk)
        
        if excess_list_ids:
            list_id = excess_list_ids.pop(0)
            old_items = cf_client.get_list_items(list_id, CFG.MAX_LIST_SIZE).get('result') or []
            remove_items = [item['value'] for item in old_items if item.get('value')]
            cf_client.update_list(list_id, append_items=items_json, remove_items=remove_items)
            used_list_ids.append(list_id)
        else:
            result = cf_client.create_list(list_name, items_json)
            used_list_ids.append(result['result']['id'])
    
    policy_id = next((p['id'] for p in current_policies if p.get('name') == policy_name), None)
    or_clauses = [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in used_list_ids]
    expression_json = {"or": or_clauses} if len(or_clauses) > 1 else (or_clauses[0] if or_clauses else {"not": {"eq": {"lhs": "dns.domains", "rhs": "null"}}})

    policy_payload = {
        "name": policy_name,
        "conditions": [{"type": "traffic", "expression": expression_json}],
        "action": "block",
        "enabled": True,
        "filters": ["dns"]
    }
    
    if policy_id:
        cf_client.update_rule(policy_id, policy_payload)
    else:
        cf_client.create_rule(policy_payload)
        
    for list_id in excess_list_ids:
        cf_client.delete_list(list_id)

    return True

def cleanup_resources(cf_client):
    current_policies = cf_client.get_rules().get('result') or []
    all_current_lists = cf_client.get_lists().get('result') or []

    for feed in CFG.FEED_CONFIGS:
        prefix = feed['prefix']
        policy_name = feed['policy_name']
        p_id = next((p['id'] for p in current_policies if p.get('name') == policy_name), None)
        if p_id: cf_client.delete_rule(p_id)
        for lst in [l for l in all_current_lists if prefix in l.get('name', '')]:
            cf_client.delete_list(lst['id'])

def git_configure():
    run_command(["git", "config", "--global", "user.email", f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"])
    run_command(["git", "config", "--global", "user.name", f"{CFG.GITHUB_ACTOR}[bot]"])

def discard_local_changes(file_path):
    try: run_command(["git", "checkout", "--", str(file_path)])
    except: 
        if os.path.exists(file_path): os.remove(file_path)

def git_commit_and_push(changed_files):
    files_to_commit = []
    for f in changed_files:
        try:
            run_command(["git", "diff", "--exit-code", f])
        except:
            run_command(["git", "add", f])
            files_to_commit.append(f)

    if files_to_commit:
        run_command(["git", "commit", "-m", f"Update blocklists: {', '.join(files_to_commit)}"])
        run_command(["git", "push", "origin", CFG.TARGET_BRANCH])

# --- 5. Main Execution ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        CFG.validate()
        with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf_client:
            if args.delete:
                cleanup_resources(cf_client)
                return

            if Path(".git").exists():
                git_configure()

            feed_datasets = {feed['name']: fetch_domains(feed) for feed in CFG.FEED_CONFIGS}

            # Deduplication logic
            ad, sec, tif = "Ad Block Feed", "Security Feed", "Threat Intel Feed"
            if ad in feed_datasets and sec in feed_datasets:
                feed_datasets[sec] -= feed_datasets[ad]
            if ad in feed_datasets and tif in feed_datasets:
                feed_datasets[tif] -= feed_datasets[ad]
            if sec in feed_datasets and tif in feed_datasets:
                feed_datasets[tif] -= feed_datasets[sec]

            changed_files = []
            for feed in CFG.FEED_CONFIGS:
                if save_and_sync(cf_client, feed, feed_datasets[feed['name']], force_update=args.force):
                    changed_files.append(feed['filename'])

            if Path(".git").exists() and changed_files:
                git_commit_and_push(changed_files)

        logger.info("✅ Execution complete!")

    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
