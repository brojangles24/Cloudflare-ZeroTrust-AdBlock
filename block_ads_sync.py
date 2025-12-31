import os
import sys
import tempfile
import shutil
import re
import concurrent.futures
import logging
import argparse
import time
import math
from datetime import datetime
from pathlib import Path
from subprocess import run, CalledProcessError
from itertools import islice
from collections import Counter
import requests

# --- 1. Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

# --- 2. Configuration Class ---
class Config:
    API_TOKEN: str = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID: str = os.environ.get("ACCOUNT_ID", "")
    MAX_LIST_SIZE: int = 1000
    MAX_RETRIES: int = 5
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or "main"
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

# --- UNIFIED FEED CONFIG ---
FEED_CONFIGS = [
    {
        "name": "Precision Protection",
        "prefix": "Block-Unified",
        "policy_name": "Main Block Policy",
        "filename": "blocklist.txt",
        "urls": [
            "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"
        ]
    }
]

# --- 3. Helper Functions ---
INVALID_CHARS_PATTERN = re.compile(r'[<>&;\"\'/=\s]')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1', 'broadcasthost'}

def validate_config():
    if not Config.API_TOKEN or not Config.ACCOUNT_ID:
        raise RuntimeError("API_TOKEN or ACCOUNT_ID environment variable is not set.")

def domains_to_cf_items(domains):
    return [{"value": domain} for domain in domains if domain]

def chunked_iterable(iterable, size):
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk: break
        yield chunk

def run_command(command):
    try:
        result = run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        return result.stdout
    except CalledProcessError as e:
        raise RuntimeError(f"Command failed: {e.stderr}")

# --- 4. Cloudflare API Client ---
class CloudflareAPI:
    def __init__(self, account_id, api_token, max_retries):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
        self.max_retries = max_retries
        self.session = requests.Session()

    def __enter__(self): return self
    def __exit__(self, *args): self.session.close()

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}/{endpoint}"
        for i in range(self.max_retries + 1):
            try:
                resp = self.session.request(method, url, headers=self.headers, **kwargs)
                if resp.status_code == 429 or resp.status_code >= 500:
                    time.sleep((i + 1) * 2)
                    continue
                resp.raise_for_status()
                return resp.json()
            except Exception as e:
                if i == self.max_retries: raise e
        return None

    def get_lists(self): return self._request("GET", "lists")
    def get_list_items(self, lid, limit): return self._request("GET", f"lists/{lid}/items?limit={limit}")
    def update_list(self, lid, append, remove): return self._request("PATCH", f"lists/{lid}", json={"append": append, "remove": remove})
    def create_list(self, name, items): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items})
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def get_rules(self): return self._request("GET", "rules")
    def create_rule(self, data): return self._request("POST", "rules", json=data)
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json=data)
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")

# --- 5. Workflow Functions ---
def fetch_domains(feed_config):
    start_time = time.time()
    logger.info(f"--- Fetching: {feed_config['name']} ---")
    unique_domains = set()
    stats = {"raw_lines": 0, "valid_domains": 0, "time_taken": 0.0, "tlds": Counter()}

    for url in feed_config['urls']:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')): continue
            stats["raw_lines"] += 1
            
            candidate = line.split()[-1].lower()
            if candidate.startswith('*.'): candidate = candidate[2:] # Cloudflare fix
            
            if '.' in candidate and not INVALID_CHARS_PATTERN.search(candidate):
                if candidate not in COMMON_JUNK_DOMAINS:
                    unique_domains.add(candidate)
                    stats["tlds"][candidate.split('.')[-1]] += 1
                        
    stats["valid_domains"] = len(unique_domains)
    stats["time_taken"] = time.time() - start_time
    return unique_domains, stats

def save_and_sync(cf, feed, domains, force=False):
    out = Path(feed['filename'])
    new_data = '\n'.join(sorted(domains)) + '\n'
    if out.exists() and not force and out.read_text(encoding='utf-8') == new_data:
        return False

    out.write_text(new_data, encoding='utf-8')
    all_lists = cf.get_lists().get('result') or []
    existing = [l for l in all_lists if feed['prefix'] in l.get('name', '')]
    used_ids, excess = [], [l['id'] for l in existing]

    for i, chunk in enumerate(chunked_iterable(sorted(domains), Config.MAX_LIST_SIZE)):
        items = domains_to_cf_items(chunk)
        if excess:
            lid = excess.pop(0)
            old = cf.get_list_items(lid, Config.MAX_LIST_SIZE).get('result') or []
            rem = [item['value'] for item in old if item.get('value')]
            cf.update_list(lid, items, rem)
            used_ids.append(lid)
        else:
            res = cf.create_list(f"{feed['prefix']} - {i+1:03d}", items)
            used_ids.append(res['result']['id'])

    rules = cf.get_rules().get('result') or []
    rid = next((r['id'] for r in rules if r.get('name') == feed['policy_name']), None)
    clauses = [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in used_ids]
    expr = {"or": clauses} if len(clauses) > 1 else clauses[0]
    payload = {"name": feed['policy_name'], "conditions": [{"type": "traffic", "expression": expr}], "action": "block", "enabled": True, "filters": ["dns"]}
    
    if rid: cf.update_rule(rid, payload)
    else: cf.create_rule(payload)
    for lid in excess: cf.delete_list(lid)
    return True

def git_push(files):
    run_command(["git", "config", "--global", "user.email", f"{Config.GITHUB_ACTOR_ID}+{Config.GITHUB_ACTOR}@users.noreply.github.com"])
    run_command(["git", "config", "--global", "user.name", f"{Config.GITHUB_ACTOR}"])
    changed = []
    for f in files:
        try: 
            run_command(["git", "diff", "--exit-code", f])
        except:
            run_command(["git", "add", f]); changed.append(f)
    if changed:
        run_command(["git", "commit", "-m", f"Update blocklists: {datetime.now().strftime('%Y-%m-%d')}"])
        run_command(["git", "push", "origin", Config.TARGET_BRANCH])

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        validate_config()
        with CloudflareAPI(Config.ACCOUNT_ID, Config.API_TOKEN, Config.MAX_RETRIES) as cf:
            if args.delete:
                logger.warning("🗑️ Deleting matching lists and rules...")
                rules = cf.get_rules().get('result') or []
                lists = cf.get_lists().get('result') or []
                for f in FEED_CONFIGS:
                    rid = next((r['id'] for r in rules if r['name'] == f['policy_name']), None)
                    if rid: cf.delete_rule(rid)
                    for l in [ls for ls in lists if f['prefix'] in ls['name']]: cf.delete_list(l['id'])
                return

            changed_files = []
            for feed in FEED_CONFIGS:
                domains, stats = fetch_domains(feed)
                if save_and_sync(cf, feed, domains, args.force):
                    changed_files.append(feed['filename'])
            
            if Path(".git").exists() and changed_files:
                git_push(changed_files)
        logger.info("✅ Execution complete!")
    except Exception as e:
        logger.critical(f"Fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
