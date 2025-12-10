import os
import sys
import tempfile
import shutil
import re
import concurrent.futures
import logging
import argparse
import time
from typing import List, Set, Optional
from pathlib import Path
from subprocess import run
from itertools import islice
from dataclasses import dataclass

import requests

# --- 1. Configuration & Constants ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Full TLD list
BLOCKED_TLDS = (
    ".zip", ".mov", ".xyz", ".top", ".gdn", ".win", ".loan", ".bid", ".stream", 
    ".tk", ".ml", ".ga", ".cf", ".gq", ".cn", ".ru", ".sbs", ".cfd", ".bond", 
    ".es", ".xn--11b4c3d", ".xn--1ck2e1b", ".xn--1qqw23a", ".xn--2scrj9c",
    ".xn--30rr7y", ".xn--3bst00m", ".xn--3ds443g", ".xn--3e0b707e", ".xn--3hcrj9c", 
    ".xn--3oq18vl8pn36a", ".xn--3pxu8k", ".xn--42c2d9a", ".xn--45br5cyl", 
    ".xn--45brj9c", ".xn--45q11c", ".xn--4gbrim", ".xn--54b7fta0cc", ".xn--55qw42g", 
    ".xn--55qx5d", ".xn--5su34j936bgsg", ".xn--5tzm5g", ".xn--6frz82g", 
    ".xn--6qq986b3xl", ".xn--80adxhks", ".xn--80ao21a", ".xn--80aqecdr1a", 
    ".xn--80asehdb", ".xn--80aswg", ".xn--8y0a063a", ".xn--90a3ac", ".xn--90ae", 
    ".xn--90ais", ".xn--9dbq2a", ".xn--9et52u", ".xn--9krt00a", ".xn--b4w605ferd", 
    ".xn--bck1b9a5dre4c", ".xn--c1avg", ".xn--c2br7g", ".xn--cck2b3b", 
    ".xn--cckwcxetd", ".xn--cg4bki", ".xn--clchc0ea0b2g2a9gcd", ".xn--czr694b", 
    ".xn--czrs0t", ".xn--czru2d", ".xn--d1acj3b", ".xn--d1alf", ".xn--e1a4c", 
    ".xn--eckvdtc9d", ".xn--efvy88h", ".xn--fct429k", ".xn--fhbei", ".xn--fiq228c5hs", 
    ".xn--fiq64b", ".xn--fiqs8s", ".xn--fiqz9s", ".xn--fjq720a", ".xn--flw351e", 
    ".xn--fpcrj9c3d", ".xn--fzc2c9e2c", ".xn--fzys8d69uvgm", ".xn--g2xx48c", 
    ".xn--gckr3f0f", ".xn--gecrj9c", ".xn--gk3at1e", ".xn--h2breg3eve", 
    ".xn--h2brj9c", ".xn--h2brj9c8c", ".xn--hxt814e", ".xn--i1b6b1a6a2e", 
    ".xn--imr513n", ".xn--io0a7i", ".xn--j1aef", ".xn--j1amh", ".xn--j6w193g", 
    ".xn--jlq480n2rg", ".xn--jlq61u9w7b", ".xn--jvr189m", ".xn--kcrx77d1x4a", 
    ".xn--kprw13d", ".xn--kpry57d", ".xn--kput3i", ".xn--l1acc", ".xn--lgbbat1ad8j", 
    ".xn--mgb9awbf", ".xn--mgba3a3ejt", ".xn--mgba3a4f16a", ".xn--mgba7c0bbn0a", 
    ".xn--mgbaakc7dvf", ".xn--mgbaam7a8h", ".xn--mgbab2bd", ".xn--mgbah1a3hjkrd", 
    ".xn--mgbai9azgqp6j", ".xn--mgbayh7gpa", ".xn--mgbbh1a", ".xn--mgbbh1a71e", 
    ".xn--mgbc0a9azcg", ".xn--mgbca7dzdo", ".xn--mgbcpq6gpa1a", ".xn--mgberp4a5d4ar", 
    ".xn--mgbgu82a", ".xn--mgbi4ecexp", ".xn--mgbpl2fh", ".xn--mgbt3dhd", 
    ".xn--mgbtx2b", ".xn--mgbx4cd0ab", ".xn--mix891f", ".xn--mk1bu44c", 
    ".xn--mxtq1m", ".xn--ngbc5azd", ".xn--ngbe9e0a", ".xn--ngbrx", ".xn--node", 
    ".xn--nqv7f", ".xn--nqv7fs00ema", ".xn--nyqy26a", ".xn--o3cw4h", ".xn--ogbpf8fl", 
    ".xn--otu796d", ".xn--p1acf", ".xn--p1ai", ".xn--pgbs0dh", ".xn--pssy2u", 
    ".xn--q7ce6a", ".xn--q9jyb4c", ".xn--qcka1pmc", ".xn--qxa6a", ".xn--qxam", 
    ".xn--rhqv96g", ".xn--rovu88b", ".xn--rvc1e0am3e", ".xn--s9brj9c", 
    ".xn--ses554g", ".xn--t60b56a", ".xn--tckwe", ".xn--tiq49xqyj", ".xn--unup4y", 
    ".xn--vhquv", ".xn--vuq861b", ".xn--w4r85el8fhu5dnra", ".xn--w4rs40l", 
    ".xn--wgbh1c", ".xn--wgbl6a", ".xn--xhq521b", ".xn--xkc2al3hye2a", 
    ".xn--xkc2dl3a5ee0h", ".xn--y9a3aq", ".xn--yfro4i67o", ".xn--ygbi2ammx", 
    ".xn--zfr164b"
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
    WEBHOOK_URL: str = os.environ.get("WEBHOOK_URL", "")
    
    # Global Limits
    MAX_LIST_SIZE: int = 1000
    MAX_LISTS: int = 300 
    MAX_RETRIES: int = 5
    USER_AGENT: str = "Mozilla/5.0 (compatible; CloudflareBlocklistManager/3.2)"
    
    # Git
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main" 
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

    ALLOWLIST_FILE: str = "allowlist.txt"

    # Define your feeds here
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
        if not cls.API_TOKEN or not cls.ACCOUNT_ID:
            raise ScriptExit("Missing API_TOKEN or ACCOUNT_ID env vars.", critical=True)

CFG = Config()

# --- 2. Advanced Helper Classes ---

class ScriptExit(Exception):
    def __init__(self, message, silent=False, critical=False):
        super().__init__(message)
        self.silent = silent
        self.critical = critical

class GitHubActions:
    @staticmethod
    def is_running(): return os.getenv('GITHUB_ACTIONS') == 'true'

    @staticmethod
    def write_summary(lines: List[str]):
        if not GitHubActions.is_running(): return
        summary_file = os.getenv('GITHUB_STEP_SUMMARY')
        if summary_file:
            with open(summary_file, 'a', encoding='utf-8') as f:
                f.write("\n".join(lines) + "\n")

class NotificationHandler:
    @staticmethod
    def send(message: str, level: str = "info"):
        if not CFG.WEBHOOK_URL: return
        color = 3066993
        if level == "error": color = 15158332
        if level == "warning": color = 16776960
        payload = {
            "username": "Blocklist Manager",
            "embeds": [{"description": message, "color": color, "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z')}]
        }
        try: requests.post(CFG.WEBHOOK_URL, json=payload, timeout=5)
        except Exception: pass

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
        self.session.headers.update({"User-Agent": CFG.USER_AGENT})
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.session: self.session.close()

    def _request(self, method, endpoint, **kwargs):
        if self.dry_run and method != 'GET':
            logger.info(f"[DRY RUN] {method} {endpoint}")
            return {'result': {'id': 'dry-run-id'}}

        url = f"{self.base_url}/{endpoint}"
        retries = 0
        while retries <= self.max_retries:
            try:
                response = self.session.request(method, url, headers=self.headers, **kwargs)
                if response.status_code == 429:
                    time.sleep(int(response.headers.get("Retry-After", 10)))
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

VALID_DOMAIN_PATTERN = re.compile(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1', 'broadcasthost', 'ip6-localhost'}

def clean_domain(domain_str: str) -> Optional[str]:
    if not domain_str or domain_str.startswith('#'): return None
    d = domain_str.split()[0].strip().lower().rstrip('.')
    if d in COMMON_JUNK_DOMAINS: return None
    if d.endswith(BLOCKED_TLDS): return None
    try:
        puny = d.encode('idna').decode('ascii')
        if VALID_DOMAIN_PATTERN.match(puny): return puny
    except Exception: pass
    return None

def download_file(url, path):
    try:
        r = requests.get(url, timeout=30, headers={"User-Agent": CFG.USER_AGENT})
        r.raise_for_status()
        path.write_bytes(r.content)
        return True
    except Exception as e:
        logger.warning(f"Download failed {url}: {e}")
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
                    d = clean_domain(line)
                    if d and d not in allowlist:
                        valid_domains.add(d)
        except Exception: pass

    shutil.rmtree(temp_dir)
    return valid_domains

def sync_feed(cf_client: CloudflareAPI, feed: FeedConfig, domains: Set[str]):
    if not domains: return
    
    sorted_domains = sorted(domains)
    chunks = [sorted_domains[i:i + CFG.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), CFG.MAX_LIST_SIZE)]
    total_needed = len(chunks)

    all_lists = cf_client.get_lists().get('result') or []
    my_lists = sorted([l for l in all_lists if feed.prefix in l.get('name', '')], key=lambda x: x['name'])
    
    available = CFG.MAX_LISTS - (len(all_lists) - len(my_lists))
    if total_needed > available:
        msg = f"❌ Capacity Exceeded: {feed.name} needs {total_needed}, has {available}."
        logger.error(msg)
        NotificationHandler.send(msg, "error")
        raise ScriptExit(msg)

    used_ids = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_map = {}
        for i, chunk in enumerate(chunks):
            list_name = f"{feed.prefix} - {i + 1:03d}"
            payload = [{"value": d} for d in chunk]
            
            if i < len(my_lists):
                lid = my_lists[i]['id']
                used_ids.append(lid)
                future_map[executor.submit(cf_client.replace_list_items, lid, payload)] = list_name
            else:
                future_map[executor.submit(cf_client.create_list, list_name, payload)] = list_name
        
        for f in concurrent.futures.as_completed(future_map):
            try:
                res = f.result()
                if "result" in res: used_ids.append(res['result']['id'])
            except Exception as e:
                logger.error(f"{future_map[f]} failed: {e}")

    # Cleanup Excess
    if len(my_lists) > total_needed:
        for lst in my_lists[total_needed:]:
            cf_client.delete_list(lst['id'])

    # Update Policy
    policies = cf_client.get_rules().get('result') or []
    pid = next((p['id'] for p in policies if p.get('name') == feed.policy_name), None)
    
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

    if pid: cf_client.update_rule(pid, payload)
    else: cf_client.create_rule(payload)

def nuke_all_resources(cf_client: CloudflareAPI):
    """
    SMART NUKE: 
    1. Delete ONLY rules managed by this script.
    2. Delete ALL Domain Lists (cleaning up everything).
    """
    logger.warning("☢️ SMART NUKE INITIATED ☢️")
    NotificationHandler.send("☢️ Smart Nuke: Cleaning up managed resources...", "warning")

    # 1. Identify Managed Policies
    managed_policy_names = {feed.policy_name for feed in CFG.FEEDS}
    
    rules = cf_client.get_rules().get('result') or []
    for rule in rules:
        if rule['name'] in managed_policy_names:
            logger.info(f"🔥 Deleting Managed Rule: {rule['name']}")
            try: cf_client.delete_rule(rule['id'])
            except Exception: pass
        else:
            logger.info(f"🛡️ Skipping Custom Rule: {rule['name']}")

    # 2. Delete ALL Domain Lists
    lists = cf_client.get_lists().get('result') or []
    deleted_count = 0
    for lst in lists:
        if lst['type'] == 'DOMAIN':
            logger.info(f"🔥 Deleting List: {lst['name']}")
            try: 
                cf_client.delete_list(lst['id'])
                deleted_count += 1
            except Exception: pass
            
    logger.info(f"☢️ Nuke Complete. Deleted {deleted_count} lists.")
    NotificationHandler.send(f"☢️ Nuke Complete. Deleted {deleted_count} lists.", "info")

# --- 5. Main ---

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true", help="Simulate without changes")
    p.add_argument("--force", action="store_true", help="Force update regardless of diff")
    p.add_argument("--nuke", action="store_true", help="Delete ALL lists and managed rules")
    args = p.parse_args()

    start_time = time.time()
    try:
        CFG.validate()
        
        with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES, args.dry_run) as cf:
            if args.nuke:
                nuke_all_resources(cf)
                return

            allowlist = set()
            if Path(CFG.ALLOWLIST_FILE).exists():
                with open(CFG.ALLOWLIST_FILE, 'r') as f:
                    allowlist = {clean_domain(line) for line in f if clean_domain(line)}

            is_git = Path(".git").exists() and not args.dry_run
            if is_git:
                run(["git", "fetch", "origin", CFG.TARGET_BRANCH], check=False)
                run(["git", "checkout", CFG.TARGET_BRANCH], check=False)
                run(["git", "reset", "--hard", f"origin/{CFG.TARGET_BRANCH}"], check=False)

            global_seen = set()
            changed_files = []
            report_lines = ["## 🛡️ Blocklist Update Report"]

            for feed in CFG.FEEDS:
                raw = fetch_domains(feed, allowlist)
                unique = raw - global_seen
                duplicates = len(raw) - len(unique)
                global_seen.update(unique)
                
                out_path = Path(feed.filename)
                new_text = '\n'.join(sorted(unique)) + '\n'
                
                has_diff = True
                if out_path.exists() and out_path.read_text(encoding='utf-8') == new_text:
                    has_diff = False
                
                status_icon = "✅"
                if has_diff or args.force:
                    status_icon = "💾"
                    if not args.dry_run:
                        out_path.write_text(new_text, encoding='utf-8')
                        changed_files.append(feed.filename)
                        sync_feed(cf, feed, unique)
                    
                logger.info(f"{status_icon} {feed.name}: {len(unique)} domains (removed {duplicates} dupes)")
                report_lines.append(f"* **{feed.name}**: {len(unique):,} domains ({status_icon})")

            if is_git and changed_files:
                git_actor = f"{CFG.GITHUB_ACTOR}[bot]"
                git_email = f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"
                run(["git", "config", "--global", "user.email", git_email], check=False)
                run(["git", "config", "--global", "user.name", git_actor], check=False)
                run(["git", "add"] + changed_files, check=False)
                run(["git", "commit", "-m", "Update blocklists"], check=False)
                run(["git", "push", "origin", CFG.TARGET_BRANCH], check=False)
                report_lines.append(f"\n**Git**: Pushed {len(changed_files)} updated files.")
                NotificationHandler.send(f"Updated {len(changed_files)} blocklists.", "info")

            duration = time.time() - start_time
            report_lines.append(f"\n⏱️ **Duration**: {duration:.2f}s")
            GitHubActions.write_summary(report_lines)

    except Exception as e:
        logger.critical(f"Fatal: {e}", exc_info=True)
        NotificationHandler.send(f"Critical Script Failure: {e}", "error")
        sys.exit(1)

if __name__ == "__main__":
    main()
