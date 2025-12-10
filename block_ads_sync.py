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
import toml 

# --- 1. Configuration & Setup ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- FEED URL DEFINITIONS (Constants) ---
HAGEZI_ULTIMATE = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt"
HAGEZI_PRO = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt"
HAGEZI_NORMAL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/normal-onlydomains.txt"
HAGEZI_LIGHT = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt"
HAGEZI_BADWARE = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/badware-onlydomains.txt"
HAGEZI_FAKE = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt"
HAGEZI_TIF_MINI = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"
HAGEZI_TIF_MEDIUM = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt"
HAGEZI_SPAM_TLDS_IDNS = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt" 

# --- TLD DEFINITIONS (Used for Level 2 TLD list) ---
TOP_15_TLDS_TUPLE = (
    "zip", "mov", "xyz", "top", "gdn", "win", "loan", "bid",
    "stream", "tk", "ml", "ga", "cf", "gq", "cn",
)
AGGR_TLDS_IDNS = HAGEZI_SPAM_TLDS_IDNS


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

    # Dynamic Configuration
    CURRENT_LEVEL: str = "0"
    LAST_DEPLOYED_LEVEL: str = "0"
    SHOULD_WIPE: bool = False
    
    BLOCKED_TLDS_SET: set = set()
    TLD_SOURCE: str | tuple = () 
    FEED_CONFIGS: list = []

    # --- PROFILE DEFINITIONS ---
    PROFILE_LEVELS = {
        "1": {"name": "Minimal", "tlds_source": (), "feeds": [{"name": "Ads Light", "prefix": "Block 1A", "policy_name": "Level 1: Minimal Ads/Trackers", "filename": "L1_Light.txt", "urls": [HAGEZI_LIGHT]}, {"name": "Security Mini", "prefix": "Block 1S", "policy_name": "Level 1: Minimal Security", "filename": "L1_Security.txt", "urls": [HAGEZI_TIF_MINI, HAGEZI_BADWARE, HAGEZI_FAKE]}]},
        "2": {"name": "Normal", "tlds_source": TOP_15_TLDS_TUPLE, "feeds": [{"name": "Ads Normal", "prefix": "Block 2A", "policy_name": "Level 2: Normal Ads/Trackers", "filename": "L2_Normal.txt", "urls": [HAGEZI_NORMAL]}, {"name": "Security Mini", "prefix": "Block 2S", "policy_name": "Level 2: Normal Security", "filename": "L2_Security.txt", "urls": [HAGEZI_TIF_MINI, HAGEZI_BADWARE, HAGEZI_FAKE]}]},
        "3": {"name": "Aggressive", "tlds_source": AGGR_TLDS_IDNS, "feeds": [{"name": "Ads Pro", "prefix": "Block 3A", "policy_name": "Level 3: Aggressive Ads/Trackers", "filename": "L3_Pro.txt", "urls": [HAGEZI_PRO]}, {"name": "Threat Intel Mini", "prefix": "Block 3S", "policy_name": "Level 3: Strong Security", "filename": "L3_Security.txt", "urls": [HAGEZI_TIF_MINI]}]},
        "4": {"name": "Extreme", "tlds_source": AGGR_TLDS_IDNS, "feeds": [{"name": "Ads Ultimate", "prefix": "Block 4A", "policy_name": "Level 4: Ultimate Scorched Earth", "filename": "L4_Ultimate.txt", "urls": [HAGEZI_ULTIMATE]}, {"name": "Threat Intel Medium", "prefix": "Block 4S", "policy_name": "Level 4: Extreme Security", "filename": "L4_Security.txt", "urls": [HAGEZI_TIF_MEDIUM]}]},
    }

    @classmethod
    def load_config_data(cls):
        config_path = Path("config.toml")
        if not config_path.exists():
             raise ScriptExit("config.toml not found. Please create it.", critical=True)
             
        try:
            config_data = toml.loads(config_path.read_text())
            level_str = str(config_data.get('security_level', 1))
            if level_str not in cls.PROFILE_LEVELS:
                raise ValueError(f"Invalid level '{level_str}'")
        except Exception as e:
            raise ScriptExit(f"Error reading config.toml: {e}", critical=True)

        cache_path = Path(".last_deployed_profile")
        last_level = cache_path.read_text().strip() if cache_path.exists() else "0"
        
        cls.CURRENT_LEVEL = level_str
        cls.LAST_DEPLOYED_LEVEL = last_level

        if cls.CURRENT_LEVEL != cls.LAST_DEPLOYED_LEVEL:
            cls.SHOULD_WIPE = True
            logger.warning(f"PROFILE CHANGE DETECTED: {last_level} -> {cls.CURRENT_LEVEL}. Forcing full wipe and redeploy.")
        else:
            cls.SHOULD_WIPE = False
            logger.info(f"Profile {cls.CURRENT_LEVEL} is consistent. Performing update sync.")

        profile = cls.PROFILE_LEVELS[level_str]
        cls.TLD_SOURCE = profile["tlds_source"]
        cls.FEED_CONFIGS = profile["feeds"]
        
        if isinstance(cls.TLD_SOURCE, tuple) and cls.TLD_SOURCE:
            cls.BLOCKED_TLDS_SET = set(cls.TLD_SOURCE)
        elif isinstance(cls.TLD_SOURCE, str) and cls.TLD_SOURCE:
            logger.info("Downloading external TLD list for fast internal filtering...")
            temp_file = Path(tempfile.gettempdir()) / "external_tlds.txt"
            try:
                download_list(cls.TLD_SOURCE, temp_file)
                with open(temp_file, 'r', encoding='utf-8') as f:
                    tlds = [line.strip().lstrip('.').lower() for line in f if line.strip() and not line.startswith('#')]
                cls.BLOCKED_TLDS_SET = set(tlds)
                logger.info(f"Loaded {len(cls.BLOCKED_TLDS_SET)} TLDs/IDNs for internal filtering.")
                os.remove(temp_file)
            except Exception as e:
                logger.error(f"Failed to load external TLD list for filtering: {e}")
                cls.BLOCKED_TLDS_SET = set()
        
        if cls.TLD_SOURCE:
            tld_feed = {
                "name": "Junk TLDs and IDNs",
                "prefix": "Block TLD",
                "policy_name": f"Level {level_str}: Junk TLD/IDN Blocking",
                "filename": f"L{level_str}_TLDs.txt",
                "urls": [cls.TLD_SOURCE] if isinstance(cls.TLD_SOURCE, str) else []
            }
            cls.FEED_CONFIGS.append(tld_feed)

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
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk

def run_command(command):
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

# --- 3. Cloudflare API Client (REAL) ---

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
                if response.status_code >= 500 or response.status_code == 429:
                    response.raise_for_status() 
                
                response_json = response.json()
                if not response_json.get('success'):
                    error_messages = [err.get('message', 'Unknown API Error') for err in response_json.get('errors', [])]
                    # Specific check to handle 404 deletion gracefully
                    if "not found" in str(error_messages).lower() and method == "DELETE":
                        return {'success': True}
                    raise requests.exceptions.HTTPError(f"API failed: {', '.join(error_messages)}", response=response)
                    
                response.raise_for_status()
                return response_json
                
            except requests.exceptions.RequestException as e:
                status_code = e.response.status_code if e.response is not None else 0
                if status_code >= 500 or status_code == 429:
                    retries += 1
                    sleep_time = retries * 2
                    logger.warning(f"Cloudflare API Error ({status_code}). Retrying {retries}/{self.max_retries} in {sleep_time}s...")
                    time.sleep(sleep_time)
                    if retries > self.max_retries:
                        logger.error(f"Max retries exceeded for {method} {url}")
                        raise RuntimeError(f"Cloudflare API failed after retries: {e}")
                else:
                    logger.error(f"Cloudflare Client Error: {e}")
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

def create_tld_regex(tld_list_content):
    tlds = tld_list_content.splitlines()
    cleaned_tlds = []
    for line in tlds:
        line = line.strip().lstrip('.').lower()
        if not line or line.startswith('#'): continue
        cleaned_tlds.append(line)
    
    if not cleaned_tlds:
        return ""

    tld_pattern = "|".join(sorted(set(cleaned_tlds)))
    regex = f"(?i)\\.({tld_pattern})$"
    return regex


def create_tld_policy(cf_client, tld_list_file, level):
    policy_name = f"Level {level}: Junk TLD/IDN Blocking"
    
    if not tld_list_file.exists():
        logger.error("Cannot create TLD policy: TLD file not found locally.")
        return

    tld_list_content = tld_list_file.read_text(encoding='utf-8')
    tld_regex = create_tld_regex(tld_list_content)
    
    if not tld_regex:
        logger.warning("TLD policy skipped: Regex pattern is empty.")
        return

    policy_payload = {
        "name": policy_name,
        "description": f"Managed by script. Blocks known spam, phishing, and IDN TLDs for Level {level}.",
        "precedence": 5, 
        "enabled": True,
        "action": "block",
        "filters": ["dns"],
        "traffic": f"dns.fqdn matches regex \"{tld_regex}\"",
        "rule_settings": {"block_page_enabled": False},
    }
    
    current_policies = cf_client.get_rules().get('result') or []
    policy_id = next((p['id'] for p in current_policies if p.get('name') == policy_name), None)

    if policy_id:
        logger.info(f"Updating TLD Policy '{policy_name}'...")
        cf_client.update_rule(policy_id, policy_payload)
    else:
        logger.info(f"Creating TLD Policy '{policy_name}'...")
        cf_client.create_rule(policy_payload)


def fetch_domains(feed_config):
    logger.info(f"--- Fetching: {feed_config['name']} ---")
    list_urls = feed_config['urls']
    temp_dir = Path(tempfile.mkdtemp())
    unique_domains = set()
    tld_filtered_count = 0

    if feed_config['name'] == "Junk TLDs and IDNs" and isinstance(CFG.TLD_SOURCE, tuple):
        unique_domains = set(f"domain.{tld}" for tld in CFG.TLD_SOURCE)
        output_path = Path(feed_config['filename'])
        output_path.write_text('\n'.join(sorted(CFG.TLD_SOURCE)) + '\n', encoding='utf-8')
        shutil.rmtree(temp_dir)
        logger.info(f"  [Net Result] Generated {len(unique_domains)} domains for TLD List.")
        return unique_domains

    logger.info(f"Downloading {len(list_urls)} lists...")
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
                    if not parts: continue
                    candidate = parts[-1].lower() 
                    
                    if CFG.BLOCKED_TLDS_SET:
                        if '.' in candidate:
                            if candidate.split('.')[-1] in CFG.BLOCKED_TLDS_SET:
                                tld_filtered_count += 1
                                continue 
                    
                    if '.' in candidate and not INVALID_CHARS_PATTERN.search(candidate):
                        if candidate not in COMMON_JUNK_DOMAINS:
                            unique_domains.add(candidate)
        except Exception as e:
            logger.warning(f"Error processing file {file_path}: {e}")

    shutil.rmtree(temp_dir)
    logger.info(f"  [TLD Filter] Removed {tld_filtered_count} junk domains.")
    logger.info(f"  [Net Result] Fetched {len(unique_domains)} unique domains.")
    return unique_domains


def save_and_sync(cf_client, feed_config, domain_set, force_update=False):
    output_path = Path(feed_config['filename'])
    
    is_tld_url_feed = feed_config['name'] == "Junk TLDs and IDNs" and isinstance(CFG.TLD_SOURCE, str)
    
    if output_path.exists() and not force_update:
        current_content = output_path.read_text(encoding='utf-8')
        new_content = '\n'.join(sorted(domain_set)) + '\n'
        
        if current_content == new_content:
            logger.info(f"✅ [No Changes] {feed_config['name']} matches local file. Skipping Cloudflare sync.")
            return True 
    
    if is_tld_url_feed:
        logger.info(f"Saving {len(domain_set)} TLDs/IDNs to {output_path} for Regex assembly...")
        output_path.write_text('\n'.join(sorted(domain_set)) + '\n', encoding='utf-8')
        logger.info(f"Skipping Cloudflare List sync for {feed_config['name']} (Handled by Regex Policy).")
        return True
    
    new_content = '\n'.join(sorted(domain_set)) + '\n'
    logger.info(f"💾 Saving {len(domain_set)} domains to {output_path}...")
    output_path.write_text(new_content, encoding='utf-8')
    
    prefix = feed_config['prefix']
    policy_name = feed_config['policy_name']
    total_lines = len(domain_set)

    if total_lines == 0:
        logger.warning(f"Feed {feed_config['name']} is empty. Skipping Sync.")
        return False

    total_lists_needed = (total_lines + CFG.MAX_LIST_SIZE - 1) // CFG.MAX_LIST_SIZE
    
    all_current_lists = cf_client.get_lists().get('result') or []
    current_policies = cf_client.get_rules().get('result') or []

    current_lists_with_prefix = [l for l in all_current_lists if prefix in l.get('name', '')]
    other_lists_count = len(all_current_lists) - len(current_lists_with_prefix)
    
    if total_lists_needed > CFG.MAX_LISTS - other_lists_count:
        logger.error(f"Not enough capacity! Needed: {total_lists_needed}, Available: {CFG.MAX_LISTS - other_lists_count}")
        return False

    used_list_ids = []
    excess_list_ids = [l['id'] for l in current_lists_with_prefix]

    sorted_domains = sorted(domain_set)
    for i, domains_chunk in enumerate(chunked_iterable(sorted_domains, CFG.MAX_LIST_SIZE)):
        list_name = f"{prefix} - {i + 1:03d}"
        items_json = domains_to_cf_items(domains_chunk)
        
        if excess_list_ids:
            list_id = excess_list_ids.pop(0)
            logger.info(f"Updating list {list_id} ({list_name})...")
            old_items = cf_client.get_list_items(list_id, CFG.MAX_LIST_SIZE).get('result') or []
            remove_items = [item['value'] for item in old_items if item.get('value')]
            cf_client.update_list(list_id, append_items=items_json, remove_items=remove_items)
            used_list_ids.append(list_id)
        else:
            logger.info(f"Creating new list: {list_name}...")
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
        "description": f"Managed by script: {feed_config['name']}",
        "rule_settings": {"block_page_enabled": False},
        "filters": ["dns"]
    }
    
    if policy_id:
        existing_policy = next((p for p in current_policies if p.get('id') == policy_id), {})
        existing_conditions = existing_policy.get('conditions') or []
        
        needs_update = bool(excess_list_ids)
        if not needs_update and existing_conditions:
             if existing_conditions[0].get('expression') != expression_json:
                 needs_update = True

        if needs_update:
            logger.info(f"Updating policy '{policy_name}'...")
            cf_client.update_rule(policy_id, policy_payload)
        else:
            logger.info(f"Policy '{policy_name}' up to date.")
    else:
        logger.info(f"Creating policy '{policy_name}'...")
        cf_client.create_rule(policy_payload)
        
    for list_id in excess_list_ids:
        logger.info(f"Deleting excess list {list_id}...")
        try:
            cf_client.delete_list(list_id)
        except Exception as e:
            logger.warning(f"Failed to delete {list_id}: {e}")

    return True

# --- CLEANUP FUNCTION WITH IMPROVED POLICY DETECTION ---
def cleanup_resources(cf_client):
    logger.info("--- ⚠️ CLEANUP MODE: DELETING RESOURCES ⚠️ ---")
    current_policies = cf_client.get_rules().get('result') or []
    all_current_lists = cf_client.get_lists().get('result') or []

    # 1. DELETE POLICIES FIRST (Aggressive Match)
    prefixes_to_delete = ["Level ", "Block ", "Ads ", "Security ", "Threat Intel", "Junk TLD"]
    
    for policy in current_policies:
        name = policy.get('name', '')
        # Check if the policy name starts with or contains any of our keywords
        if any(name.startswith(p) for p in prefixes_to_delete) or "Managed by script" in policy.get('description', ''):
            logger.info(f"Deleting Policy: {name} ({policy['id']})...")
            try:
                cf_client.delete_rule(policy['id'])
            except Exception as e:
                logger.error(f"Failed to delete policy {policy['id']}: {e}")

    # 2. WAIT for Cloudflare to release the locks
    logger.info("Waiting 5 seconds for policy deletion to propagate...")
    time.sleep(5)

    # 3. DELETE LISTS
    for lst in all_current_lists:
        # Match lists created by this script 
        if lst.get('name', '').startswith("Block ") or "Block" in lst.get('name', ''):
            logger.info(f"Deleting List: {lst['name']} ({lst['id']})...")
            try:
                cf_client.delete_list(lst['id'])
            except Exception as e:
                logger.error(f"Failed to delete list {lst['id']}: {e}")
                
    Path(".last_deployed_profile").write_text(CFG.CURRENT_LEVEL)
    logger.info("--- Cleanup Complete. Cache file updated. ---")

def git_configure():
    git_user_name = f"{CFG.GITHUB_ACTOR}[bot]"
    git_user_email = f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"
    run_command(["git", "config", "--global", "user.email", git_user_email])
    run_command(["git", "config", "--global", "user.name", git_user_name])

def discard_local_changes(file_path):
    logger.info(f"Discarding local changes to {file_path}...")
    try:
        run_command(["git", "checkout", "--", str(file_path)])
    except RuntimeError:
        try:
            os.remove(file_path)
        except OSError:
            pass

def git_commit_and_push(changed_files):
    logger.info("--- Git Commit & Push ---")
    if not changed_files: return
    
    files_to_commit = []
    for f in changed_files:
        try:
            run_command(["git", "diff", "--exit-code", f])
            logger.info(f"File {f} matches repo. Skipping add.")
        except RuntimeError:
            logger.info(f"File {f} has changes. Staging.")
            run_command(["git", "add", f])
            files_to_commit.append(f)

    if not files_to_commit:
        logger.info("No files actually changed. Skipping commit.")
        return

    try:
        run_command(["git", "commit", "-m", f"Update blocklists: {', '.join(files_to_commit)}"])
    except RuntimeError as e:
        if "nothing to commit" in str(e) or "no changes added to commit" in str(e):
            logger.info("Git reported nothing to commit.")
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
    parser.add_argument("--force", action="store_true", help="Force update even if files haven't changed")
    args = parser.parse_args()

    try:
        logger.info("--- 0. Initializing ---")
        
        CFG.load_config_data()
        CFG.validate()
        
        with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf_client:
            
            if args.delete or CFG.SHOULD_WIPE:
                cleanup_resources(cf_client)
                if args.delete: return

            is_git_repo = Path(".git").exists()
            if is_git_repo:
                try:
                    run_command(["git", "fetch", "origin", CFG.TARGET_BRANCH])
                    run_command(["git", "checkout", CFG.TARGET_BRANCH])
                    run_command(["git", "reset", "--hard", f"origin/{CFG.TARGET_BRANCH}"])
                    git_configure()
                except Exception as e:
                    logger.warning(f"Git init warning: {e}")

            feed_datasets = {}
            for feed in CFG.FEED_CONFIGS:
                feed_datasets[feed['name']] = fetch_domains(feed)

            # --- SMART DEDUPLICATION ---
            ad_name = next((f['name'] for f in CFG.FEED_CONFIGS if 'Ads ' in f['name']), None)
            security_name = next((f['name'] for f in CFG.FEED_CONFIGS if 'Security' in f['name']), None)
            tif_name = next((f['name'] for f in CFG.FEED_CONFIGS if 'Threat Intel' in f['name']), None)
            
            if ad_name and security_name and ad_name in feed_datasets and security_name in feed_datasets:
                 overlap = feed_datasets[ad_name].intersection(feed_datasets[security_name])
                 if overlap:
                     logger.info(f"🔍 Found {len(overlap)} overlaps between Ads & Security.")
                     feed_datasets[security_name] -= overlap

            if ad_name and tif_name and ad_name in feed_datasets and tif_name in feed_datasets:
                overlap = feed_datasets[ad_name].intersection(feed_datasets[tif_name])
                if overlap:
                    logger.info(f"🔍 Found {len(overlap)} overlaps between Ads & TIF.")
                    feed_datasets[tif_name] -= overlap

            if security_name and tif_name and security_name in feed_datasets and tif_name in feed_datasets:
                overlap = feed_datasets[security_name].intersection(feed_datasets[tif_name])
                if overlap:
                    logger.info(f"🔍 Found {len(overlap)} overlaps between Security & TIF.")
                    feed_datasets[tif_name] -= overlap
            # --- END DEDUPLICATION ---


            changed_files_list = []
            sync_success_global = True
            
            # --- Sync Feeds ---
            for feed in CFG.FEED_CONFIGS:
                try:
                    dataset = feed_datasets[feed['name']]
                    sync_success = save_and_sync(cf_client, feed, dataset, force_update=args.force)
                    if sync_success:
                        changed_files_list.append(feed['filename'])
                    else:
                        sync_success_global = False
                except Exception as e:
                    logger.error(f"Failed to process feed '{feed['name']}': {e}", exc_info=True)
                    sync_success_global = False
                    if is_git_repo:
                        discard_local_changes(feed['filename'])
            
            # --- TLD POLICY CREATION ---
            if sync_success_global:
                tld_feed_config = next((f for f in CFG.FEED_CONFIGS if f['name'] == 'Junk TLDs and IDNs'), None)
                
                if tld_feed_config:
                    tld_list_file = Path(tld_feed_config['filename'])
                    
                    try:
                        create_tld_policy(cf_client, tld_list_file, CFG.CURRENT_LEVEL)
                        logger.info(f"✅ TLD Regex Policy deployment successful.")
                    except Exception as e:
                        logger.error(f"Failed to create TLD Policy: {e}", exc_info=True)
                        sync_success_global = False
                else:
                    logger.info("Skipping TLD Policy creation (No TLDs defined for this level).")
            
            # --- Cache Update and Finalization ---
            if sync_success_global:
                Path(".last_deployed_profile").write_text(CFG.CURRENT_LEVEL)
                logger.info(f"Deployment successful. Cache updated to profile {CFG.CURRENT_LEVEL}.")
            else:
                logger.critical("One or more feeds/policies failed to sync. Profile cache NOT updated. Rerun to complete.")

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
