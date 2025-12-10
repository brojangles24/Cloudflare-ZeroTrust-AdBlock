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
    
    # Git Configuration (Using default GitHub Actions setup)
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main" 
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

    # Dynamic Configuration (Set in load_config_data)
    CURRENT_LEVEL: str = "0"
    LAST_DEPLOYED_LEVEL: str = "0"
    SHOULD_WIPE: bool = False
    
    BLOCKED_TLDS_SET: set = set() # Set of TLDs to filter *other* feeds against
    TLD_SOURCE: str | tuple = () # The source definition (URL or Tuple)
    FEED_CONFIGS: list = []

    # --- PROFILE DEFINITIONS ---
    PROFILE_LEVELS = {
        # 1. MINIMAL (No TLD/IDN Blocking)
        "1": {
            "name": "Minimal",
            "tlds_source": (), 
            "feeds": [
                {"name": "Ads Light", "prefix": "Block 1A", "policy_name": "Level 1: Minimal Ads/Trackers", "filename": "L1_Light.txt", "urls": [HAGEZI_LIGHT]},
                {"name": "Security Mini", "prefix": "Block 1S", "policy_name": "Level 1: Minimal Security", "filename": "L1_Security.txt", "urls": [HAGEZI_TIF_MINI, HAGEZI_BADWARE, HAGEZI_FAKE]}, 
            ]
        },
        
        # 2. NORMAL (Top 15 TLDs)
        "2": {
            "name": "Normal",
            "tlds_source": TOP_15_TLDS_TUPLE, 
            "feeds": [
                {"name": "Ads Normal", "prefix": "Block 2A", "policy_name": "Level 2: Normal Ads/Trackers", "filename": "L2_Normal.txt", "urls": [HAGEZI_NORMAL]}, 
                {"name": "Security Mini", "prefix": "Block 2S", "policy_name": "Level 2: Normal Security", "filename": "L2_Security.txt", "urls": [HAGEZI_TIF_MINI, HAGEZI_BADWARE, HAGEZI_FAKE]}, 
            ]
        },
        
        # 3. AGGRESSIVE (Pro Ads, External TLD/IDN List)
        "3": {
            "name": "Aggressive",
            "tlds_source": AGGR_TLDS_IDNS, # External TLD list URL
            "feeds": [
                {"name": "Ads Pro", "prefix": "Block 3A", "policy_name": "Level 3: Aggressive Ads/Trackers", "filename": "L3_Pro.txt", "urls": [HAGEZI_PRO]}, 
                {"name": "Threat Intel Mini", "prefix": "Block 3S", "policy_name": "Level 3: Strong Security", "filename": "L3_Security.txt", "urls": [HAGEZI_TIF_MINI]},
            ]
        },

        # 4. EXTREME (Ultimate Ads, External TLD/IDN List)
        "4": {
            "name": "Extreme",
            "tlds_source": AGGR_TLDS_IDNS, # External TLD list URL
            "feeds": [
                {"name": "Ads Ultimate", "prefix": "Block 4A", "policy_name": "Level 4: Ultimate Scorched Earth", "filename": "L4_Ultimate.txt", "urls": [HAGEZI_ULTIMATE]}, 
                {"name": "Threat Intel Medium", "prefix": "Block 4S", "policy_name": "Level 4: Extreme Security", "filename": "L4_Security.txt", "urls": [HAGEZI_TIF_MEDIUM]},
            ]
        },
    }

    @classmethod
    def load_config_data(cls):
        # 1. Load desired level from config.toml
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

        # 2. Check last deployed level from a local cache file
        cache_path = Path(".last_deployed_profile")
        last_level = cache_path.read_text().strip() if cache_path.exists() else "0"
        
        # 3. Determine if a full wipe is needed
        cls.CURRENT_LEVEL = level_str
        cls.LAST_DEPLOYED_LEVEL = last_level

        if cls.CURRENT_LEVEL != cls.LAST_DEPLOYED_LEVEL:
            cls.SHOULD_WIPE = True
            logger.warning(f"PROFILE CHANGE DETECTED: {last_level} -> {cls.CURRENT_LEVEL}. Forcing full wipe and redeploy.")
        else:
            cls.SHOULD_WIPE = False
            logger.info(f"Profile {cls.CURRENT_LEVEL} is consistent. Performing update sync.")

        # 4. Assign dynamic config and TLD source
        profile = cls.PROFILE_LEVELS[level_str]
        cls.TLD_SOURCE = profile["tlds_source"]
        cls.FEED_CONFIGS = profile["feeds"]
        
        # 5. Populate TLD_BLOCKING_SET for fast filtering (Handles both tuple and URL source)
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
                cls.BLOCKED_TLDS_SET = set() # Fail safe

        # 6. Add TLD Blocking as a dedicated feed for list creation and policy assembly
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

# --- 3. Cloudflare API Client (Requires actual implementation in your environment) ---
# NOTE: The following is a DUMMY class for code completeness. 
# Use your complete, working CloudflareAPI class here.
class CloudflareAPI:
    def __init__(self, account_id, api_token, max_retries):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
        self.max_retries = max_retries
        self.session = requests.Session()

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_value, traceback): self.session.close()

    def _request(self, method, endpoint, **kwargs):
        # NOTE: Implement actual API logic here. Returning mock data for completeness.
        logger.debug(f"API CALL: {method} {endpoint}")
        if 'lists' in endpoint and 'GET' in method: return {'result': []}
        if 'rules' in endpoint and 'GET' in method: return {'result': []}
        return {'success': True, 'result': {'id': 'mock-id'}}
    
    def get_lists(self): return self._request("GET", "lists")
    def get_rules(self): return self._request("GET", "rules")
    def delete_rule(self, rule_id): return self._request("DELETE", f"rules/{rule_id}")
    def delete_list(self, list_id): return self._request("DELETE", f"lists/{list_id}")
    def create_list(self, name, items): return self._request("POST", "lists", json={"name": name, "items": items})
    def update_list(self, list_id, append_items, remove_items): return self._request("PATCH", f"lists/{list_id}")
    def get_list_items(self, list_id, limit): return self._request("GET", f"lists/{list_id}/items?limit={limit}")
    def create_rule(self, payload): return self._request("POST", "rules", json=payload)
    def update_rule(self, rule_id, payload): return self._request("PUT", f"rules/{rule_id}", json=payload)
# --- END Cloudflare API Class ---


# --- 4. Workflow Functions ---

def create_tld_regex(tld_list_content):
    """Assembles the final TLD/IDN regex for Cloudflare Gateway from raw content."""
    
    tlds = tld_list_content.splitlines()
    
    # Clean the TLD strings (remove dot, remove comments, lowercase)
    cleaned_tlds = []
    for line in tlds:
        line = line.strip().lstrip('.').lower()
        if not line or line.startswith('#'): continue
        cleaned_tlds.append(line)
    
    if not cleaned_tlds:
        return ""

    tld_pattern = "|".join(sorted(set(cleaned_tlds)))

    # The final regex pattern: (?i)\.(tld1|tld2|...)$
    regex = f"(?i)\\.({tld_pattern})$"
    
    return regex


def create_tld_policy(cf_client, tld_list_file, level):
    """Creates or updates the TLD blocking policy in Cloudflare Zero Trust."""
    policy_name = f"Level {level}: Junk TLD/IDN Blocking"
    
    if not tld_list_file.exists():
        logger.error("Cannot create TLD policy: TLD file not found locally.")
        return

    # 1. Read the list content to generate the regex
    tld_list_content = tld_list_file.read_text(encoding='utf-8')
    tld_regex = create_tld_regex(tld_list_content)
    
    if not tld_regex:
        logger.warning("TLD policy skipped: Regex pattern is empty.")
        return

    # 2. Prepare the policy payload
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
    
    # 3. Check and deploy
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

    # Special handling for TLD blocking list from local tuple (Level 2)
    if feed_config['name'] == "Junk TLDs and IDNs" and isinstance(CFG.TLD_SOURCE, tuple):
        # Create dummy domains using the TLD list, as Cloudflare lists need FQDNs
        unique_domains = set(f"domain.{tld}" for tld in CFG.TLD_SOURCE)
        
        # Save TLDs to file for the regex assembly step later
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
                    
                    # TLD Filter logic (Using the fast BLOCKED_TLDS_SET)
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
    
    # Check if this is the TLD list from a URL (Levels 3/4)
    is_tld_url_feed = feed_config['name'] == "Junk TLDs and IDNs" and isinstance(CFG.TLD_SOURCE, str)
    
    if output_path.exists() and not force_update:
        current_content = output_path.read_text(encoding='utf-8')
        new_content = '\n'.join(sorted(domain_set)) + '\n'
        
        if current_content == new_content:
            logger.info(f"✅ [No Changes] {feed_config['name']} matches local file. Skipping Cloudflare sync.")
            return True 

    # If this is the TLD URL feed, we save the content locally (Tlds as lines)
    if is_tld_url_feed:
        logger.info(f"Saving {len(domain_set)} TLDs/IDNs to {output_path} for Regex assembly...")
        output_path.write_text('\n'.join(sorted(domain_set)) + '\n', encoding='utf-8')
        
        # We don't need to upload TLDs as domains to CF lists, so we exit sync here
        logger.info(f"Skipping Cloudflare List sync for {feed_config['name']} (Handled by Regex Policy).")
        return True
    
    # Standard domain list sync below
    new_content = '\n'.join(sorted(domain_set)) + '\n'
    logger.info(f"💾 Saving {len(domain_set)} domains to {output_path}...")
    output_path.write_text(new_content, encoding='utf-8')
    
    # ... (Rest of CF API interaction logic remains the same) ...
    
    prefix = feed_config['prefix']
    policy_name = feed_config['policy_name']
    total_lines = len(domain_set)

    # NOTE: The rest of the CF API list/policy creation/update logic goes here.
    # We must assume the user's original implementation of this section is correct.
    
    # --- START MOCK API CALLS (Replace with your robust implementation) ---
    logger.info(f"--- MOCK SYNC: {policy_name} ---")
    if total_lines == 0:
        logger.warning("Mock: List is empty. Skipping API Sync.")
        return False
    # Mocking successful list and policy creation/update.
    logger.info(f"Mock: Syncing {total_lines} domains across 1 list...")
    logger.info(f"Mock: Policy '{policy_name}' successfully updated/created.")
    return True
    # --- END MOCK API CALLS ---

def cleanup_resources(cf_client):
    logger.info("--- ⚠️ CLEANUP MODE: DELETING RESOURCES ⚠️ ---")
    current_policies = cf_client.get_rules().get('result') or []
    all_current_lists = cf_client.get_lists().get('result') or []

    # Clean up Policies
    for policy in current_policies:
        # Delete any policy created by the script (starting with "Level ")
        if policy.get('name', '').startswith("Level "):
            logger.info(f"Deleting Policy: {policy['name']} ({policy['id']})...")
            try:
                cf_client.delete_rule(policy['id'])
            except Exception as e:
                logger.error(f"Failed to delete policy {policy['id']}: {e}")

    # Clean up Lists
    for lst in all_current_lists:
        # Match lists created by this script (starting with "Block ")
        if lst.get('name', '').startswith("Block "):
            logger.info(f"Deleting List: {lst['name']} ({lst['id']})...")
            try:
                cf_client.delete_list(lst['id'])
            except Exception as e:
                logger.error(f"Failed to delete list {lst['id']}: {e}")
                
    # Update cache file to ensure the new level is recorded after successful cleanup
    Path(".last_deployed_profile").write_text(CFG.CURRENT_LEVEL)
    logger.info("--- Cleanup Complete. Cache file updated. ---")

def git_configure():
    git_user_name = f"{CFG.GITHUB_ACTOR}[bot]"
    git_user_email = f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"
    # Assuming run_command is defined and executes git commands
    # run_command(["git", "config", "--global", "user.email", git_user_email])
    # run_command(["git", "config", "--global", "user.name", git_user_name])
    logger.info("Mock: Git configured.")

def discard_local_changes(file_path):
    logger.warning("Mock: Discarding local changes.")
    # Assuming git commands or file deletion runs here.

def git_commit_and_push(changed_files):
    logger.info("Mock: Git Commit and Push skipped.")
    # Assuming git commands run here.


# --- 5. Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Cloudflare Gateway Blocklist Manager")
    parser.add_argument("--delete", action="store_true", help="Delete all lists and policies defined in config")
    parser.add_argument("--force", action="store_true", help="Force update even if files haven't changed")
    args = parser.parse_args()

    try:
        logger.info("--- 0. Initializing ---")
        
        # Load config and determine wipe necessity
        CFG.load_config_data()
        CFG.validate()
        
        # IMPORTANT: Using the mock CloudflareAPI defined above. Replace with your actual implementation.
        with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf_client:
            
            if args.delete or CFG.SHOULD_WIPE:
                cleanup_resources(cf_client)
                if args.delete: return

            is_git_repo = Path(".git").exists()
            if is_git_repo:
                # ... (git setup remains here) ...
                try:
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

            # Deduplication logic (removed for brevity, but should remain in your final script)
            
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
