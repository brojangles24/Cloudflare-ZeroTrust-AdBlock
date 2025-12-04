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

import requests

# --- 1. Configuration & Setup ---

# Set up logging early
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Define configuration settings using a class
class Config:
    API_TOKEN: str = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID: str = os.environ.get("ACCOUNT_ID", "")
    PREFIX: str = "Block ads"
    MAX_LIST_SIZE: int = 1000
    MAX_LISTS: int = 300
    MAX_RETRIES: int = 10
    OUTPUT_FILE_NAME: str = "Aggregated_List.txt"
    OUTPUT_PATH: Path = Path(OUTPUT_FILE_NAME)
    
    # Git Configuration
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main"
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

    # Aggregator Configuration
    LIST_URLS = [
        #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt", # Hagezi Ultimate ~ 260k domains
        #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt", # OISD Big ~ 212k domains
        #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt", # Hagezi Pro++ ~190k domains 
        #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt", # Hagezi Pro ~ 160k domains
        #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt", # Hagezi Normal ~ 120k domains
        #"https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.wildcards", # 1Hosts Lite ~ 90k domains
        #"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", # Steven Black Hosts ~ 84k domains
        #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_small.txt", #OISD Small ~ 45k domains
        #"https://raw.githubusercontent.com/anudeepND/blacklist/master/adservers.txt", #Aundeep Servers ~42k domains
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt", #Hagezi Light ~ 40k domains 
        #"https://adaway.org/hosts.txt", # Adaway Hosts ~6k domains
    ]

    @classmethod
    def validate(cls):
        if not cls.API_TOKEN:
            raise ScriptExit("API_TOKEN environment variable is not set.", critical=True)
        if not cls.ACCOUNT_ID:
            raise ScriptExit("ACCOUNT_ID environment variable is not set.", critical=True)

# Load config
CFG = Config()

# --- 2. Helper Functions & Exceptions ---

# Domain Processing Patterns (Compiled for efficiency)
INVALID_CHARS_PATTERN = re.compile(r'[<>&;\"\'/=\s]')
DOMAIN_EXTRACT_PATTERN = re.compile(r'^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}\s+)?(.+)$')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1'}

class ScriptExit(Exception):
    """Custom exception to stop the script gracefully."""
    def __init__(self, message, silent=False, critical=False):
        super().__init__(message)
        self.silent = silent
        self.critical = critical

def domains_to_cf_items(domains):
    """Converts a list of domain strings to the Cloudflare API item format."""
    return [{"value": domain} for domain in domains if domain]

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
    except FileNotFoundError:
        raise RuntimeError(f"Command not found: {command[0]}")

def download_list(url, file_path):
    """Downloads a single list to the specified path."""
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    file_path.write_bytes(response.content)

# --- 3. Cloudflare API Client (Context Manager with Secret Redaction) ---

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
        redacted_headers = self.headers.copy()
        redacted_headers["Authorization"] = "Bearer [REDACTED]"
        logger.debug(f"CF Request: {method} {url} with headers {redacted_headers}")
        
        try:
            response = self.session.request(method, url, headers=self.headers, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Cloudflare API failed for {method} {url}. Status: {e.response.status_code if e.response else 'N/A'}")
            raise RuntimeError(f"Cloudflare API failed: {e}")

    # API methods
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

def run_aggregation():
    """Download lists, process, normalize, and deduplicate domains."""
    logger.info("--- 1. Aggregating Lists ---")

    temp_dir = Path(tempfile.mkdtemp())
    logger.info(f"Using temporary directory: {temp_dir}")

    # 1. Download Lists in Parallel
    logger.info(f"Downloading {len(CFG.LIST_URLS)} lists in parallel...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {
            executor.submit(download_list, url, temp_dir / f"list_{i}.txt"): url
            for i, url in enumerate(CFG.LIST_URLS)
        }
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                future.result()
            except requests.exceptions.RequestException as e:
                logger.warning(f"Failed to download {url}. Skipping. Error: {e}")
    logger.info("All lists downloaded.")

    # 2. Process, Normalize, and Deduplicate
    logger.info("Processing, normalizing, and deduplicating domains...")
    unique_domains = set()

    for file_path in temp_dir.glob("list_*.txt"):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue

                    match = DOMAIN_EXTRACT_PATTERN.match(line)
                    if not match: continue

                    domain = match.group(1).split()[0].lower()
                    
                    if not domain or domain in COMMON_JUNK_DOMAINS: continue
                    
                    if '.' not in domain or INVALID_CHARS_PATTERN.search(domain): continue
                        
                    unique_domains.add(domain)
        except Exception as e:
            logger.warning(f"Error processing file {file_path}: {e}")

    # 3. Save unique entries
    CFG.OUTPUT_PATH.write_text('\n'.join(sorted(unique_domains)) + '\n', encoding='utf-8')
    logger.info(f"Processing complete. Aggregated list saved to {CFG.OUTPUT_PATH}.")
    shutil.rmtree(temp_dir)
    logger.info("Temporary download directory cleaned up.")
    return len(unique_domains)

def sync_cloudflare(total_lines):
    """Sync the aggregated domains to Cloudflare Gateway Lists and Rules."""
    logger.info("--- 2. Syncing to Cloudflare ---")
    
    # Check if the file has changed
    try:
        run_command(["git", "diff", "--exit-code", CFG.OUTPUT_FILE_NAME])
        raise ScriptExit("The aggregated domains list has not changed", silent=True)
    except RuntimeError:
        # This is where the error 'Command failed: git diff --exit-code Aggregated_List.txt' appeared.
        # This is expected when changes exist, so we catch the failure and continue.
        pass

    if total_lines == 0:
        raise ScriptExit("The aggregated domains list is empty", critical=True)

    max_total_lines = CFG.MAX_LIST_SIZE * CFG.MAX_LISTS
    if total_lines > max_total_lines:
        raise ScriptExit(f"The domains list has more than {max_total_lines} lines", critical=True)

    logger.info(f"Total unique domains aggregated: {total_lines}")
    total_lists = (total_lines + CFG.MAX_LIST_SIZE - 1) // CFG.MAX_LIST_SIZE
    logger.info(f"This will require {total_lists} Cloudflare lists.")

    with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf:
        
        # Fetch current state
        all_current_lists = cf.get_lists().get('result', [])
        current_policies = cf.get_rules().get('result', [])

        current_lists_with_prefix = [l for l in all_current_lists if CFG.PREFIX in l.get('name', '')]
        current_lists_without_prefix = [l for l in all_current_lists if CFG.PREFIX not in l.get('name', '')]
        
        # Capacity check
        current_lists_count_without_prefix = len(current_lists_without_prefix)
        if total_lists > CFG.MAX_LISTS - current_lists_count_without_prefix:
            raise ScriptExit(f"Required lists ({total_lists}) > Max allowed ({CFG.MAX_LISTS - current_lists_count_without_prefix})", critical=True)

        # Split list into chunks
        domains = CFG.OUTPUT_PATH.read_text(encoding='utf-8').splitlines()
        chunked_domains = [domains[i:i + CFG.MAX_LIST_SIZE] for i in range(0, len(domains), CFG.MAX_LIST_SIZE)]

        used_list_ids = []
        excess_list_ids = [l['id'] for l in current_lists_with_prefix]

        # --- Update/Create Lists ---
        for i, domains_chunk in enumerate(chunked_domains):
            list_counter = i + 1
            formatted_counter = f"{list_counter:03d}"
            list_name = f"{CFG.PREFIX} - {formatted_counter}"
            
            items_json = domains_to_cf_items(domains_chunk)
            
            if excess_list_ids:
                list_id = excess_list_ids.pop(0)
                logger.info(f"Updating list {list_id} ({list_name})...")
                
                old_items_result = cf.get_list_items(list_id, CFG.MAX_LIST_SIZE).get('result', [])
                remove_items = [item['value'] for item in old_items_result if item.get('value')]
                
                cf.update_list(list_id, append_items=items_json, remove_items=remove_items)
                used_list_ids.append(list_id)

            else:
                logger.info(f"Creating new list: {list_name}...")
                result = cf.create_list(list_name, items_json)
                used_list_ids.append(result['result']['id'])
        
        # --- Update/Create Gateway Policy (MOVE THIS STEP UP) ---
        # We must update the policy FIRST to remove references to the lists we are about to delete.
        policy_id = next((p['id'] for p in current_policies if p.get('name') == CFG.PREFIX), None)

        # Build the policy expression (handles 0, 1, or multiple lists)
        or_clauses = [
            {"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${list_id}"}}}
            for list_id in used_list_ids
        ]

        if not or_clauses:
             expression_json = {"not": {"eq": {"lhs": "dns.domains", "rhs": "null"}}}
        elif len(or_clauses) == 1:
            expression_json = or_clauses[0]
        else:
            expression_json = {"or": or_clauses}

        policy_payload = {
            "name": CFG.PREFIX,
            "conditions": [{"type": "traffic", "expression": expression_json}],
            "action": "block",
            "enabled": True,
            "description": "Aggregated blocklist from singularitysink",
            "rule_settings": {"block_page_enabled": False},
            "filters": ["dns"]
        }
        
        # Policy Idempotence Check
        if policy_id:
            existing_policy = next((p for p in current_policies if p.get('id') == policy_id), {})
            existing_conditions = existing_policy.get('conditions', [])
            
            # Check if the expression has logically changed
            if existing_conditions and existing_conditions[0].get('expression') == expression_json:
                logger.info("Policy expression is unchanged. Skipping PUT request.")
            else:
                logger.info(f"Updating policy {policy_id}...")
                cf.update_rule(policy_id, policy_payload)
        else:
            logger.info("Creating policy...")
            cf.create_rule(policy_payload)
            
        # --- Delete Excess Lists (MOVE THIS STEP DOWN) ---
        # Now that the Policy is updated and no longer references the excess list IDs, we can delete them.
        for list_id in excess_list_ids:
            logger.info(f"Deleting excess list {list_id}...")
            # We wrap this in a try/except because the list might have been partially deleted
            # or the connection might be unstable, but we don't want the whole workflow to fail
            # if the policy update was already successful.
            try:
                cf.delete_list(list_id)
                logger.info(f"Successfully deleted list {list_id}.")
            except Exception as e:
                logger.warning(f"Failed to delete excess list {list_id} (might be already gone): {e}")


        logger.info("Cloudflare sync complete.")
        return True

def commit_to_git(total_lines):
    """Commit the updated list to the repository."""
    logger.info("--- 3. Committing to Git ---")
    
    git_user_name = f"{CFG.GITHUB_ACTOR}[bot]"
    git_user_email = f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"
    
    logger.info("Configuring Git user...")
    run_command(["git", "config", "--global", "user.email", git_user_email])
    run_command(["git", "config", "--global", "user.name", git_user_name])

    logger.info("Committing and pushing updated list...")
    
    run_command(["git", "add", CFG.OUTPUT_FILE_NAME])
    
    try:
        run_command(["git", "commit", "-m", f"Update domains list ({total_lines} domains)"])
    except RuntimeError as e:
        if "nothing to commit" in str(e):
            logger.info("No changes to commit. Skipping push.")
            return
        raise
    
    # Git pull/push logic
    if run(["git", "remote", "get-url", "origin"], check=False, capture_output=True).returncode == 0:
        logger.info(f"Attempting to push to branch: {CFG.TARGET_BRANCH}")
        run_command(["git", "pull", "--rebase", "origin", CFG.TARGET_BRANCH])
        run_command(["git", "push", "origin", CFG.TARGET_BRANCH])
    else:
        logger.warning("Origin remote not found. Skipping Git push.")
        
    logger.info("Git commit and push complete.")

# --- 5. Main Execution ---
def main():
    """Main execution function for the Cloudflare blocklist update workflow."""
    try:
        # --- 0. Initializing ---
        logger.info("--- 0. Initializing ---")
        
        CFG.validate()

        is_git_repo = Path(".git").exists()
        if is_git_repo:
            logger.info(f"Target Git Branch: {CFG.TARGET_BRANCH}")
            try:
                run_command(["git", "fetch", "origin", CFG.TARGET_BRANCH])
                run_command(["git", "checkout", CFG.TARGET_BRANCH])
                run_command(["git", "reset", "--hard", f"origin/{CFG.TARGET_BRANCH}"])
            except CalledProcessError as e:
                logger.warning(f"Git initialization failed. Error: {e.stderr.strip()}")
        else:
            logger.warning("Not running in a Git repository. Git operations will be skipped.")


        # --- 1. Run the Aggregation ---
        total_lines = run_aggregation()

        # --- 2. Run the Cloudflare Sync ---
        sync_cloudflare(total_lines)
        
        # --- 3. Run the Git Commit ---
        if is_git_repo:
            commit_to_git(total_lines)

        logger.info("================================================")
        logger.info("✅ Aggregation and Cloudflare upload finished!")
        logger.info(f"Total unique domains: {total_lines}")
        logger.info("================================================")

    except ScriptExit as e:
        if e.silent:
            logger.info(f"Silent exit: {e}")
            sys.exit(0)
        elif e.critical:
            logger.error(f"Configuration/Validation Error: {e}")
            sys.exit(1)
        else:
            logger.error(f"Runtime Error: {e}")
            sys.exit(1)
    except RuntimeError as e:
        logger.critical(f"Unhandled Command/API Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected fatal error occurred: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
