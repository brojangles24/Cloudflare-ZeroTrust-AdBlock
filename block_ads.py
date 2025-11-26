import os
import sys
import tempfile
import shutil
import re
import concurrent.futures
from pathlib import Path
from subprocess import run, CalledProcessError

import requests

# --- Configuration ---
API_TOKEN = os.environ.get("API_TOKEN", "")
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
PREFIX = "Block ads"
MAX_LIST_SIZE = 1000
MAX_LISTS = 300
MAX_RETRIES = 10
OUTPUT_FILE_NAME = "Aggregated_List.txt"
OUTPUT_PATH = Path(OUTPUT_FILE_NAME)

# Git Configuration
TARGET_BRANCH = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main"
GITHUB_ACTOR = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
GITHUB_ACTOR_ID = os.environ.get("GITHUB_ACTOR_ID", "41898282")

# Aggregator Configuration
LIST_URLS = [
    "https://raw.githubusercontent.com/brojangles24/shiny-telegram/refs/heads/main/Aggregated_list/priority_300k.txt",
    # Add more lists here
]

# --- Domain Processing Helpers ---
INVALID_CHARS_PATTERN = re.compile(r'[<>&;\"\'/=\s]')
DOMAIN_EXTRACT_PATTERN = re.compile(r'^(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}\s+)?(.+)$')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1'}

def domains_to_cf_items(domains):
    """Converts a list of domain strings to the Cloudflare API item format."""
    return [{"value": domain} for domain in domains if domain]

# --- Custom Exception ---
class ScriptExit(Exception):
    """Custom exception to stop the script gracefully."""
    def __init__(self, message, silent=False):
        super().__init__(message)
        self.silent = silent

# --- Helper Functions ---
def run_command(command):
    """Run a shell command and raise an error on non-zero exit code."""
    try:
        run(command, check=True, capture_output=True, text=True, encoding='utf-8')
    except CalledProcessError as e:
        raise RuntimeError(f"Command failed: {' '.join(command)}\nStdout: {e.stdout}\nStderr: {e.stderr}")
    except FileNotFoundError:
        raise RuntimeError(f"Command not found: {command[0]}")

def download_list(url, file_path):
    """Downloads a single list to the specified path."""
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    file_path.write_bytes(response.content)

# --- Cloudflare API Client (Context Manager) ---
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
            raise RuntimeError(f"Cloudflare API failed for {method} {url}: {e}")

    # API methods remain the same, using self._request...
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


# --- 1. Aggregation Function ---
def run_aggregation():
    """Download lists, process, normalize, and deduplicate domains."""
    print("--- 1. Aggregating Lists ---")

    temp_dir = Path(tempfile.mkdtemp())
    print(f"Using temporary directory: {temp_dir}")

    # 1. Download Lists in Parallel
    print(f"Downloading {len(LIST_URLS)} lists in parallel...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {
            executor.submit(download_list, url, temp_dir / f"list_{i}.txt"): url
            for i, url in enumerate(LIST_URLS)
        }
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                future.result()
            except requests.exceptions.RequestException as e:
                print(f"Warning: Failed to download {url}. Skipping. Error: {e}", file=sys.stderr)
    print("All lists downloaded.")

    # 2. Process, Normalize, and Deduplicate
    print("Processing, normalizing, and deduplicating domains...")
    unique_domains = set()

    for file_path in temp_dir.glob("list_*.txt"):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Extract domain and convert to lowercase
                    match = DOMAIN_EXTRACT_PATTERN.match(line)
                    if not match:
                        continue

                    # Take the first word after optional IP and convert to lowercase
                    domain = match.group(1).split()[0].lower()
                    
                    # Filter out junk and invalid entries
                    if not domain or domain in COMMON_JUNK_DOMAINS:
                        continue
                    
                    # Stricter filtering for HTML junk and basic domain validation
                    if '.' not in domain or INVALID_CHARS_PATTERN.search(domain):
                        continue
                        
                    unique_domains.add(domain)
        except Exception as e:
            print(f"Warning: Error processing file {file_path}: {e}", file=sys.stderr)

    # 3. Save unique entries
    OUTPUT_PATH.write_text('\n'.join(sorted(unique_domains)) + '\n', encoding='utf-8')
    print(f"Processing complete. Aggregated list saved to {OUTPUT_PATH}.")
    shutil.rmtree(temp_dir)
    print("Temporary download directory cleaned up.")
    return len(unique_domains)

# --- 2. Cloudflare Sync Function ---
def sync_cloudflare(total_lines):
    """Sync the aggregated domains to Cloudflare Gateway Lists and Rules."""
    print("--- 2. Syncing to Cloudflare ---")
    
    # Check if the file has changed
    try:
        run_command(["git", "diff", "--exit-code", OUTPUT_FILE_NAME])
        raise ScriptExit("The aggregated domains list has not changed", silent=True)
    except RuntimeError:
        pass # File has changed, continue

    if total_lines == 0:
        raise ScriptExit("The aggregated domains list is empty")

    max_total_lines = MAX_LIST_SIZE * MAX_LISTS
    if total_lines > max_total_lines:
        raise ScriptExit(f"The domains list has more than {max_total_lines} lines")

    print(f"Total unique domains aggregated: {total_lines}")
    total_lists = (total_lines + MAX_LIST_SIZE - 1) // MAX_LIST_SIZE
    print(f"This will require {total_lists} Cloudflare lists.")

    with CloudflareAPI(ACCOUNT_ID, API_TOKEN, MAX_RETRIES) as cf:
        
        # Get current lists and policies
        all_current_lists = cf.get_lists().get('result', [])
        current_policies = cf.get_rules().get('result', [])

        current_lists_with_prefix = [l for l in all_current_lists if PREFIX in l.get('name', '')]
        current_lists_without_prefix = [l for l in all_current_lists if PREFIX not in l.get('name', '')]
        
        current_lists_count_without_prefix = len(current_lists_without_prefix)
        if total_lists > MAX_LISTS - current_lists_count_without_prefix:
            raise ScriptExit(f"The number of lists required ({total_lists}) is greater than the maximum allowed ({MAX_LISTS - current_lists_count_without_prefix})")

        # Split list into chunks
        domains = OUTPUT_PATH.read_text(encoding='utf-8').splitlines()
        chunked_domains = [domains[i:i + MAX_LIST_SIZE] for i in range(0, len(domains), MAX_LIST_SIZE)]

        used_list_ids = []
        excess_list_ids = [l['id'] for l in current_lists_with_prefix]

        # --- Update/Create Lists ---
        for i, domains_chunk in enumerate(chunked_domains):
            list_counter = i + 1
            formatted_counter = f"{list_counter:03d}"
            list_name = f"{PREFIX} - {formatted_counter}"
            
            items_json = domains_to_cf_items(domains_chunk)
            
            if excess_list_ids:
                # Update existing list
                list_id = excess_list_ids.pop(0)
                print(f"Updating list {list_id}...")
                
                # Get old items for removal
                old_items_result = cf.get_list_items(list_id, MAX_LIST_SIZE).get('result', [])
                remove_items = [item['value'] for item in old_items_result if item.get('value')]
                
                cf.update_list(list_id, append_items=items_json, remove_items=remove_items)
                used_list_ids.append(list_id)

            else:
                # Create new list
                print(f"Creating list: {list_name}...")
                result = cf.create_list(list_name, items_json)
                used_list_ids.append(result['result']['id'])
        
        # --- Delete Excess Lists ---
        for list_id in excess_list_ids:
            print(f"Deleting excess list {list_id}...")
            cf.delete_list(list_id)

        # --- Update/Create Gateway Policy ---
        policy_id = next((p['id'] for p in current_policies if p.get('name') == PREFIX), None)

        # Build the policy expression (handles 0, 1, or multiple lists)
        or_clauses = [
            {
                "any": {
                    "in": {
                        "lhs": {"splat": "dns.domains"},
                        "rhs": f"${list_id}"
                    }
                }
            }
            for list_id in used_list_ids
        ]

        if not or_clauses:
             # Failsafe: if no lists, use an expression that is always false
             expression_json = {"not": {"eq": {"lhs": "dns.domains", "rhs": "null"}}}
        elif len(or_clauses) == 1:
            expression_json = or_clauses[0]
        else:
            expression_json = {"or": or_clauses}

        policy_payload = {
            "name": PREFIX,
            "conditions": [{"type": "traffic", "expression": expression_json}],
            "action": "block",
            "enabled": True,
            "description": "Aggregated blocklist from singularitysink",
            "rule_settings": {"block_page_enabled": False},
            "filters": ["dns"]
        }
        
        if policy_id:
            print(f"Updating policy {policy_id}...")
            cf.update_rule(policy_id, policy_payload)
        else:
            print("Creating policy...")
            cf.create_rule(policy_payload)
            
        print("Cloudflare sync complete.")
        return True

# --- 3. Git Commit Function ---
def commit_to_git(total_lines):
    """Commit the updated list to the repository."""
    print("--- 3. Committing to Git ---")
    
    git_user_name = f"{GITHUB_ACTOR}[bot]"
    git_user_email = f"{GITHUB_ACTOR_ID}+{GITHUB_ACTOR}@users.noreply.github.com"
    
    print("Configuring Git user...")
    run_command(["git", "config", "--global", "user.email", git_user_email])
    run_command(["git", "config", "--global", "user.name", git_user_name])

    print("Committing and pushing updated list...")
    
    run_command(["git", "add", OUTPUT_FILE_NAME])
    
    try:
        run_command(["git", "commit", "-m", f"Update domains list ({total_lines} domains)"])
    except RuntimeError as e:
        if "nothing to commit" in str(e):
            print("No changes to commit. Skipping push.")
            return
        raise
    
    # Git pull/push logic (optimized for CI environment)
    if run(["git", "remote", "get-url", "origin"], check=False, capture_output=True).returncode == 0:
        print(f"Attempting to push to branch: {TARGET_BRANCH}")
        run_command(["git", "pull", "--rebase", "origin", TARGET_BRANCH])
        run_command(["git", "push", "origin", TARGET_BRANCH])
    else:
        print("Warning: Origin remote not found. Skipping Git push.")
        
    print("Git commit and push complete.")

# --- Main Execution ---
def main():
    """Main execution function for the Cloudflare blocklist update workflow."""
    try:
        # --- 0. Initializing ---
        print("--- 0. Initializing ---")
        
        if not API_TOKEN:
            raise ScriptExit("API_TOKEN environment variable is not set.")
        if not ACCOUNT_ID:
            raise ScriptExit("ACCOUNT_ID environment variable is not set.")

        is_git_repo = Path(".git").exists()
        if is_git_repo:
            # Sync local branch with remote
            print(f"Target Git Branch: {TARGET_BRANCH}")
            try:
                run_command(["git", "fetch", "origin", TARGET_BRANCH])
                run_command(["git", "checkout", TARGET_BRANCH])
                run_command(["git", "reset", "--hard", f"origin/{TARGET_BRANCH}"])
            except CalledProcessError as e:
                print(f"Warning: Git initialization failed. Continuing with potential outdated branch. Error: {e.stderr}", file=sys.stderr)
        else:
            print("Warning: Not running in a Git repository. Git operations will be skipped at the end.")


        # --- 1. Run the Aggregation ---
        total_lines = run_aggregation()

        # --- 2. Run the Cloudflare Sync ---
        sync_cloudflare(total_lines)
        
        # --- 3. Run the Git Commit ---
        if is_git_repo:
            commit_to_git(total_lines)

        print("================================================")
        print("Aggregation and Cloudflare upload finished!")
        print(f"Total unique domains: {total_lines}")
        print("================================================")

    except ScriptExit as e:
        if e.silent:
            print(f"Silent exit: {e}")
            sys.exit(0)
        else:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    except RuntimeError as e:
        print(f"Critical Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
