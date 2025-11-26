import os
import sys
import logging
from pathlib import Path

import requests

# --- 1. Configuration & Setup ---

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Define configuration settings
class Config:
    # Use environment variables for sensitive data
    API_TOKEN: str = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID: str = os.environ.get("ACCOUNT_ID", "")
    PREFIX: str = "Block ads"
    MAX_RETRIES: int = 10
    
    # Files to delete locally
    FILES_TO_DELETE = ["Aggregated_List.txt", "Aggregated_List.txt.*"]

    @classmethod
    def validate(cls):
        if not cls.API_TOKEN:
            raise ScriptExit("API_TOKEN environment variable is not set.", critical=True)
        if not cls.ACCOUNT_ID:
            raise ScriptExit("ACCOUNT_ID environment variable is not set.", critical=True)

# Load config
CFG = Config()

# --- 2. Helper Functions & Exceptions ---

class ScriptExit(Exception):
    """Custom exception to stop the script gracefully."""
    def __init__(self, message, critical=False):
        super().__init__(message)
        self.critical = critical

# --- 3. Cloudflare API Client (Context Manager with Secret Redaction) ---

class CloudflareAPI:
    """Handles secure and reliable communication with the Cloudflare API."""
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
            logger.debug(f"Response text: {e.response.text if e.response else 'N/A'}")
            raise RuntimeError(f"Cloudflare API failed: {e}")

    # Simplified API method definitions
    def get_lists(self): return self._request("GET", "lists")
    def get_rules(self): return self._request("GET", "rules")
    def delete_list(self, list_id): return self._request("DELETE", f"lists/{list_id}")
    def delete_rule(self, rule_id): return self._request("DELETE", f"rules/{rule_id}")


# --- 4. Cleanup Logic ---

def delete_local_files():
    """Deletes the aggregated domain list and its chunks locally."""
    logger.info("Deleting local files...")
    deleted_count = 0
    
    for pattern in CFG.FILES_TO_DELETE:
        # Use glob for wildcard matching (e.g., Aggregated_List.txt.*)
        for file_path in Path('.').glob(pattern):
            try:
                os.remove(file_path)
                logger.debug(f"Deleted file: {file_path}")
                deleted_count += 1
            except OSError as e:
                logger.warning(f"Could not delete {file_path}: {e}")

    logger.info(f"Finished deleting {deleted_count} local files.")

def cleanup_cloudflare():
    """Deletes the policy and lists matching the configured prefix."""
    logger.info("--- Cloudflare Gateway Cleanup ---")

    with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf:
        
        # 1. Get current lists and policies
        logger.info("Fetching current policies and lists...")
        current_policies = cf.get_rules().get('result', [])
        current_lists = cf.get_lists().get('result', [])

        # 2. Delete Policy
        policy_to_delete = next((p for p in current_policies if p.get('name') == CFG.PREFIX), None)
        
        if policy_to_delete:
            policy_id = policy_to_delete['id']
            logger.info(f"Deleting policy '{CFG.PREFIX}' ({policy_id})...")
            try:
                cf.delete_rule(policy_id)
                logger.info(f"Policy {policy_id} deleted successfully.")
            except RuntimeError as e:
                logger.error(f"Failed to delete policy {policy_id}. Continuing to lists.")
        else:
            logger.info(f"No policy found with name '{CFG.PREFIX}'. Skipping policy deletion.")

        # 3. Delete Lists
        lists_to_delete = [l for l in current_lists if CFG.PREFIX in l.get('name', '')]
        
        if lists_to_delete:
            logger.info(f"Found {len(lists_to_delete)} lists with prefix '{CFG.PREFIX}'. Deleting...")
            for list_item in lists_to_delete:
                list_id = list_item['id']
                list_name = list_item['name']
                logger.info(f"Deleting list '{list_name}' ({list_id})...")
                try:
                    cf.delete_list(list_id)
                except RuntimeError as e:
                    logger.error(f"Failed to delete list {list_id}. Error: {e}")
            logger.info("All lists deletion attempts complete.")
        else:
            logger.info(f"No lists found with prefix '{CFG.PREFIX}'. Skipping list deletion.")

# --- 5. Main Execution ---

def main():
    """Main execution function for the Cloudflare cleanup workflow."""
    try:
        logger.info("================================================")
        logger.info("Starting Cloudflare cleanup script...")
        
        # Validate environment variables
        CFG.validate()

        # 1. Delete local files
        delete_local_files()

        # 2. Cleanup Cloudflare resources
        cleanup_cloudflare()

        logger.info("================================================")
        logger.info("✅ Cloudflare cleanup finished successfully!")
        logger.info("================================================")

    except ScriptExit as e:
        if e.critical:
            logger.critical(f"Configuration Error: {e}")
            sys.exit(1)
        # This shouldn't be reached, but included for safety
        logger.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"An unexpected fatal error occurred: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
