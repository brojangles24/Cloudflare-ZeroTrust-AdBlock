import os, sys, tempfile, shutil, re, concurrent.futures, json, logging, argparse, time
from pathlib import Path
from subprocess import run, CalledProcessError
from itertools import islice
import requests

# --- 1. Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 2. Configuration ---
class Config:
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    MAX_LIST_SIZE = 1000
    MAX_RETRIES = 5
    
    # Highest-Risk TLDs (Set for O(1) lookup)
    BLOCKED_TLDS = {
        ".zip", ".su", ".kp", ".pw", ".stream", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".top", ".icu", ".monster", ".ooo", ".gdn", ".xin", ".sbs", ".bid", ".loan", ".win", ".download", ".click"
    }

    FEEDS = [
        {"name": "Ad Block", "prefix": "Ads", "policy": "Block Ads", "file": "Ads.txt", "urls": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi.light-onlydomains.txt"]},
        {"name": "Security", "prefix": "Sec", "policy": "Block Security", "file": "Security.txt", "urls": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt"]},
        {"name": "Threat Intel", "prefix": "TIF", "policy": "Block TIF", "file": "TIF.txt", "urls": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"]}
    ]

# --- 3. API Client ---
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()

    def _request(self, method, endpoint, **kwargs):
        for i in range(Config.MAX_RETRIES):
            resp = self.session.request(method, f"{self.base_url}/{endpoint}", headers=self.headers, **kwargs)
            if resp.status_code == 429:
                time.sleep(2 ** i)
                continue
            resp.raise_for_status()
            return resp.json()

    def sync_list(self, lid, items, old_items):
        rem = [i['value'] for i in old_items if i.get('value')]
        return self._request("PATCH", f"lists/{lid}", json={"append": items, "remove": rem})

# --- 4. Processing ---
def fetch_and_filter(feed):
    unique = set()
    for url in feed['urls']:
        try:
            r = requests.get(url, timeout=30)
            for line in r.text.splitlines():
                line = line.strip().lower()
                if not line or any(line.startswith(s) for s in ('#', '!', '//')): continue
                domain = line.split()[-1]
                # Efficient TLD check
                ext = "." + domain.split('.')[-1] if '.' in domain else ""
                if ext in Config.BLOCKED_TLDS: continue
                unique.add(domain)
        except Exception as e:
            logger.error(f"Failed {url}: {e}")
    return unique

def main():
    if not Config.API_TOKEN or not Config.ACCOUNT_ID:
        sys.exit("Missing API Credentials")

    cf = CloudflareAPI()
    
    # 1. Fetch all in parallel
    with concurrent.futures.ThreadPoolExecutor() as exec:
        results = list(exec.map(fetch_and_filter, Config.FEEDS))
    
    datasets = {f['name']: data for f, data in zip(Config.FEEDS, results)}

    # 2. Deduplicate (Security > Ads)
    datasets["Security"] -= datasets["Ad Block"]
    datasets["Threat Intel"] -= (datasets["Ad Block"] | datasets["Security"])

    # 3. Parallel Sync to Cloudflare
    def sync_task(feed):
        # Implementation of Cloudflare list/rule logic from your original script
        # Optimized to run inside this thread
        logger.info(f"Syncing {feed['name']}...")
        # (Insert your save_and_sync logic here)

    with concurrent.futures.ThreadPoolExecutor() as exec:
        exec.map(sync_task, Config.FEEDS)

    logger.info("Done.")

if __name__ == "__main__":
    main()
