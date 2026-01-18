import os, re, logging, argparse, requests, concurrent.futures
from collections import Counter
from datetime import datetime
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- Config ---
class Config:
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    MAX_LIST_SIZE = 1000 
    TOTAL_QUOTA = 300000 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

MASTER_CONFIG = {
    "prefix": "AT4",
    "policy_name": "AT4_Policy",
    "filename": "blocklist.txt",
    "banned_tlds": {
        "top", "xin", "bond", "cfd", "sbs", "icu", "win", "help", "cyou", "monster", 
        "click", "quest", "buzz", "ink", "fyi", "su", "motorcycles", "gay", "pw", 
        "gdn", "loan", "men", "party", "review", "webcam", "hair", "fun", "cam", 
        "stream", "bid", "zip", "mov", "xyz", "cn", "cc"
    },
    "urls": {
        "HaGeZi Ultimate": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
        #"TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
    }
}

class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])))

    def req(self, method, ep, **kwargs):
        r = self.session.request(method, f"{self.base_url}/{ep}", headers=self.headers, **kwargs)
        r.raise_for_status()
        return r.json()

def fetch_and_filter(name, url):
    excluded_counts = Counter()
    valid_domains = set()
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')): continue
            
            domain = line.split()[-1].lower()
            
            # Basic validation
            if '.' not in domain or 'xn--' in domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
                continue
                
            # TLD Exclusion Check
            tld = domain.rsplit('.', 1)[-1]
            if tld in MASTER_CONFIG['banned_tlds']:
                excluded_counts[tld] += 1
                continue
            
            valid_domains.add(domain)
            
        return name, valid_domains, excluded_counts
    except Exception as e:
        logger.error(f"Failed {name}: {e}")
        return name, set(), Counter()

def optimize(domains):
    rev = sorted([d[::-1] for d in domains])
    kept, last = [], ""
    for d in rev:
        if not (last and d.startswith(last + ".")):
            kept.append(d)
            last = d
    return [d[::-1] for d in kept]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    
    cf = CloudflareAPI()
    all_domains = set()
    global_exclusions = Counter()
    
    with concurrent.futures.ThreadPoolExecutor() as ex:
        futures = [ex.submit(fetch_and_filter, n, u) for n, u in MASTER_CONFIG['urls'].items()]
        for future in concurrent.futures.as_completed(futures):
            name, domains, exclusions = future.result()
            all_domains.update(domains)
            global_exclusions.update(exclusions)

    # Report Exclusions
    total_excluded = sum(global_exclusions.values())
    logger.info("--- TLD EXCLUSION REPORT ---")
    for tld, count in global_exclusions.most_common(10):
        logger.info(f".{tld}: {count:,} domains removed")
    logger.info(f"TOTAL DOMAINS EXCLUDED: {total_excluded:,}")
    logger.info("----------------------------")

    final = optimize(list(all_domains))
    
    if len(final) <= Config.TOTAL_QUOTA:
        # Syncing logic from previous version goes here
        logger.info(f"Final domain count for Cloudflare: {len(final):,}")
    else:
        logger.error(f"Quota exceeded: {len(final):,} > {Config.TOTAL_QUOTA}")

if __name__ == "__main__":
    main()
