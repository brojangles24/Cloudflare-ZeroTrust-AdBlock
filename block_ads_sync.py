import os
import re
import logging
import argparse
import requests
import concurrent.futures
from datetime import datetime
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- 1. Config ---
class Config:
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    MAX_LIST_SIZE = 1000 
    MAX_RETRIES = 5
    # Cloudflare Zero Trust Free Limit
    TOTAL_QUOTA = 300000 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

MASTER_CONFIG = {
    "name": "AT4 Global", 
    "prefix": "AT4", 
    "policy_name": "AT4 Global Block",
    "filename": "aggregate_blocklist.txt",
    "banned_tlds": [
    "zip", "mov", "su", "top", "xin", "win", "icu", "sbs", 
    "cfd", "bond", "monster", "buzz", "tk", "ml", "ga", 
    "cf", "gq", "pw", "cc", "rest", "cam", "kim", "cricket", 
    "science", "work", "party", "review", "country", "motorcycles", 
    "ooo", "wang", "online", "host", "zw", "stream", 
    "date", "faith", "racing", "li", "ing", "foo", "meme", "bot"
],
    "urls": {
        "HaGeZi Pro++": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        "1Hosts Lite": "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
        "TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
        #"Fake Hosters": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    }
}

# --- 2. API Client ---
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        retries = Retry(total=Config.MAX_RETRIES, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def _request(self, method, endpoint, **kwargs):
        resp = self.session.request(method, f"{self.base_url}/{endpoint}", headers=self.headers, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def get_lists(self): return self._request("GET", "lists").get('result') or []
    def update_list(self, lid, name, items): return self._request("PUT", f"lists/{lid}", json={"name": name, "items": items})
    def create_list(self, name, items): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items})
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def get_rules(self): return self._request("GET", "rules").get('result') or []
    def create_rule(self, data): return self._request("POST", "rules", json=data)
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json=data)
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")

# --- 3. Logic ---
def is_valid_domain(domain):
    # 1. Basics: Must have a dot, no IP addresses
    if '.' not in domain: return False
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain): return False
    
    # 2. Punycode Exclusion (xn--)
    if 'xn--' in domain: return False
        
    # 3. Banned TLD Regex Check (Exact TLD match at end of string)
    tld_pattern = r'\.(' + '|'.join(MASTER_CONFIG['banned_tlds']) + ')$'
    if re.search(tld_pattern, domain):
        return False

    return True

def fetch_url(name, url):
    logger.info(f"Fetching: {name}")
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        valid_domains = set()
        raw_count = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')): continue
            raw_count += 1
            domain = line.split()[-1].lower()
            if is_valid_domain(domain):
                valid_domains.add(domain)
        return name, raw_count, valid_domains
    except Exception as e:
        logger.error(f"Error fetching {name}: {e}")
        return name, 0, set()

def optimize_domains(domains):
    """Aggressive Subdomain Removal (Blocks parent only)."""
    logger.info("Performing Tree-Based Deduplication...")
    reversed_domains = sorted([d[::-1] for d in domains])
    optimized = []
    last_kept = None
    for d in reversed_domains:
        if last_kept and d.startswith(last_kept + "."):
            continue
        optimized.append(d)
        last_kept = d
    return [d[::-1] for d in optimized]

def fetch_and_process():
    all_unique = set()
    stats_data = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(fetch_url, name, url): name for name, url in MASTER_CONFIG['urls'].items()}
        for future in concurrent.futures.as_completed(futures):
            name, raw_count, valid_domains = future.result()
            stats_data.append({"name": name, "raw": raw_count, "valid": len(valid_domains)})
            all_unique.update(valid_domains)
    
    original_count = len(all_unique)
    optimized_list = optimize_domains(all_unique)
    return optimized_list, stats_data, original_count

def write_markdown_stats(stats_data, original_unique, final_total):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    usage_pct = (final_total / Config.TOTAL_QUOTA) * 100
    
    md = [
        f"# 🛡️ AT4 Global Statistics",
        f"*Updated: {now}*",
        f"\n**QUOTA WATCH:** `{final_total:,} / {Config.TOTAL_QUOTA:,} ({usage_pct:.1f}%)`",
        "",
        "| Source | Raw | Unique |",
        "| :--- | :---: | :---: |"
    ]
    for s in stats_data:
        md.append(f"| {s['name']} | {s['raw']:,} | {s['valid']:,} |")
    
    md.append(f"\n* **Optimized Savings:** {original_unique - final_total:,} redundant subdomains removed.")
    
    if Config.TOTAL_QUOTA - final_total < 5000:
        md.append("\n⚠️ **CRITICAL QUOTA ALERT:** Less than 5,000 slots remaining.")
    
    Path("STATS.md").write_text('\n'.join(md))
    logger.info(f"FINAL COUNT: {final_total:,} ({usage_pct:.1f}% used)")

def sync_at4(cf, domains, force):
    out = Path(MASTER_CONFIG['filename'])
    new_content = '\n'.join(sorted(domains))
    if out.exists() and not force and out.read_text().strip() == new_content.strip():
        logger.info("No changes detected. Skipping Sync.")
        return
    out.write_text(new_content)

    lists = cf.get_lists()
    existing = sorted([l for l in lists if MASTER_CONFIG['prefix'] in l['name']], key=lambda x: x['name'])
    
    sorted_domains = sorted(list(domains))
    chunks = [sorted_domains[i:i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    used_ids = []

    logger.info(f"Syncing {len(chunks)} chunks to Cloudflare...")

    for idx, chunk in enumerate(chunks):
        list_name = f"{MASTER_CONFIG['prefix']} {idx+1:03d}"
        items = [{"value": d} for d in chunk]
        if idx < len(existing):
            lid = existing[idx]['id']
            cf.update_list(lid, list_name, items)
            used_ids.append(lid)
        else:
            res = cf.create_list(list_name, items)
            used_ids.append(res['result']['id'])

    rules = cf.get_rules()
    rid = next((r['id'] for r in rules if r['name'] == MASTER_CONFIG['policy_name']), None)
    clauses = [f'any(dns.domains[*] in ${lid})' for lid in used_ids]
    payload = {"name": MASTER_CONFIG['policy_name'], "action": "block", "enabled": True, "filters": ["dns"], "traffic": " or ".join(clauses)}
    
    if rid: cf.update_rule(rid, payload)
    else: cf.create_rule(payload)
    
    if len(existing) > len(chunks):
        for old_list in existing[len(chunks):]:
            cf.delete_list(old_list['id'])
    logger.info("Sync Complete.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    cf = CloudflareAPI()

    if args.delete:
        rules, lists = cf.get_rules(), cf.get_lists()
        rid = next((r['id'] for r in rules if r['name'] == MASTER_CONFIG['policy_name']), None)
        if rid: cf.delete_rule(rid)
        for l in [ls for ls in lists if MASTER_CONFIG['prefix'] in ls['name']]: cf.delete_list(l['id'])
        return

    all_domains, stats_data, original_unique = fetch_and_process()
    
    if len(all_domains) > Config.TOTAL_QUOTA:
        logger.error(f"OVER QUOTA: {len(all_domains):,}. Script aborted.")
        exit(1)

    write_markdown_stats(stats_data, original_unique, len(all_domains))
    sync_at4(cf, all_domains, args.force)

if __name__ == "__main__":
    main()
