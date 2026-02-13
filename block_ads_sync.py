import os, re, logging, argparse, requests, concurrent.futures, time
from collections import Counter
from datetime import datetime
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- 1. Config ---
class Config:
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    MAX_LIST_SIZE = 1000  # Optimized for Cloudflare's 300-list limit
    MAX_RETRIES = 5
    TOTAL_QUOTA = 300000 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

MASTER_CONFIG = {
    "name": "Ads, Tracker, Telemetry, Malware", 
    "prefix": "Ads, Tracker, Telemetry, Malware", 
    "policy_name": "Ads, Tracker, Telemetry, Malware",
    "filename": "aggregate_blocklist.txt",
    "stats_filename": "README_STATS.md",
    "banned_tlds": {
        # High-Risk / Spam
        "top", "xyz", "xin", "icu", "sbs", "cfd", "gdn", "monster", "buzz", "bid", 
        "stream", "webcam", "zip", "mov", "pw", "tk", "ml", "ga", "cf", "gq",
        "men", "work", "click", "link", "party", "trade", "date", "loan", "win", 
        "faith", "racing", "review", "country", "kim", "cricket", "science",
        "download", "ooo",
        # Requested Country Blocks
        "by", "cn", "ir", "kp", "ng", "ru", "su", "ss",
        # Business & Gambling
        "accountant", "accountants", "rest", "bar", "bzar", "bet", "poker", "casino"
    },
    "offloaded_keywords": {
        "xxx", "porn", "sex", "fuck", "tits", "pussy", "dick", "cock", 
        "hentai", "milf", "blowjob", "threesome", "bondage", "bdsm", 
        "gangbang", "handjob", "deepthroat", "horny", "bukkake", "titfuck",
        "brazzers", "redtube", "pornhub", "xvideo"
    },
    "urls": {
        #"HaGeZi Ultimate": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
        #"HaGeZi Pro++": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        "HaGeZi Pro": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
        #"1Hosts Lite": "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
        #"TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
        "OISD NSFW": "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt",
        #"Hagezi NSFW": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
        "Hagezi Anti-Piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
        "HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
        #"Hagezi Social Media": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
        "Hagezi Dynamic DNS": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
        "Hagezi Badware Hoster": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt",
        #"Hagezi DoH/VPN": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        "Hagezi DoH Only": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-onlydomains.txt",
        "Hagezi Safeserach not Supported": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
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

# --- 3. Processing Logic ---
def is_valid_domain(domain, ex_counts):
    # IDN / Punycode / IP Check
    if '.' not in domain or 'xn--' in domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        ex_counts["Invalid/IDN/IP"] += 1
        return False
    # TLD filtering
    tld = domain.rsplit('.', 1)[-1]
    if tld in MASTER_CONFIG['banned_tlds']:
        ex_counts[f"TLD: {tld}"] += 1
        return False
    # Keyword filtering
    if any(kw in domain for kw in MASTER_CONFIG['offloaded_keywords']):
        ex_counts["Keyword Offload"] += 1
        return False
    return True

def fetch_url(name, url):
    logger.info(f"Fetching: {name}")
    ex_counts = Counter()
    valid_domains = set()
    raw_count = 0
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')): continue
            domain = line.split()[-1].lower()
            raw_count += 1
            if is_valid_domain(domain, ex_counts):
                valid_domains.add(domain)
        return name, raw_count, valid_domains, ex_counts
    except Exception as e:
        logger.error(f"Error fetching {name}: {e}")
        return name, 0, set(), Counter()

def optimize_domains(domains):
    logger.info("Performing Tree-Based Deduplication...")
    reversed_domains = sorted([d[::-1] for d in domains])
    optimized, last_kept = [], None
    for d in reversed_domains:
        if last_kept and d.startswith(last_kept + "."):
            continue
        optimized.append(d)
        last_kept = d
    return [d[::-1] for d in optimized]

# --- 4. Markdown Generator ---
def generate_markdown_report(stats):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tld_rows = "\n".join([f"| {reason} | {count:,} |" for reason, count in stats['global_ex'].most_common(20)])
    source_rows = "\n".join([f"| {name} | {data['raw']:,} | {data['valid']:,} |" for name, data in stats['sources'].items()])

    md_content = f"""# 🛡️ Cloudflare Zero Trust Intelligence Report
> **Generated on:** `{now}`

## 📊 Fleet Summary
| Metric | Value |
| :--- | :--- |
| **Total Raw Ingested** | {stats['total_raw']:,} |
| **Filtered (TLD/Keywords)** | - {stats['total_excluded']:,} |
| **Skipped (Duplicates)** | - {stats['duplicates']:,} |
| **Optimized (Subdomains)** | - {stats['tree_removed']:,} |
| **Final Upload Size** | **{stats['final_size']:,}** |

---

## 🛰️ Source Effectiveness
| Provider | Raw Domains | Passed Filter |
| :--- | :--- | :--- |
{source_rows}

---

## 🚩 Top Blocked TLDs & Categories
| Reason / TLD | Count |
| :--- | :--- |
{tld_rows}

---
## 🛠️ Performance
* **Cloudflare Chunks:** {stats['chunks']} lists
* **List Density:** {Config.MAX_LIST_SIZE} items/list
* **Quota Usage:** {round((stats['final_size'] / Config.TOTAL_QUOTA) * 100, 2)}%
"""
    Path(MASTER_CONFIG['stats_filename']).write_text(md_content)
    logger.info("Intelligence report updated.")

# --- 5. Sync Mechanism ---
def sync_at4(cf, domains, force):
    out = Path(MASTER_CONFIG['filename'])
    new_content = '\n'.join(sorted(domains))
    if out.exists() and not force and out.read_text().strip() == new_content.strip():
        logger.info("No changes detected. Skipping Sync.")
        return 0
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
            try: cf.delete_list(old_list['id'])
            except: pass
    logger.info("Sync Complete.")
    return len(chunks)

# --- 6. Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    cf = CloudflareAPI()

    if args.delete:
        rules, lists = cf.get_rules(), cf.get_lists()
        rid = next((r['id'] for r in rules if r['name'] == MASTER_CONFIG['policy_name']), None)
        if rid:
            cf.delete_rule(rid)
            time.sleep(3)
        for l in [ls for ls in lists if MASTER_CONFIG['prefix'] in ls['name']]:
            try: cf.delete_list(l['id'])
            except: pass
        return

    all_unique, global_ex, total_raw_fetched, source_stats = set(), Counter(), 0, {}
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(fetch_url, name, url) for name, url in MASTER_CONFIG['urls'].items()}
        for future in concurrent.futures.as_completed(futures):
            name, raw_fetched, valid_domains, ex_counts = future.result()
            all_unique.update(valid_domains)
            global_ex.update(ex_counts)
            total_raw_fetched += raw_fetched
            source_stats[name] = {'raw': raw_fetched, 'valid': len(valid_domains)}

    total_excluded = sum(global_ex.values())
    duplicates_count = total_raw_fetched - total_excluded - len(all_unique)
    optimized_list = optimize_domains(all_unique)
    tree_removed = len(all_unique) - len(optimized_list)
    
    if len(optimized_list) > Config.TOTAL_QUOTA:
        logger.error(f"OVER QUOTA: {len(optimized_list):,}. Sync aborted.")
        return

    num_chunks = sync_at4(cf, optimized_list, args.force)
    generate_markdown_report({'total_raw': total_raw_fetched, 'total_excluded': total_excluded, 'duplicates': duplicates_count, 'tree_removed': tree_removed, 'final_size': len(optimized_list), 'global_ex': global_ex, 'chunks': num_chunks, 'sources': source_stats, 'all_unique': all_unique})

if __name__ == "__main__":
    main()
