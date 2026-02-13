import os, re, logging, argparse, requests, concurrent.futures, time, math
from collections import Counter
from datetime import datetime
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- 1. Config ---
class Config:
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    MAX_LIST_SIZE = 1001  
    MAX_RETRIES = 3
    TOTAL_QUOTA = 300000 
    REQUEST_TIMEOUT = (5, 15) # (Connect, Read)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

MASTER_CONFIG = {
    "name": "Ads, Tracker, Telemetry, Malware", 
    "prefix": "Ads, Tracker, Telemetry, Malware", 
    "policy_name": "Ads, Tracker, Telemetry, Malware",
    "filename": "aggregate_blocklist.txt",
    "stats_filename": "README_STATS.md",
    "banned_tlds": {
        "top", "xyz", "xin", "icu", "sbs", "cfd", "gdn", "monster", "buzz", "bid", 
        "stream", "webcam", "zip", "mov", "pw", "tk", "ml", "ga", "cf", "gq",
        "men", "work", "click", "link", "party", "trade", "date", "loan", "win", 
        "faith", "racing", "review", "country", "kim", "cricket", "science",
        "download", "ooo", "by", "cn", "ir", "kp", "ng", "ru", "su", "ss",
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
        "HaGeZi Pro++": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        #"HaGeZi Pro": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
        #"1Hosts Lite": "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
        #"TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
        #"OISD NSFW": "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt",
        "Hagezi NSFW": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
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

# --- 2. Analytics Utils ---
def calculate_entropy(domain):
    prob = [float(domain.count(c)) / len(domain) for c in dict.fromkeys(list(domain))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        # respect_retry_after_header=False prevents hanging on server-side rate limit delays
        retries = Retry(total=Config.MAX_RETRIES, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504], respect_retry_after_header=False)
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def _request(self, method, endpoint, **kwargs):
        resp = self.session.request(method, f"{self.base_url}/{endpoint}", headers=self.headers, timeout=Config.REQUEST_TIMEOUT, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def get_lists(self): return self._request("GET", "lists").get('result') or []
    def update_list(self, lid, name, items): return self._request("PUT", f"lists/{lid}", json={"name": name, "items": items})
    def create_list(self, name, items): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items})
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def get_rules(self): return self._request("GET", "rules").get('result') or []
    def create_rule(self, data): return self._request("POST", "rules", json=data)
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json=data)

# --- 3. Markdown Generator ---
def generate_markdown_report(stats):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Pre-generate complex strings to avoid f-string SyntaxErrors
    kw_rows = "\n".join([f'| `{kw}` | {count:,} |' for kw, count in stats["kw_ex"].most_common(10)])
    source_rows = "\n".join([f"| {n} | {d['raw']:,} | {d['valid']:,} | **{round((d['unique_to_source']/d['valid'])*100, 1) if d['valid'] > 0 else 0}%** |" for n, d in stats['sources'].items()])
    
    # Charts
    funnel_chart = f"""```mermaid
pie title Domain Sync Lifecycle
    "Active Rules" : {stats['final_size']}
    "Duplicates Found" : {stats['duplicates']}
    "Subdomain Pruning" : {stats['tree_removed']}
    "Keyword Filtered" : {stats['kw_total']}
    "TLD Filtered" : {stats['tld_total']}
```"""

    kw_slices = "\n".join([f'    "{kw} ({count:,})": {count}' for kw, count in stats['kw_ex'].most_common(8)])
    kw_chart = f"```mermaid\npie title Top Blocked Keywords\n{kw_slices}\n```"

    md_content = f"""# 🛡️ Cloudflare Zero Trust Intelligence Report
> **Last Update:** `{now}` | **Runtime:** `{stats['runtime']}s`

## 📊 Visual Insights
{funnel_chart}

{kw_chart}

---

## 📋 Summary Metrics
| Metric | Count | % of Raw |
| :--- | :--- | :--- |
| **Total Raw Ingested** | {stats['total_raw']:,} | 100% |
| **Keyword Filtered** | - {stats['kw_total']:,} | {round((stats['kw_total']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}% |
| **TLD Filtered** | - {stats['tld_total']:,} | {round((stats['tld_total']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}% |
| **Duplicate Removal** | - {stats['duplicates']:,} | {round((stats['duplicates']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}% |
| **Subdomain Pruning** | - {stats['tree_removed']:,} | {round((stats['tree_removed']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}% |
| **Final Cloudflare List** | **{stats['final_size']:,}** | **{round((stats['final_size']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}%** |

---

## 🚩 Keyword Analytics (Top 10)
| Keyword | Hits |
| :--- | :--- |
{kw_rows}

---

## 🛰️ Provider Analytics (Uniqueness)
| Source | Raw | Valid | Unique |
| :--- | :--- | :--- | :--- |
{source_rows}

---

## 🛠️ Infrastructure Stats
* **Avg Entropy:** `{stats['avg_entropy']}`
* **Max Domain Length:** `{stats['max_len']}`
* **Quota Usage:** `{round((stats['final_size']/Config.TOTAL_QUOTA)*100, 2)}%`
"""
    Path(MASTER_CONFIG['stats_filename']).write_text(md_content)

# --- 4. Core Logic ---
def is_valid_domain(domain, kw_ex, tld_ex, other_ex):
    if '.' not in domain or 'xn--' in domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        other_ex["Invalid/IP"] += 1
        return False
    tld = domain.rsplit('.', 1)[-1]
    if tld in MASTER_CONFIG['banned_tlds']:
        tld_ex[tld] += 1
        return False
    for kw in MASTER_CONFIG['offloaded_keywords']:
        if kw in domain:
            kw_ex[kw] += 1
            return False
    return True

def fetch_url(name, url):
    logger.info(f"🚀 Fetching: {name}")
    kw_ex, tld_ex, other_ex, valid_domains, raw_count = Counter(), Counter(), Counter(), set(), 0
    try:
        resp = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')): continue
            domain = line.split()[-1].lower()
            raw_count += 1
            if is_valid_domain(domain, kw_ex, tld_ex, other_ex):
                valid_domains.add(domain)
        logger.info(f"✅ Finished: {name}")
        return name, raw_count, valid_domains, kw_ex, tld_ex, other_ex
    except Exception as e:
        logger.error(f"❌ Error fetching {name}: {e}")
        return name, 0, set(), Counter(), Counter(), Counter()

def optimize_domains(domains):
    reversed_domains = sorted([d[::-1] for d in domains])
    optimized, last_kept = [], None
    for d in reversed_domains:
        if last_kept and d.startswith(last_kept + "."): continue
        optimized.append(d)
        last_kept = d
    return [d[::-1] for d in optimized]

def sync_at4(cf, domains, force):
    out = Path(MASTER_CONFIG['filename'])
    sorted_domains = sorted(list(domains))
    new_content = '\n'.join(sorted_domains)
    chunks = [sorted_domains[i:i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    num_chunks = len(chunks)
    if out.exists() and not force and out.read_text().strip() == new_content.strip(): return num_chunks
    out.write_text(new_content)
    lists = cf.get_lists()
    existing = sorted([l for l in lists if MASTER_CONFIG['prefix'] in l['name']], key=lambda x: x['name'])
    used_ids = []
    for idx, chunk in enumerate(chunks):
        items = [{"value": d} for d in chunk]
        if idx < len(existing):
            lid = existing[idx]['id']
            cf.update_list(lid, f"{MASTER_CONFIG['prefix']} {idx+1:03d}", items)
            used_ids.append(lid)
        else:
            res = cf.create_list(f"{MASTER_CONFIG['prefix']} {idx+1:03d}", items)
            used_ids.append(res['result']['id'])
    rules = cf.get_rules()
    rid = next((r['id'] for r in rules if r['name'] == MASTER_CONFIG['policy_name']), None)
    clauses = [f'any(dns.domains[*] in ${lid})' for lid in used_ids]
    payload = {"name": MASTER_CONFIG['policy_name'], "action": "block", "enabled": True, "filters": ["dns"], "traffic": " or ".join(clauses)}
    if rid: cf.update_rule(rid, payload)
    else: cf.create_rule(payload)
    return num_chunks

# --- 5. Main ---
def main():
    start_time = time.time()
    cf = CloudflareAPI()
    all_source_data, total_raw_fetched, total_valid_pool = {}, 0, []
    global_kw_ex, global_tld_ex = Counter(), Counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_url, name, url): name for name, url in MASTER_CONFIG['urls'].items()}
        for future in concurrent.futures.as_completed(futures):
            name, raw_fetched, valid_domains, kw_ex, tld_ex, other_ex = future.result()
            all_source_data[name] = {'raw': raw_fetched, 'valid': len(valid_domains), 'set': valid_domains}
            total_raw_fetched += raw_fetched
            total_valid_pool.extend(list(valid_domains))
            global_kw_ex.update(kw_ex)
            global_tld_ex.update(tld_ex)

    for name, data in all_source_data.items():
        others = set().union(*(d['set'] for n, d in all_source_data.items() if n != name))
        data['unique_to_source'] = len(data['set'] - others)

    unique_set = set(total_valid_pool)
    optimized_list = optimize_domains(unique_set)
    num_chunks = sync_at4(cf, optimized_list, False)
    
    generate_markdown_report({
        'total_raw': total_raw_fetched, 'kw_total': sum(global_kw_ex.values()), 'tld_total': sum(global_tld_ex.values()),
        'duplicates': len(total_valid_pool) - len(unique_set), 'tree_removed': len(unique_set) - len(optimized_list), 
        'final_size': len(optimized_list), 'kw_ex': global_kw_ex, 'sources': all_source_data,
        'avg_entropy': round(sum(calculate_entropy(d) for d in optimized_list) / len(optimized_list), 3) if optimized_list else 0,
        'max_len': max(len(d) for d in optimized_list) if optimized_list else 0,
        'chunks': num_chunks, 'runtime': round(time.time() - start_time, 2)
    })
    logger.info("✨ Intelligence Sync Complete.")

if __name__ == "__main__":
    main()
