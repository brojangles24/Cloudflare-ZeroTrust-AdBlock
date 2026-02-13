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
    MAX_LIST_SIZE = 1000  
    MAX_RETRIES = 3
    TOTAL_QUOTA = 300000 # Cloudflare Zero Trust Free/Standard Limit
    REQUEST_TIMEOUT = (5, 25)

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
        "accountant", "accountants", "rest", "bar", "bzar", "bet", "cc", "poker", "casino"
    },
    "keywords": {
        # AGGRESSIVE: Block if found ANYWHERE (catches zzzxxx154)
        "aggressive": {
            "xxx", "porn", "fuck", "tits", "pussy", "hentai", "milf", 
            "blowjob", "threesome", "bondage", "bdsm", "gangbang", "handjob", 
            "deepthroat", "bukkake",
        },
    },
    "urls": {
        # --- BASE AD/TRACKER PROTECTION (Active) ---
        #"HaGeZi Pro++": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        
        # --- CONTENT & AGGRESSIVE BLOCKS (Active) ---
        "Hagezi NSFW": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
        "Hagezi Anti-Piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
        "HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",

        # --- INFRASTRUCTURE & PRIVACY (Active) ---
        #"Hagezi Dynamic DNS": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
        #"Hagezi DoH Only": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-onlydomains.txt",
        #"Hagezi Badware Hoster": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt",

        # --- DISABLED / OPTIONAL ---
        "HaGeZi Ultimate": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
        #"Hagezi Safeserach not Supported": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
        #"Hagezi Social Media": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
        #"Hagezi DoH/VPN": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        #"1Hosts Lite": "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
        #"TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
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

# --- 3. Processing Core ---
def is_valid_domain(domain, kw_ex, tld_ex, other_ex):
    # CRITICAL: Clean domain of wildcards and leading dots to prevent 400 Bad Request
    domain = domain.strip().strip('.')
    
    if not domain or any(c in domain for c in ('*', '/', ':', '[', ']')):
        other_ex["Malformed/Wildcard"] += 1
        return False

    if '.' not in domain or 'xn--' in domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        other_ex["Invalid/IP/IDN"] += 1
        return False
    
    # 1. Banned TLD Check
    tld = domain.rsplit('.', 1)[-1]
    if tld in MASTER_CONFIG['banned_tlds']:
        tld_ex[tld] += 1
        return False
    
    # 2. Hybrid Keyword Matching
    # A. Aggressive Check (Substring)
    for kw in MASTER_CONFIG['keywords']['aggressive']:
        if kw in domain:
            kw_ex[kw] += 1
            return False

    # B. Safe Check (Segments Only) - Spares 'document', 'community', 'peacock'
    segments = re.split(r'\.|\-', domain)
    for kw in MASTER_CONFIG['keywords']['safe']:
        if kw in segments:
            kw_ex[kw] += 1
            return False
            
    return domain

def fetch_url(name, url):
    logger.info(f"🚀 Fetching: {name}")
    kw_ex, tld_ex, other_ex, valid_domains, raw_count = Counter(), Counter(), Counter(), set(), 0
    try:
        resp = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')): continue
            raw_domain = line.split()[-1].lower()
            raw_count += 1
            cleaned = is_valid_domain(raw_domain, kw_ex, tld_ex, other_ex)
            if cleaned:
                valid_domains.add(cleaned)
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

# --- 4. Sync & Reporting ---
def generate_markdown_report(stats):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    kw_rows = "\n".join([f'| `{kw}` | {count:,} |' for kw, count in stats["kw_ex"].most_common(12)])
    source_rows = "\n".join([f"| {n} | {d['raw']:,} | {d['valid']:,} | **{round((d['unique_to_source']/d['valid'])*100, 1) if d['valid'] > 0 else 0}%** |" for n, d in stats['sources'].items()])
    
    md_content = f"""# 🛡️ Isaac's Cloudflare Intelligence Report
> **Sync Update:** `{now}` | **Duration:** `{stats['runtime']}s`

## 📊 Processing Metrics
| Metric | Count | % of Raw |
| :--- | :--- | :--- |
| **Total Raw Ingested** | {stats['total_raw']:,} | 100% |
| **Keyword Filtered** | - {stats['kw_total']:,} | {round((stats['kw_total']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}% |
| **TLD Filtered (.cc, etc)** | - {stats['tld_total']:,} | {round((stats['tld_total']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}% |
| **Active Rules Sent** | **{stats['final_size']:,}** | **{round((stats['final_size']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}%** |

---

## 🚩 Top Blocked Keywords
{kw_rows}

---

## 🛰️ Provider Analytics
{source_rows}

---

## 🛠️ Infrastructure Health
* **Randomness Index (Entropy):** `{stats['avg_entropy']}`
* **Cloudflare Quota Usage:** `{round((stats['final_size']/Config.TOTAL_QUOTA)*100, 2)}%`
"""
    Path(MASTER_CONFIG['stats_filename']).write_text(md_content)

def sync_at4(cf, domains, force):
    out = Path(MASTER_CONFIG['filename'])
    if len(domains) > Config.TOTAL_QUOTA:
        logger.warning(f"⚠️ QUOTA FULL: Truncating from {len(domains):,} to {Config.TOTAL_QUOTA:,}")
        domains = domains[:Config.TOTAL_QUOTA]

    sorted_domains = sorted(list(domains))
    new_content = '\n'.join(sorted_domains)
    chunks = [sorted_domains[i:i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    
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
            
    if len(existing) > len(chunks):
        for i in range(len(chunks), len(existing)): cf.delete_list(existing[i]['id'])

    rules = cf.get_rules()
    rid = next((r['id'] for r in rules if r['name'] == MASTER_CONFIG['policy_name']), None)
    clauses = [f'any(dns.domains[*] in ${lid})' for lid in used_ids]
    payload = {"name": MASTER_CONFIG['policy_name'], "action": "block", "enabled": True, "filters": ["dns"], "traffic": " or ".join(clauses)}
    if rid: cf.update_rule(rid, payload)
    else: cf.create_rule(payload)
    return len(chunks)

# --- 5. Main ---
def main():
    start_time = time.time()
    cf = CloudflareAPI()
    all_source_data, total_raw_fetched, total_valid_pool = {}, 0, []
    global_kw_ex, global_tld_ex, global_other_ex = Counter(), Counter(), Counter()

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(fetch_url, name, url): name for name, url in MASTER_CONFIG['urls'].items()}
        for future in concurrent.futures.as_completed(futures):
            name, raw_fetched, valid_domains, kw_ex, tld_ex, other_ex = future.result()
            all_source_data[name] = {'raw': raw_fetched, 'valid': len(valid_domains), 'set': valid_domains}
            total_raw_fetched += raw_fetched
            total_valid_pool.extend(list(valid_domains))
            global_kw_ex.update(kw_ex)
            global_tld_ex.update(tld_ex)
            global_other_ex.update(other_ex)

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
    logger.info("✨ DONE. Intelligence Report Generated.")

if __name__ == "__main__":
    main()
