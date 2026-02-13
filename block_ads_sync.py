import os, re, logging, argparse, requests, concurrent.futures, time, math
from collections import Counter
from datetime import datetime
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- 1. Config ---
class Config:
    # --- Ensure these are set in GitHub Repository Secrets ---
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    # ---------------------------------------------------------
    MAX_LIST_SIZE = 1000  
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

# --- 3. API Client ---
class CloudflareAPI:
    def __init__(self):
        # Basic validation to prevent cryptic errors later
        if not Config.API_TOKEN or not Config.ACCOUNT_ID:
            raise ValueError("Missing API_TOKEN or ACCOUNT_ID env vars")
            
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

# --- 4. Processing Logic ---
def is_valid_domain(domain, ex_counts):
    # 1. Basic syntax and IP check
    if '.' not in domain or 'xn--' in domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        ex_counts["Invalid/IDN/IP"] += 1
        return False
    # 2. TLD Check
    tld = domain.rsplit('.', 1)[-1]
    if tld in MASTER_CONFIG['banned_tlds']:
        ex_counts[f"TLD: {tld}"] += 1
        return False
    # 3. Keyword Check
    if any(kw in domain for kw in MASTER_CONFIG['offloaded_keywords']):
        ex_counts["Keyword Offload"] += 1
        return False
    return True

def fetch_url(name, url):
    logger.info(f"Fetching: {name}")
    ex_counts, valid_domains, raw_count = Counter(), set(), 0
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')): continue
            
            # Strip inline comments if present
            domain = line.split('#')[0].strip().lower()
            if not domain: continue
            
            # Handle hosts file format (0.0.0.0 domain.com)
            if domain.startswith(('0.0.0.0 ', '127.0.0.1 ')):
                 domain = domain.split()[-1]

            raw_count += 1
            if is_valid_domain(domain, ex_counts):
                valid_domains.add(domain)
        return name, raw_count, valid_domains, ex_counts
    except Exception as e:
        logger.error(f"Error fetching {name}: {e}")
        return name, 0, set(), Counter()

def optimize_domains(domains):
    logger.info("Performing Tree-Based Deduplication...")
    # Reverse domains to sort by TLD then domain (e.g., moc.elpmaxe)
    reversed_domains = sorted([d[::-1] for d in domains])
    optimized, last_kept = [], None
    for d in reversed_domains:
        # If current domain starts with last kept domain + dot, it's a subdomain
        # e.g., "moc.elpmaxe.sda".startswith("moc.elpmaxe.") is True
        if last_kept and d.startswith(last_kept + "."):
            continue
        optimized.append(d)
        last_kept = d
    # Reverse back to normal
    return [d[::-1] for d in optimized]

# --- 5. Markdown & Chart Generator ---
def generate_mermaid_charts(stats):
    # Chart 1: The Funnel
    funnel_chart = f"""```mermaid
%%{{init: {{'theme': 'base', 'themeVariables': {{ 'pie1': '#00C853', 'pie2': '#FFAB00', 'pie3': '#2962FF', 'pie4': '#D50000'}}}}}}%%
pie title Data Processing Funnel
    "Active Rules ({stats['final_size']:,})" : {stats['final_size']}
    "Exact Duplicates ({stats['duplicates']:,})" : {stats['duplicates']}
    "Subdomain Opt. ({stats['tree_removed']:,})" : {stats['tree_removed']}
    "Filtered By Policy ({stats['total_excluded']:,})" : {stats['total_excluded']}
```"""

    # Chart 2: Top Exclusions (Top 6 slices + Others)
    top_ex = stats['global_ex'].most_common(6)
    other_ex_count = sum(stats['global_ex'].values()) - sum(count for _, count in top_ex)
    
    ex_slices = "\n".join([f'    "{reason.replace(":", "")} ({count:,})": {count}' for reason, count in top_ex])
    if other_ex_count > 0:
        ex_slices += f'\n    "Others ({other_ex_count:,})": {other_ex_count}'

    exclusion_chart = f"""```mermaid
%%{{init: {{'theme': 'forest'}}}}%%
pie title Top Blocked Categories
{ex_slices}
```"""
    return funnel_chart, exclusion_chart

def generate_markdown_report(stats):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    funnel_chart, exclusion_chart = generate_mermaid_charts(stats)
    
    tld_rows = "\n".join([f"| {reason} | {count:,} |" for reason, count in stats['global_ex'].most_common(25)])
    
    source_rows = []
    for name, data in stats['sources'].items():
        eff = round((data['valid'] / data['raw']) * 100, 1) if data['raw'] > 0 else 0
        source_rows.append(f"| {name} | {data['raw']:,} | {data['valid']:,} | {eff}% |")
    source_rows_str = "\n".join(source_rows)
    
    quota_percent = round((stats['final_size'] / Config.TOTAL_QUOTA) * 100, 2)
    quota_emoji = "🟢" if quota_percent < 80 else "🟡" if quota_percent < 95 else "🔴"

    md_content = f"""# 🛡️ Cloudflare Zero Trust Intelligence Report
> **Cycle Updated:** `{now}` | **Runtime:** `{stats['runtime']}s` | **Status:** {quota_emoji}

## 📊 Visual Insights

### Data Processing Funnel
How raw inputs are transformed into active rules.
{funnel_chart}

### Top Filtered Categories
What is being removed before optimization.
{exclusion_chart}

---

## 📋 Summary Metrics
| Metric | Count | % of Raw |
| :--- | :--- | :--- |
| **Total Ingested** | {stats['total_raw']:,} | 100% |
| **Active Rules (Final)** | **{stats['final_size']:,}** | **{round((stats['final_size']/stats['total_raw'])*100, 1) if stats['total_raw'] > 0 else 0}%** |
| **Noise Removed** | {stats['total_raw'] - stats['final_size']:,} | |

---

## 🚩 Deep Analytics & Trends
| Indicator | Value | Insight |
| :--- | :--- | :--- |
| **Cloudflare Quota** | `{quota_percent}%` | Used {stats['final_size']:,} of {Config.TOTAL_QUOTA:,} |
| **Average Domain Entropy** | `{stats['avg_entropy']}` | High entropy (>4.0) suggests DGA/Malware |
| **Max Domain Length** | `{stats['max_len']}` chars | Extremely long names are anomaly markers |
| **Common FQDN Depth** | `{stats['avg_depth']}` levels | Average subdomains per root |
| **API Chunks** | `{stats['chunks']}` lists | Total lists managed in Cloudflare Gateway |

---

## 🛰️ Provider Effectiveness
| Source | Raw Ingest | Validated | Clean Efficiency |
| :--- | :--- | :--- | :--- |
{source_rows_str}

---

## 🛑 Top 25 Filtered Categories List
| Reason / TLD | Count |
| :--- | :--- |
{tld_rows}
"""
    Path(MASTER_CONFIG['stats_filename']).write_text(md_content)
    logger.info("Markdown report with charts generated.")

# --- 6. Sync Mechanism ---
def sync_at4(cf, domains, force):
    out = Path(MASTER_CONFIG['filename'])
    sorted_domains = sorted(list(domains))
    new_content = '\n'.join(sorted_domains)
    chunks = [sorted_domains[i:i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    num_chunks = len(chunks)

    if out.exists() and not force and out.read_text().strip() == new_content.strip():
        logger.info("No changes detected in domain list. Skipping API sync.")
        return num_chunks

    out.write_text(new_content)
    lists = cf.get_lists()
    existing = sorted([l for l in lists if MASTER_CONFIG['prefix'] in l['name']], key=lambda x: x['name'])
    used_ids = []
    
    logger.info(f"Starting sync of {num_chunks} chunks...")

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
    
    # Cleanup old lists if the total count decreased
    if len(existing) > num_chunks:
        logger.info(f"Cleaning up {len(existing) - num_chunks} obsolete lists...")
        for old_list in existing[num_chunks:]:
            try: cf.delete_list(old_list['id'])
            except: pass
            
    return num_chunks

# --- 7. Main ---
def main():
    start_time = time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    
    try:
        cf = CloudflareAPI()
    except Exception as e:
        logger.critical(f"Failed to initialize API client: {e}")
        return

    if args.delete:
        logger.warning("DELETE MODE ACTIVATED. Removing Gateway rules and lists...")
        rules, lists = cf.get_rules(), cf.get_lists()
        rid = next((r['id'] for r in rules if r['name'] == MASTER_CONFIG['policy_name']), None)
        if rid: cf.delete_rule(rid)
        for l in [ls for ls in lists if MASTER_CONFIG['prefix'] in ls['name']]:
            try: cf.delete_list(l['id'])
            except: pass
        logger.info("Cleanup complete.")
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
    optimized_list = optimize_domains(all_unique)
    
    # --- Deep Analytics ---
    avg_entropy = round(sum(calculate_entropy(d) for d in optimized_list) / len(optimized_list), 3) if optimized_list else 0
    max_len = max(len(d) for d in optimized_list) if optimized_list else 0
    avg_depth = round(sum(d.count('.') + 1 for d in optimized_list) / len(optimized_list), 2) if optimized_list else 0
    
    if len(optimized_list) > Config.TOTAL_QUOTA:
        logger.error(f"OVER QUOTA: {len(optimized_list):,}. Sync aborted to prevent errors.")
        # Still generate report to show why it failed
        num_chunks = 0
    else:
        num_chunks = sync_at4(cf, optimized_list, args.force)
    
    generate_markdown_report({
        'total_raw': total_raw_fetched, 
        'total_excluded': total_excluded, 
        'duplicates': total_raw_fetched - total_excluded - len(all_unique), 
        'tree_removed': len(all_unique) - len(optimized_list), 
        'final_size': len(optimized_list), 
        'global_ex': global_ex, 
        'chunks': num_chunks, 
        'sources': source_stats,
        'avg_entropy': avg_entropy,
        'max_len': max_len,
        'avg_depth': avg_depth,
        'runtime': round(time.time() - start_time, 2)
    })

if __name__ == "__main__":
    main()
