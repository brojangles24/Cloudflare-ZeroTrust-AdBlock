import os, re, logging, argparse, requests, concurrent.futures
from collections import Counter
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# --- 1. Configuration & Limits ---
class Config:
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    
    MAX_LISTS = 300             # Max number of lists allowed
    MAX_ITEMS_PER_LIST = 1000   # Max domains per list
    MAX_LISTS_PER_RULE = 50     # Max lists per rule
    GLOBAL_CAP = MAX_LISTS * MAX_ITEMS_PER_LIST 
    MAX_RETRIES = 3

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

MASTER_CONFIG = {
    "prefix": "Blocklist", 
    "policy_prefix": "Blocklist Policy", 
    "filename": "aggregate_blocklist.txt",
    
    # 1. BANNED TLDs (These are EXCLUDED to save quota; block them via TLD Rule)
    "banned_tlds": {
        "top", "xin", "icu", "sbs", "cfd", "gdn", "monster", "buzz", "bid", "stream", "webcam", 
        "zip", "mov", "cn", "su", "ru", "pw", "tk", "ml", "ga", "cf", "gq",
        "men", "work", "click", "link", "party", "trade", "date", "loan", "win", 
        "faith", "racing", "review", "country", "kim", "cricket", "science",
        "download", "accountant", "accountants", "rest", "bar", "bzar", "ooo", "bet", "poker", "casino"
    },

    # 2. OFFLOADED KEYWORDS (These are EXCLUDED from the list because you have a Regex Rule for them)
    "offloaded_keywords": {
        "xxx", "porn", "sex", "fuck", "tits", "pussy", "dick", "cock", 
        "webcam", "hentai", "milf", "anal", 
    },

    "urls": {
        #"HaGeZi Ultimate": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
        #"HaGeZi Pro++": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        #"HaGeZi Pro": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
        "1Hosts Lite": "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
        #"TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
        #"HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
        "OISD NSFW": "https://raw.githubusercontent.com/cbuijs/oisd/refs/heads/master/nsfw/domains"
    }
}

IP_REGEX = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
# Keyword Regex: Matches if keyword is present
keywords_pattern = "|".join(re.escape(k) for k in MASTER_CONFIG['offloaded_keywords'])
OFFLOAD_REGEX = re.compile(fr'(?:^|[.-])({keywords_pattern})(?:$|[.-])', re.IGNORECASE)

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
    def create_list(self, name, items): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items})
    def update_list(self, lid, name, items): return self._request("PUT", f"lists/{lid}", json={"name": name, "items": items})
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    
    def get_rules(self): return self._request("GET", "rules").get('result') or []
    def create_rule(self, data): return self._request("POST", "rules", json=data)
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json=data)
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")

# --- 3. Processing Logic ---
def is_valid_domain(domain, ex_counts):
    # 1. Filter IPs/Invalid
    if '.' not in domain or 'xn--' in domain or IP_REGEX.match(domain): 
        return False
    
    # 2. Filter Banned TLDs (Quota Saving)
    tld = domain.rsplit('.', 1)[-1]
    if tld in MASTER_CONFIG['banned_tlds']:
        ex_counts[f"TLD Excluded ({tld})"] += 1
        return False

    # 3. Filter Offloaded Keywords (Quota Saving)
    # We return FALSE here because the Regex Rule will catch these.
    if OFFLOAD_REGEX.search(domain):
        ex_counts["Regex Offloaded"] += 1
        return False 

    return True

def fetch_url(name, url):
    logger.info(f"Fetching: {name}")
    ex_counts = Counter()
    valid_domains = set()
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '!', '//')): continue
            parts = line.split()
            domain = parts[-1].lower() if len(parts) > 1 and parts[0] in ['0.0.0.0', '127.0.0.1'] else parts[0].lower()
            
            if is_valid_domain(domain, ex_counts):
                valid_domains.add(domain)
        return name, valid_domains, ex_counts
    except Exception as e:
        logger.error(f"Error fetching {name}: {e}")
        return name, set(), Counter()

def optimize_domains(domains):
    logger.info("Performing Tree-Based Deduplication...")
    reversed_domains = sorted([d[::-1] for d in domains])
    optimized = []
    last_kept = None
    
    for d in reversed_domains:
        if last_kept and d.startswith(last_kept + "."): continue
        optimized.append(d)
        last_kept = d
    
    return [d[::-1] for d in optimized]

# --- 4. Sync Mechanism ---
def chunk_list(data, size):
    for i in range(0, len(data), size): yield data[i:i + size]

def sync_resources(cf, domains, force):
    if len(domains) > Config.GLOBAL_CAP:
        logger.warning(f"⚠️ LIMIT EXCEEDED: {len(domains):,} domains.")
        logger.warning(f"⚠️ Truncating to {Config.GLOBAL_CAP:,}...")
        domains = domains[:Config.GLOBAL_CAP]

    out = Path(MASTER_CONFIG['filename'])
    new_content = '\n'.join(domains)
    if out.exists() and not force and out.read_text().strip() == new_content.strip():
        logger.info("No changes detected. Skipping Sync.")
        return
    out.write_text(new_content)

    batches = list(chunk_list(domains, Config.MAX_ITEMS_PER_LIST))
    logger.info(f"Syncing {len(batches)} lists ({len(domains)} items)...")

    existing_lists = sorted([l for l in cf.get_lists() if l['name'].startswith(MASTER_CONFIG['prefix'])], key=lambda x: x['name'])
    active_list_ids = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = []
        for i, batch in enumerate(batches):
            list_name = f"{MASTER_CONFIG['prefix']} {i+1:03d}"
            formatted = [{"value": d} for d in batch]
            if i < len(existing_lists):
                lid = existing_lists[i]['id']
                futures.append(executor.submit(cf.update_list, lid, list_name, formatted))
                active_list_ids.append(lid)
            else:
                futures.append(executor.submit(cf.create_list, list_name, formatted))

        if len(existing_lists) > len(batches):
             for old_list in existing_lists[len(batches):]:
                 futures.append(executor.submit(cf.delete_list, old_list['id']))

        for f in concurrent.futures.as_completed(futures):
            try:
                res = f.result()
                if isinstance(res, dict) and 'result' in res:
                    active_list_ids.append(res['result']['id'])
            except Exception as e:
                logger.error(f"List sync error: {e}")

    active_list_ids = sorted(list(set(active_list_ids)))
    rule_chunks = list(chunk_list(active_list_ids, Config.MAX_LISTS_PER_RULE))
    existing_rules = [r for r in cf.get_rules() if r['name'].startswith(MASTER_CONFIG['policy_prefix'])]
    
    logger.info(f"Updating {len(rule_chunks)} Gateway Policies...")
    for i, r_chunk in enumerate(rule_chunks):
        rule_name = f"{MASTER_CONFIG['policy_prefix']} {i+1}"
        clauses = [f'any(dns.domains[*] in ${lid})' for lid in r_chunk]
        traffic_expr = " or ".join(clauses)
        payload = {"name": rule_name, "action": "block", "enabled": True, "filters": ["dns"], "traffic": traffic_expr}

        target_rid = existing_rules[i]['id'] if i < len(existing_rules) else None
        try:
            if target_rid: cf.update_rule(target_rid, payload)
            else: cf.create_rule(payload)
        except Exception as e:
            logger.error(f"Rule sync error: {e}")

    if len(existing_rules) > len(rule_chunks):
        for old_rule in existing_rules[len(rule_chunks):]:
            cf.delete_rule(old_rule['id'])

    logger.info("Sync Complete.")

# --- 5. Main ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    
    cf = CloudflareAPI()
    if args.delete:
        # Deletion logic (same as before)
        return

    all_unique = set()
    global_ex = Counter()
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(fetch_url, name, url): name for name, url in MASTER_CONFIG['urls'].items()}
        for future in concurrent.futures.as_completed(futures):
            name, valid_domains, ex_counts = future.result()
            all_unique.update(valid_domains)
            global_ex.update(ex_counts)

    logger.info("-" * 40)
    logger.info(f"TOTAL EXCLUSIONS (Saved Quota): {sum(global_ex.values()):,}")
    for k, v in global_ex.most_common(5):
        logger.info(f"  {k}: {v:,}")
    logger.info("-" * 40)
    
    optimized_list = optimize_domains(all_unique)
    sync_resources(cf, optimized_list, args.force)

if __name__ == "__main__":
    main()
