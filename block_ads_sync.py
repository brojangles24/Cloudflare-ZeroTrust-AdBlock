import os, re, logging, argparse, requests, concurrent.futures
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
        "TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
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

def is_valid(domain):
    if '.' not in domain or 'xn--' in domain or re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        return False
    return domain.rsplit('.', 1)[-1] not in MASTER_CONFIG['banned_tlds']

def fetch_and_filter(name, url):
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        valid = {d for line in r.text.splitlines() if (d := line.strip().split()[-1].lower()) and not line.startswith(('#', '!', '//')) and is_valid(d)}
        return name, len(valid), valid
    except Exception as e:
        logger.error(f"Failed {name}: {e}")
        return name, 0, set()

def optimize(domains):
    rev = sorted([d[::-1] for d in domains])
    kept, last = [], ""
    for d in rev:
        if not (last and d.startswith(last + ".")):
            kept.append(d)
            last = d
    return [d[::-1] for d in kept]

def sync(cf, domains):
    # 1. TLD Rule
    tld_regex = r'\.(' + '|'.join(MASTER_CONFIG['banned_tlds']) + ')$'
    rules = cf.req("GET", "rules")['result']
    tld_payload = {"name": "Banned TLDs", "action": "block", "enabled": True, "filters": ["dns"], "traffic": f'any(dns.fqdn matches r#"{tld_regex}"#)'}
    
    tld_rid = next((r['id'] for r in rules if r['name'] == "Banned TLDs"), None)
    cf.req("PUT" if tld_rid else "POST", f"rules/{tld_rid}" if tld_rid else "rules", json=tld_payload)

    # 2. Lists
    existing = sorted([l for l in cf.req("GET", "lists")['result'] if MASTER_CONFIG['prefix'] in l['name']], key=lambda x: x['name'])
    chunks = [domains[i:i + Config.MAX_LIST_SIZE] for i in range(0, len(domains), Config.MAX_LIST_SIZE)]
    used_ids = []

    for i, chunk in enumerate(chunks):
        name, items = f"{MASTER_CONFIG['prefix']}_{i:03}", [{"value": d} for d in chunk]
        if i < len(existing):
            cf.req("PUT", f"lists/{existing[i]['id']}", json={"name": name, "items": items})
            used_ids.append(existing[i]['id'])
        else:
            used_ids.append(cf.req("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items})['result']['id'])

    # 3. Policy Rule
    policy_payload = {"name": MASTER_CONFIG['policy_name'], "action": "block", "enabled": True, "filters": ["dns"], "traffic": " or ".join([f'any(dns.domains[*] in ${lid})' for lid in used_ids])}
    pol_rid = next((r['id'] for r in rules if r['name'] == MASTER_CONFIG['policy_name']), None)
    cf.req("PUT" if pol_rid else "POST", f"rules/{pol_rid}" if pol_rid else "rules", json=policy_payload)
    
    # Cleanup
    if len(existing) > len(chunks):
        for l in existing[len(chunks):]: cf.req("DELETE", f"lists/{l['id']}")

def main():
    args = argparse.ArgumentParser()
    args.add_argument("--force", action="store_true")
    cf, all_domains = CloudflareAPI(), set()
    
    with concurrent.futures.ThreadPoolExecutor() as ex:
        for _, _, d in [f.result() for f in [ex.submit(fetch_and_filter, n, u) for n, u in MASTER_CONFIG['urls'].items()]]:
            all_domains.update(d)

    final = optimize(list(all_domains))
    if len(final) <= Config.TOTAL_QUOTA:
        sync(cf, sorted(final))
        logger.info(f"Success. Active domains: {len(final)}")
    else:
        logger.error("Quota exceeded.")

if __name__ == "__main__":
    main()
