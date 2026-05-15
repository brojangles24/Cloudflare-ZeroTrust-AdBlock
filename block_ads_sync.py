import os
import re
import logging
import requests
import concurrent.futures
import time
import io
import zipfile
import gzip
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ---------------------------------------------------------------------------
# 1. Config & Top Lists
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN               = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID              = os.environ.get("ACCOUNT_ID", "")
    
    # --- TOGGLES ---
    ENABLE_TLD_KW_FILTERING = False
    ENABLE_RELEVANCE_FILTER = True
    
    MAX_LIST_SIZE           = 1000
    MAX_RETRIES             = 3
    TOTAL_QUOTA             = 300_000
    REQUEST_TIMEOUT         = (5, 25)
    MAX_WORKERS             = 5

    # Names to scrub to free up the 100-list limit
    SCRUB_TARGETS = [
        "Ads, Tracker, Telemetry, Malware", 
        "Base Normal", 
        "Pro++ Extra", 
        "Social Block"
    ]

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID") if not getattr(cls, k)]
        if missing:
            raise EnvironmentError(f"Missing environment variables: {', '.join(missing)}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
    ("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://builtwith.com/dl/builtwith-top1m.zip", 0, False, "zip"),
]

_BANNED_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "icu", "top", "xin", "gdn", "bid", "pw", "sbs", 
    "cfd", "monster", "stream", "webcam", "download", "win", "party", "racing", 
    "trade", "loan", "faith", "review", "accountant", "accountants", "cricket",
    "zip", "mov", "xxx", "casino"
}

_OFFLOAD_KW = { 
    "blowjob", "threesome", "gangbang", "handjob", "deepthroat", 
    "bukkake", "titfuck", "shemale", 
    "porn", "redtube", "brazzers", "xnxx", "xvideo", "xxvideo", "omegle", "xxx"
}

BLOCKLIST_URLS = {
    "HaGeZi Normal": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
    "HaGeZi Pro++": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
    "Hagezi NSFW": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
    "HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "OISD NSFW": "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_nsfw.txt",
    "HaGeZi Safesearch Not Support": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
    "HaGeZi Bypass Block": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "Steven Black NSFW": "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
    "HaGeZi Anti Piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt", 
    "HaGeZi Dynamic DNS": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
    "HaGeZi Gambling Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/gambling.mini-onlydomains.txt",
    "HaGeZi Social": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt"
}

POLICIES = [
    {
        "prefix": "Base Normal",
        "policy_name": "Base Ads & NSFW (Kalli + Me)",
        "filename": "base_blocklist.txt",
        "identity_condition": 'identity.email == "jorgensenkalli@gmail.com" or identity.email == "johndoenomore24@gmail.com"',
        "include": ["HaGeZi Normal", "Hagezi NSFW", "HaGeZi Fake", "OISD NSFW", "HaGeZi Safesearch Not Support", "HaGeZi Bypass Block", "Steven Black NSFW", "HaGeZi Anti Piracy", "HaGeZi Dynamic DNS", "HaGeZi Gambling Mini"],
        "exclude": []
    },
    {
        "prefix": "Pro++ Extra",
        "policy_name": "Pro++ Extra & Social Blocks (Me Only)",
        "filename": "proplus_diff.txt",
        "identity_condition": 'identity.email == "johndoenomore24@gmail.com"',
        "include": ["HaGeZi Pro++", "HaGeZi Social"],
        "exclude": ["HaGeZi Normal"] 
    }
]

# ---------------------------------------------------------------------------
# 2. Cloudflare API Client
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        retry = Retry(total=Config.MAX_RETRIES, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _request(self, method, endpoint, **kwargs):
        resp = self.session.request(method, f"{self.base_url}/{endpoint}", headers=self.headers, timeout=Config.REQUEST_TIMEOUT, **kwargs)
        if not resp.ok:
            logger.error(f"Cloudflare API Error [{resp.status_code}]: {resp.text}")
        resp.raise_for_status()
        return resp.json()

    def get_lists(self):                      return self._request("GET",    "lists").get("result") or []
    def get_rules(self):                      return self._request("GET",    "rules").get("result") or []
    def delete_list(self, lid):               return self._request("DELETE", f"lists/{lid}")
    def delete_rule(self, rid):               return self._request("DELETE", f"rules/{rid}")
    def create_list(self, name, items):       return self._request("POST",   "lists",          json={"name": name, "type": "DOMAIN", "items": items})
    def update_list(self, lid, name, items):  return self._request("PUT",    f"lists/{lid}",   json={"name": name, "items": items})
    def create_rule(self, data):              return self._request("POST",   "rules",          json=data)
    def update_rule(self, rid, data):         return self._request("PUT",    f"rules/{rid}",   json=data)

# ---------------------------------------------------------------------------
# 3. Cleanup & Domain Logic
# ---------------------------------------------------------------------------
def nuke_old_setup(cf: CloudflareAPI):
    logger.info("Starting pre-flight nuke of old rules and lists...")
    
    # 1. Rules MUST be deleted first
    rules = cf.get_rules()
    for r in rules:
        if any(target in r["name"] for target in Config.SCRUB_TARGETS) or "Ads, Tracker" in r["name"]:
            try:
                cf.delete_rule(r["id"])
                logger.info(f"Deleted Rule: {r['name']}")
            except Exception as e:
                logger.error(f"Could not delete rule {r['name']}: {e}")

    # 2. Now lists can be deleted
    lists = cf.get_lists()
    for l in lists:
        if any(target in l["name"] for target in Config.SCRUB_TARGETS) or "Ads, Tracker" in l["name"]:
            try:
                cf.delete_list(l["id"])
                logger.info(f"Deleted List: {l['name']}")
            except Exception as e:
                logger.error(f"Could not delete list {l['name']}: {e}")

def has_suffix_match(host: str, lookup_set: set[str]) -> bool:
    if host in lookup_set: return True
    idx = host.find('.')
    while idx != -1:
        if host[idx+1:] in lookup_set: return True
        idx = host.find('.', idx + 1)
    return False

def _parse_csv_lines(iterable, col_idx: int, skip_header: bool) -> set[str]:
    domains = set()
    for i, line in enumerate(iterable):
        if skip_header and i == 0: continue
        parts = line.split(',')
        if len(parts) > col_idx:
            dom = parts[col_idx].strip().lower().strip('"')
            if dom and "." in dom: domains.add(dom)
    return domains

def fetch_top_list(url: str, col_idx: int, skip_header: bool, compression: str) -> set[str]:
    logger.info(f"Fetching Top List: {url}")
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=90)
        r.raise_for_status()
        if compression == "zip":
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                with io.TextIOWrapper(z.open(z.namelist()[0]), encoding='utf-8', errors='ignore') as f:
                    return _parse_csv_lines(f, col_idx, skip_header)
        elif compression == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
                with io.TextIOWrapper(gz, encoding='utf-8', errors='ignore') as f:
                    return _parse_csv_lines(f, col_idx, skip_header)
        else:
            return _parse_csv_lines(r.text.splitlines(), col_idx, skip_header)
    except Exception as e:
        logger.error(f"Error fetching top list {url}: {e}")
        return set()

def is_valid_domain(domain: str, top_domains: set[str]) -> str | None:
    domain = domain.strip().strip(".")
    if not domain or any(c in domain for c in "*/:[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None
    if Config.ENABLE_TLD_KW_FILTERING:
        if domain.rsplit(".", 1)[-1] in _BANNED_TLDS or any(kw in domain for kw in _OFFLOAD_KW):
            return None
    if Config.ENABLE_RELEVANCE_FILTER and top_domains:
        if not has_suffix_match(domain, top_domains):
            return None
    return domain

def fetch_url(name: str, url: str, top_domains: set[str]) -> tuple[str, set[str]]:
    valid_domains = set()
    try:
        resp = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"): continue
            cleaned = is_valid_domain(line.split()[-1].lower(), top_domains)
            if cleaned: valid_domains.add(cleaned)
        logger.info(f"Fetched {name}: {len(valid_domains):,} domains")
    except Exception as exc:
        logger.error(f"Error fetching {name}: {exc}")
    return name, valid_domains

def optimize_domains(domains: set[str]) -> list[str]:
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized, last_kept = [], None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."): continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]

# ---------------------------------------------------------------------------
# 4. Cloudflare Sync
# ---------------------------------------------------------------------------
def sync_to_cloudflare(cf: CloudflareAPI, domains: list[str], policy: dict) -> None:
    if not domains: return
    domains = domains[:Config.TOTAL_QUOTA]
    sorted_domains = sorted(domains)
    chunks = [sorted_domains[i : i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    
    existing = sorted([l for l in cf.get_lists() if policy["prefix"] in l["name"]], key=lambda x: x["name"])
    used_ids = []

    for idx, chunk in enumerate(chunks):
        items = [{"value": d} for d in chunk]
        list_name = f"{policy['prefix']} {idx + 1:03d}"
        if idx < len(existing):
            cf.update_list(existing[idx]["id"], list_name, items)
            used_ids.append(existing[idx]["id"])
        else:
            res = cf.create_list(list_name, items)
            used_ids.append(res["result"]["id"])
    
    traffic_expr = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in used_ids])
    payload = {"name": policy["policy_name"], "action": "block", "enabled": True, "filters": ["dns"], "traffic": traffic_expr}
    if policy.get("identity_condition"): payload["identity"] = policy["identity_condition"]
    
    rules = cf.get_rules()
    rid = next((r["id"] for r in rules if r["name"] == policy["policy_name"]), None)
    if rid: cf.update_rule(rid, payload)
    else: cf.create_rule(payload)
    logger.info(f"Sync complete for policy: {policy['policy_name']}")

# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    # ONE-TIME NUKE to solve the dependency error
    nuke_old_setup(cf)
    
    global_top_domains = set()
    if Config.ENABLE_RELEVANCE_FILTER:
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            top_futures = [pool.submit(fetch_top_list, *lst) for lst in TOP_LISTS]
            for future in concurrent.futures.as_completed(top_futures): global_top_domains |= future.result()

    fetched_lists = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_url, name, url, global_top_domains): name for name, url in BLOCKLIST_URLS.items()}
        for future in concurrent.futures.as_completed(futures):
            name, valid_set = future.result()
            fetched_lists[name] = valid_set

    for policy in POLICIES:
        policy_domain_set = set()
        for inc in policy.get("include", []): policy_domain_set |= fetched_lists.get(inc, set())
        for exc in policy.get("exclude", []): policy_domain_set -= fetched_lists.get(exc, set())
        sync_to_cloudflare(cf, optimize_domains(policy_domain_set), policy)

    logger.info(f"Total time: {time.perf_counter() - start:.2f} seconds.")

if __name__ == "__main__":
    main()
