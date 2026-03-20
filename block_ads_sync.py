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
    ENABLE_TLD_KW_FILTERING = True
    ENABLE_RELEVANCE_FILTER = True   # <--- Keep only active/popular domains
    
    MAX_LIST_SIZE           = 1000
    MAX_RETRIES             = 3
    TOTAL_QUOTA             = 300_000
    REQUEST_TIMEOUT         = (5, 25)
    MAX_WORKERS             = 5

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

# Relevance Datasets
TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
]

MASTER_CONFIG = {
    "name":           "Ads, Tracker, Telemetry, Malware",
    "prefix":         "Ads, Tracker, Telemetry, Malware",
    "policy_name":    "Ads, Tracker, Telemetry, Malware",
    "filename":       "aggregate_blocklist.txt",
    "banned_tlds": {
        "tk", "ml", "ga", "cf", "gq", "icu", "top", "xin", "gdn", "bid", "pw", "sbs", 
        "cfd", "monster", "stream", "webcam", "download", "win", "party", "racing", 
        "trade", "loan", "faith", "review", "accountant", "accountants", "cricket",
        "zip", "mov", "xxx", "casino",
    },
    "offloaded_keywords": {
        "blowjob", "threesome", "gangbang", "handjob", "deepthroat", 
        "bukkake", "titfuck", "shemale", 
        "pornhub", "redtube", "brazzers", "xnxx", "xvideo", "xxvideo", "omegle",
    },
    "urls": {
        # --- THE CORE FOUR (Broad Protection) ---
        "HaGeZi Normal":                  "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
        "1Hosts Lite":                    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
        #"OISD Big":                       "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_big.txt",
        "Hagezi TIF Mini":                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",

        # --- SPECIALTY & SAFETY ---
        "Hagezi NSFW":                    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
        "OISD NSFW":                      "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/domainswild2_nsfw.txt",
        "HaGeZi Fake":                    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
        
        # --- NATIVE TRACKERS (Device Specific) ---
        "Amazon":                         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.amazon.txt",
        "TikTok":                         "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.tiktok.txt",
        "Windows":                        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.winoffice.txt",
        "Apple":                          "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/domains/native.apple.txt",
    },
}

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
        resp.raise_for_status()
        return resp.json()

    def get_lists(self):                      return self._request("GET",    "lists").get("result") or []
    def get_rules(self):                      return self._request("GET",    "rules").get("result") or []
    def create_list(self, name, items):       return self._request("POST",   "lists",          json={"name": name, "type": "DOMAIN", "items": items})
    def update_list(self, lid, name, items):  return self._request("PUT",    f"lists/{lid}",   json={"name": name, "items": items})
    def delete_list(self, lid):               return self._request("DELETE", f"lists/{lid}")
    def create_rule(self, data):              return self._request("POST",   "rules",          json=data)
    def update_rule(self, rid, data):         return self._request("PUT",    f"rules/{rid}",   json=data)

# ---------------------------------------------------------------------------
# 3. Domain Processing & Relevance
# ---------------------------------------------------------------------------
_BANNED_TLDS  = MASTER_CONFIG["banned_tlds"]
_OFFLOAD_KW   = MASTER_CONFIG["offloaded_keywords"]
_BAD_CHARS    = frozenset("*/:[]")

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

    if not domain or _BAD_CHARS.intersection(domain):
        return None

    if "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None

    if Config.ENABLE_TLD_KW_FILTERING:
        tld = domain.rsplit(".", 1)[-1]
        if tld in _BANNED_TLDS: return None
        if any(kw in domain for kw in _OFFLOAD_KW): return None

    # Relevance check: If enabled, domain MUST exist in the top lists
    if Config.ENABLE_RELEVANCE_FILTER and top_domains:
        if not has_suffix_match(domain, top_domains):
            return None

    return domain

def fetch_url(name: str, url: str, top_domains: set[str]) -> tuple[str, set[str]]:
    logger.info(f"Fetching Blocklist: {name}")
    valid_domains: set[str] = set()

    try:
        resp = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"):
                continue
            
            cleaned = is_valid_domain(line.split()[-1].lower(), top_domains)
            if cleaned:
                valid_domains.add(cleaned)
                
        logger.info(f"Done: {name} — {len(valid_domains):,} valid domains")
    except Exception as exc:
        logger.error(f"Error fetching {name}: {exc}")

    return name, valid_domains

def optimize_domains(domains: set[str]) -> list[str]:
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized: list[str] = []
    last_kept: str | None = None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."):
            continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]

# ---------------------------------------------------------------------------
# 4. Cloudflare Sync
# ---------------------------------------------------------------------------
def sync_to_cloudflare(cf: CloudflareAPI, domains: list[str]) -> None:
    if not domains:
        logger.error("Optimised list is empty — aborting sync.")
        return

    if len(domains) > Config.TOTAL_QUOTA:
        logger.warning(f"Quota exceeded — slicing to {Config.TOTAL_QUOTA:,}")
        domains = domains[: Config.TOTAL_QUOTA]

    sorted_domains = sorted(domains)
    chunks = [sorted_domains[i : i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]

    Path(MASTER_CONFIG["filename"]).write_text("\n".join(sorted_domains))

    existing = sorted([l for l in cf.get_lists() if MASTER_CONFIG["prefix"] in l["name"]], key=lambda x: x["name"])
    used_ids: list[str] = []

    for idx, chunk in enumerate(chunks):
        items = [{"value": d} for d in chunk]
        list_name = f"{MASTER_CONFIG['prefix']} {idx + 1:03d}"
        
        if idx < len(existing):
            lid = existing[idx]["id"]
            cf.update_list(lid, list_name, items)
            used_ids.append(lid)
            logger.info(f"Updated list {list_name} ({len(chunk):,} domains)")
        else:
            res = cf.create_list(list_name, items)
            lid = res["result"]["id"]
            used_ids.append(lid)
            logger.info(f"Created list {list_name} ({len(chunk):,} domains)")

    clauses = [f"any(dns.domains[*] in ${lid})" for lid in used_ids]
    payload = {
        "name":    MASTER_CONFIG["policy_name"],
        "action":  "block",
        "enabled": True,
        "filters": ["dns"],
        "traffic": " or ".join(clauses),
    }
    
    rules = cf.get_rules()
    rid = next((r["id"] for r in rules if r["name"] == MASTER_CONFIG["policy_name"]), None)
    
    if rid:
        cf.update_rule(rid, payload)
        logger.info("Firewall rule updated.")
    else:
        cf.create_rule(payload)
        logger.info("Firewall rule created.")

    for stale in existing[len(chunks):]:
        try:
            cf.delete_list(stale["id"])
            logger.info(f"Deleted stale list: {stale['name']} ({stale['id']})")
        except Exception as exc:
            logger.error(f"Failed to delete stale list {stale['id']}: {exc}")

# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    global_top_domains: set[str] = set()
    global_domain_set: set[str]  = set()

    # Step 1: Pre-fetch Top Relevance Lists (If Enabled)
    if Config.ENABLE_RELEVANCE_FILTER:
        logger.info("Relevance Filter Enabled. Fetching global top internet domains...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            top_futures = [
                pool.submit(fetch_top_list, url, col, skip, comp)
                for url, col, skip, comp in TOP_LISTS
            ]
            for future in concurrent.futures.as_completed(top_futures):
                global_top_domains |= future.result()
        logger.info(f"Compiled {len(global_top_domains):,} root domains into the Relevance Allowlist.")

    # Step 2: Fetch and Filter Blocklists
    logger.info("Fetching DNS Blocklists...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {
            pool.submit(fetch_url, name, url, global_top_domains): name
            for name, url in MASTER_CONFIG["urls"].items()
        }
        for future in concurrent.futures.as_completed(futures):
            _, valid_set = future.result()
            global_domain_set |= valid_set

    logger.info(f"Total domains after relevance & validation: {len(global_domain_set):,}")

    # Step 3: Optimize (Tree Pruning)
    optimized = optimize_domains(global_domain_set)
    logger.info(f"Total domains after tree-pruning: {len(optimized):,}")

    # Step 4: Cloudflare Sync
    sync_to_cloudflare(cf, optimized)

    logger.info(f"Sync complete in {time.perf_counter() - start:.2f} seconds.")

if __name__ == "__main__":
    main()
