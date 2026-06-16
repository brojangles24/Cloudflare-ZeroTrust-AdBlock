import os
import re
import logging
import requests
import concurrent.futures
import time
import hashlib
import io
import zipfile
import gzip
import sys
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ---------------------------------------------------------------------------
# 1. Config & Lists
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN               = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID              = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL           = os.environ.get("PRIMARY_EMAIL", "")   
    SECONDARY_EMAIL         = os.environ.get("SECONDARY_EMAIL", "")  
    TERTIARY_EMAIL          = os.environ.get("TERTIARY_EMAIL", "")
    
    # --- TOGGLES ---
    ENABLE_RELEVANCE_FILTER = False
    ENABLE_TIF_FULL         = False
    
    MAX_LIST_SIZE           = 1000  # Optimized to Cloudflare Max Batch Limit
    MAX_RETRIES             = 5
    TOTAL_QUOTA             = 300_000
    REQUEST_TIMEOUT         = (5, 25)
    MAX_WORKERS             = 5

    # Targets to scrub orphaned rules/lists
    SCRUB_TARGETS = [
        "Base", "Pro++", "Ultimate", "Normal", "Social", 
        "Block:", "Allow:", "L_", "ProMini", "ProPlus", 
        "ProUser", "ProHome", "Piracy", "DynDNS", "Hoster", "Restrictive"
    ]

    @classmethod
    def validate(cls):
        required_vars = ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL")
        missing = [k for k in required_vars if not getattr(cls, k)]
        if missing:
            raise EnvironmentError(f"Missing mandatory environment variables: {', '.join(missing)}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|"
    r"^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|"
    r"^(?:[A-Fa-f0-9]{1,4}:)*:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*$"
)

BLOCKLIST_URLS = {
    "HaGeZi Normal": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
    ],
    "HaGeZi Pro++": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus.mini-onlydomains.txt",
    "Hagezi NSFW": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",  
        #"https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    ],
    "HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "HaGeZi TIF Full": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
    "HaGeZi Social": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
    "HaGeZi No SafeSearch": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
    "HaGeZi Bypass Prevention": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "HaGeZi Anti Piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
    "HaGeZi DynDNS": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
}

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

excluded_emails = [e for e in [Config.SECONDARY_EMAIL, Config.TERTIARY_EMAIL] if e]
if excluded_emails:
    emails_cond = " or ".join([f'identity.email == "{e}"' for e in excluded_emails])
    TARGET_IDENTITY = f"not ({emails_cond})"
else:
    TARGET_IDENTITY = None

POLICIES = [
    {
        "prefix": "L_Relaxed", 
        "policy_name": "Block: Relaxed Profile", 
        "action": "block", 
        "identity_condition": None, 
        "category_condition": "any(dns.security_category[*] in {178 80 187 83 176 175 117 131 134 153}) or any(dns.content_category[*] in {133})",
        "include": ["HaGeZi Normal"], 
        "exclude": []
    },
    {
        "prefix": "L_Restrictive", 
        "policy_name": "Block: Restrictive Profile", 
        "action": "block", 
        "identity_condition": TARGET_IDENTITY, 
        "category_condition": "any(dns.security_category[*] in {151 191 188 68}) or any(dns.content_category[*] in {67 125})",
        "include": [
            "HaGeZi Pro++", 
            "HaGeZi Bypass Prevention", 
            "HaGeZi Social", 
            "Hagezi NSFW", 
            "HaGeZi Fake", 
            "HaGeZi No SafeSearch", 
            "HaGeZi Anti Piracy", 
            "HaGeZi DynDNS"
        ], 
        "exclude": ["HaGeZi Normal"]
    }
]

if Config.ENABLE_TIF_FULL:
    POLICIES[1]["include"].append("HaGeZi TIF Full")

# ---------------------------------------------------------------------------
# 2. Cloudflare API Client
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        retry = Retry(total=Config.MAX_RETRIES, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(pool_connections=Config.MAX_WORKERS, pool_maxsize=Config.MAX_WORKERS + 2, max_retries=retry)
        self.session.mount("https://", adapter)

    def _request(self, method, endpoint, **kwargs):
        retries = Config.MAX_RETRIES
        delay = 2
        resp = None
        while retries > 0:
            try:
                resp = self.session.request(method, f"{self.base_url}/{endpoint}", headers=self.headers, timeout=Config.REQUEST_TIMEOUT, **kwargs)
                
                if resp.status_code in [429, 500, 502, 503, 504]:
                    retries -= 1
                    logger.warning(f"Transient API Error ({resp.status_code}) on {endpoint}. Retrying in {delay}s... ({retries} left)")
                    time.sleep(delay)
                    delay *= 2 
                    continue
                    
                if not resp.ok:
                    logger.error(f"Cloudflare API Error [{resp.status_code}]: {resp.text}")
                resp.raise_for_status()
                return resp.json()
                
            except requests.exceptions.RequestException as exc:
                retries -= 1
                if retries == 0:
                    raise exc
                logger.warning(f"Network error/timeout on {endpoint}: {exc}. Retrying in {delay}s... ({retries} left)")
                time.sleep(delay)
                delay *= 2

        raise requests.exceptions.HTTPError("Exhausted retries due to persistent Cloudflare API dropouts.", response=resp)

    def _get_paginated(self, endpoint):
        results, page = [], 1
        while True:
            resp = self._request("GET", f"{endpoint}?page={page}&per_page=100")
            data = resp.get("result") or []
            results.extend(data)
            info = resp.get("result_info")
            if not info or page >= info.get("total_pages", 1): break
            page += 1
        return results

    def get_lists(self):                                      return self._get_paginated("lists")
    def get_rules(self):                                      return self._get_paginated("rules")
    def delete_list(self, lid):                               return self._request("DELETE", f"lists/{lid}")
    def delete_rule(self, rid):                               return self._request("DELETE", f"rules/{rid}")
    def create_list(self, name, items, desc=""):              return self._request("POST",   "lists",         json={"name": name, "type": "DOMAIN", "items": items, "description": desc})
    def update_list(self, lid, name, items, desc=""):         return self._request("PUT",    f"lists/{lid}",  json={"name": name, "items": items, "description": desc})
    def create_rule(self, data):                              return self._request("POST",   "rules",         json=data)
    def update_rule(self, rid, data):                         return self._request("PUT",    f"rules/{rid}",  json=data)

# ---------------------------------------------------------------------------
# 3. Relevance Filtering & Domain Logic
# ---------------------------------------------------------------------------
TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
    ("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://builtwith.com/dl/builtwith-top1m.zip", 0, False, "zip"),
]

def has_suffix_match(host: str, lookup_set: set[str]) -> bool:
    if host in lookup_set: return True
    parts = host.split('.')
    for i in range(1, len(parts)):
        if '.'.join(parts[i:]) in lookup_set: return True
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

def fetch_top_list(url: str, col_idx: int, skip_header: bool, compression: str, session: requests.Session) -> set[str]:
    try:
        r = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=90)
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
        logger.critical(f"Critical failure fetching top list {url}: {e}", exc_info=True)
        sys.exit(1)

class RelevanceChecker:
    def __init__(self, session: requests.Session):
        self.master_allowlist: set[str] = set()
        self.session = session

    def build_dataset(self, max_workers: int = 5) -> None:
        logger.info(f"Building relevance dataset using {max_workers} threads...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(fetch_top_list, url, col, skip, comp, self.session) for url, col, skip, comp in TOP_LISTS]
            for future in concurrent.futures.as_completed(futures):
                self.master_allowlist.update(future.result())
        logger.info(f"Relevance dataset built. Total unique root domains: {len(self.master_allowlist):,}")

    def is_relevant(self, domain: str) -> bool:
        clean_domain = domain.lower().strip('.')
        if clean_domain.startswith("www."): clean_domain = clean_domain[4:]
        return has_suffix_match(clean_domain, self.master_allowlist)

def is_valid_domain(domain: str) -> str | None:
    domain = domain.strip().strip(".")
    if not domain or any(c in domain for c in "*/[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None
    return domain

def fetch_url(session: requests.Session, name: str, url: str | list[str], checker: RelevanceChecker = None):
    kept_domains = set()
    total_irrelevant_count = 0
    
    urls_to_process = [url] if isinstance(url, str) else url

    for target_url in urls_to_process:
        try:
            resp = session.get(target_url, timeout=Config.REQUEST_TIMEOUT)
            resp.raise_for_status()
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line[0] in ("#", "!", "/"): continue
                cleaned = is_valid_domain(line.split()[-1].lower())
                if cleaned: 
                    if checker and not checker.is_relevant(cleaned): 
                        total_irrelevant_count += 1
                    else: 
                        kept_domains.add(cleaned)
        except Exception as exc:
            logger.error(f"Error fetching submodule in {name} ({target_url}): {exc}")
            raise exc
            
    logger.info(f"Fetched {name}: {len(kept_domains):,} kept (Pruned via relevance: {total_irrelevant_count:,})")
    return name, kept_domains, total_irrelevant_count

def fetch_raw_tlds(session: requests.Session) -> list[str]:
    logger.info("Fetching target Spam TLD source dataset...")
    tlds = []
    try:
        resp = session.get(SPAM_TLD_URL, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip().lower()
            if not line or line.startswith(("#", "!", "/")): continue
            clean_tld = line.split()[-1].strip(".")
            if clean_tld and "." not in clean_tld and "*" not in clean_tld:
                tlds.append(clean_tld)
        logger.info(f"Compiled {len(tlds):,} raw target entries from TLD blocklist.")
        return sorted(list(set(tlds)))
    except Exception as exc:
        logger.error(f"Failed to fetch baseline TLD requirements: {exc}")
        return []

def build_cloudflare_tld_expression(tlds: list[str], chunk_size: int = 35) -> str:
    if not tlds: return ""
    chunks = [tlds[i:i + chunk_size] for i in range(0, len(tlds), chunk_size)]
    expr_blocks = [f'any(dns.domains[*] matches "(?i)\\\\.(?:{"|".join(chunk)})$")' for chunk in chunks]
    return " or ".join(expr_blocks)

def optimize_domains(domains: set[str]) -> list[str]:
    sorted_domains = sorted(domains, key=lambda d: d.split('.')[::-1])
    optimized, last_kept = [], None
    for dom in sorted_domains:
        if last_kept and dom.endswith("." + last_kept): continue
        optimized.append(dom)
        last_kept = dom
    return optimized

def build_policy_sets(policies_config, fetched_lists):
    sets = []
    base_household_set = fetched_lists.get("HaGeZi Normal", set())

    for policy in policies_config:
        p_set = set()
        
        for inc in policy.get("include", []):
            if inc in fetched_lists:
                p_set |= fetched_lists[inc]
                
        for exc in policy.get("exclude", []):
            if exc in fetched_lists:
                p_set -= fetched_lists[exc]
        
        if policy["prefix"] != "L_Normal" and "HaGeZi Normal" not in policy.get("exclude", []) and base_household_set:
            p_set = {dom for dom in p_set if not has_suffix_match(dom, base_household_set)}

        sets.append((policy, optimize_domains(p_set)))
    return sets

# ---------------------------------------------------------------------------
# 4. Cloudflare Sync & Cleanup
# ---------------------------------------------------------------------------
def sync_to_cloudflare(cf: CloudflareAPI, existing_lists: list[dict], existing_rules: list[dict], domains: list[str], policy: dict, raw_tld_expr: str = "") -> tuple[list[str], list[str]]:
    if not domains and not raw_tld_expr and not policy.get("category_condition"): return [], []
    
    used_ids = []
    if domains:
        sorted_domains = sorted(domains)
        chunks = [sorted_domains[i : i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
        policy_existing_lists = sorted([l for l in existing_lists if l["name"].startswith(policy["prefix"] + " ")], key=lambda x: x["name"])
        
        def process_chunk(idx: int, chunk: list[str]) -> str:
            list_name = f"{policy['prefix']} {idx + 1:03d}"
            chunk_hash = hashlib.sha256(",".join(chunk).encode('utf-8')).hexdigest()
            items = [{"value": d} for d in chunk]
            
            if idx < len(policy_existing_lists):
                existing = policy_existing_lists[idx]
                if existing.get("description") == chunk_hash: return existing["id"]
                cf.update_list(existing["id"], list_name, items, desc=chunk_hash)
                logger.info(f"Updated list {list_name} ({len(chunk):,} domains)")
                return existing["id"]
            else:
                res = cf.create_list(list_name, items, desc=chunk_hash)
                logger.info(f"Created list {list_name} ({len(chunk):,} domains)")
                return res["result"]["id"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = [executor.submit(process_chunk, idx, chunk) for idx, chunk in enumerate(chunks)]
            used_ids = [f.result() for f in futures]

    list_items = [f"any(dns.domains[*] in ${lid})" for lid in used_ids]
    
    if raw_tld_expr:
        list_items.append(f"({raw_tld_expr})")
        
    cat_expr = policy.get("category_condition")
    if cat_expr:
        list_items.append(f"({cat_expr})")

    traffic_expr, identity_expr = "", ""
    cond = policy.get("identity_condition")

    if cond:
        if "dns." not in cond:
            identity_expr = cond
            traffic_expr = " or ".join(list_items)
        else:
            traffic_expr = " or ".join([f"({cond} and {item})" for item in list_items])
    else:
        traffic_expr = " or ".join(list_items)

    final_rule_name = policy['policy_name']
    action = policy.get("action", "block")
    existing_rule = next((r for r in existing_rules if r["name"] == final_rule_name), None)
    is_enabled = existing_rule.get("enabled", True) if existing_rule else True

    payload = {"name": final_rule_name, "action": action, "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
    if identity_expr: payload["identity"] = identity_expr
    
    if existing_rule:
        if existing_rule.get("traffic", "") == traffic_expr and existing_rule.get("identity", "") == identity_expr:
            logger.info(f"Firewall rule {final_rule_name} unchanged. Skipping.")
        else:
            cf.update_rule(existing_rule["id"], payload)
            logger.info(f"Firewall rule updated: {final_rule_name}")
    else: 
        cf.create_rule(payload)
        logger.info(f"Firewall rule created: {final_rule_name}")
            
    return used_ids, [final_rule_name]

def cleanup_orphans(cf: CloudflareAPI, existing_lists: list[dict], existing_rules: list[dict], active_list_ids: list[str], active_rule_names: list[str]):
    logger.info("Running post-sync cleanup of orphaned resources...")
    for r in existing_rules:
        if any(kw in r["name"] for kw in ["IoT Bypass", "Custom", "Keywords"]): continue
        if r["name"] not in active_rule_names and any(target in r["name"] for target in Config.SCRUB_TARGETS):
            try:
                cf.delete_rule(r["id"])
                logger.info(f"Deleted Orphaned Rule: {r['name']}")
            except Exception as e: logger.error(f"Could not delete rule {r['name']}: {e}")

    for l in existing_lists:
        if "IoT Bypass" in l["name"]: continue
        if l["id"] not in active_list_ids and any(target in l["name"] for target in Config.SCRUB_TARGETS):
            try:
                cf.delete_list(l["id"])
                logger.info(f"Deleted Orphaned List: {l['name']}")
            except Exception as e: logger.error(f"Could not delete list {l['name']}: {e}")

# ---------------------------------------------------------------------------
# 5. Main Execution
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    active_blocklist_urls = BLOCKLIST_URLS
    active_policies = POLICIES
    
    download_session = requests.Session()
    dl_retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    download_session.mount("https://", HTTPAdapter(pool_connections=Config.MAX_WORKERS, pool_maxsize=Config.MAX_WORKERS + 2, max_retries=dl_retry))

    if Config.ENABLE_RELEVANCE_FILTER:
        checker = RelevanceChecker(download_session)
        checker.build_dataset(max_workers=Config.MAX_WORKERS)
    else:
        logger.info("Relevance filter disabled via config. Skipping dataset build.")
        checker = None

    tld_raw_list = fetch_raw_tlds(download_session)
    tld_regex_expression = build_cloudflare_tld_expression(tld_raw_list)

    fetched_lists = {}
    total_irrelevant_pruned = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_url, download_session, name, url, checker): name for name, url in active_blocklist_urls.items()}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                name, kept_set, irrelevant_count = future.result()
                fetched_lists[name] = kept_set
                total_irrelevant_pruned += irrelevant_count
            except Exception as e:
                if name == "HaGeZi Normal":
                    logger.critical("Primary structural baseline compilation failure (HaGeZi Normal). Halting pipeline execution.", exc_info=True)
                    return
                logger.warning(f"Non-critical list source offline: {name}. Error context: {e}")

    compiled_policies = build_policy_sets(active_policies, fetched_lists)
    total_domains = sum(len(domains) for _, domains in compiled_policies)

    if total_domains > Config.TOTAL_QUOTA:
        logger.error(f"Total compiled payload matrix size ({total_domains:,}) exceeds infrastructure limits. Execution halted.")
        return

    logger.info(f"Domains pruned via Relevance Filter: {total_irrelevant_pruned:,}")
    logger.info(f"Target payload footprint to sync: {total_domains:,} elements.")

    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()

    valid_prefixes = tuple(p["prefix"] for p in active_policies)
    valid_rule_bases = {p["policy_name"] for p in active_policies}

    for rule in existing_rules[:]:
        if any(kw in rule["name"] for kw in ["IoT Bypass", "Custom", "Keywords"]): continue
        if fasteners := any(target in rule["name"] for target in Config.SCRUB_TARGETS):
            if not any(rule["name"].startswith(base) for base in valid_rule_bases):
                try:
                    cf.delete_rule(rule["id"])
                    existing_rules.remove(rule)
                    logger.info(f"Purged deprecated baseline rule: {rule['name']}")
                except Exception as e: logger.error(f"Rule cleanup intercept drop: {e}")

    for lst in existing_lists[:]:
        if "IoT Bypass" in lst["name"]: continue
        if any(target in lst["name"] for target in Config.SCRUB_TARGETS):
            if not any(lst["name"].startswith(pfx + " ") for pfx in valid_prefixes):
                try:
                    cf.delete_list(lst["id"])
                    existing_lists.remove(lst)
                    logger.info(f"Purged deprecated baseline table array: {lst['name']}")
                except Exception as e: logger.error(f"Table array footprint cleanup intercept drop: {e}")

    all_active_list_ids, all_active_rule_names = [], []

    for policy, optimized_domains in compiled_policies:
        tld_expr = tld_regex_expression if policy["prefix"] == "L_Restrictive" else ""
        used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_domains, policy, raw_tld_expr=tld_expr)
        all_active_list_ids.extend(used_ids)
        all_active_rule_names.extend(rule_names)

    # --- AGGREGATE BLOCKLIST EXPORT FOR GITHUB ---
    logger.info("Compiling absolute master aggregate blocklist payload...")
    aggregate_master_set = set()
    for _, domains in compiled_policies:
        aggregate_master_set.update(domains)
        
    try:
        with open("aggregate_blocklist.txt", "w", encoding="utf-8") as f:
            for domain in sorted(list(aggregate_master_set)):
                f.write(f"{domain}\n")
        logger.info(f"Successfully dumped {len(aggregate_master_set):,} total consolidated entries to aggregate_blocklist.txt")
    except Exception as e:
        logger.error(f"Failed writing target aggregate blocklist dump matrix: {e}")

    cleanup_orphans(cf, existing_lists, existing_rules, all_active_list_ids, all_active_rule_names)

    logger.info(f"Sync complete. Network timeline iteration: {time.perf_counter() - start:.2f} seconds.")

if __name__ == "__main__":
    main()
