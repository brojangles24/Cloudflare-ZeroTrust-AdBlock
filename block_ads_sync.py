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

# Global variables for the dynamically compiled filters
TLD_SET = set()
KW_PATTERN = None

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
    ENABLE_TLD_KW_FILTERING = False
    ENABLE_TIF_FULL         = True 
    
    # Static custom explicit keywords used to drop matching domains locally
    OFFLOAD_KEYWORDS = [
        "blowjob", "threesome", "gangbang", "deepthroat", "bukkake", 
        "tits", "fuck", "onlyfans", "porn", "xxx", "sex",
    ]
    
    MAX_LIST_SIZE           = 10000  # Optimized to Cloudflare Max Batch Limit
    MAX_RETRIES              = 5
    TOTAL_QUOTA              = 300_000
    REQUEST_TIMEOUT          = (5, 25)
    MAX_WORKERS              = 5

    # Targets to scrub orphaned rules/lists
    SCRUB_TARGETS = [
        "Base", 
        "Pro++", 
        "Ultimate",
        "Normal",
        "Social",
        "Block:",
        "Allow:",
        "L_",
        "ProMini",
        "ProPlus",
        "ProUser",
        "ProHome"
    ]

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL", "SECONDARY_EMAIL", "TERTIARY_EMAIL") if not getattr(cls, k)]
        if missing:
            raise EnvironmentError(f"Missing environment variables: {', '.join(missing)}")

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

ADGUARD_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

BLOCKLIST_URLS = {
    "HaGeZi Normal": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
    "HaGeZi Pro++": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
    "Hagezi NSFW": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
    "HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "HaGeZi TIF Full": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
    "HaGeZi Social": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
    "HaGeZi No SafeSearch": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
    "HaGeZi Bypass Prevention": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
}

excluded_emails = [e for e in [Config.SECONDARY_EMAIL, Config.TERTIARY_EMAIL] if e]

if excluded_emails:
    emails_cond = " or ".join([f'identity.email == "{e}"' for e in excluded_emails])
    TARGET_IDENTITY = f'not ({emails_cond})'
else:
    TARGET_IDENTITY = None

OFFLOAD_TARGETS = [
    {"suffix": "", "traffic_cond": None, "identity_cond": TARGET_IDENTITY}
]

POLICIES = [
    {"prefix": "L_Normal", "policy_name": "Block: HaGeZi Normal (Household Base)", "action": "block", "identity_condition": None, "apply_offload": False, "include": ["HaGeZi Normal"], "exclude": []},
    {"prefix": "L_ProPlus", "policy_name": "Block: HaGeZi Pro++", "action": "block", "identity_condition": TARGET_IDENTITY, "apply_offload": True, "include": ["HaGeZi Pro++"], "exclude": ["HaGeZi Normal"]},
    {"prefix": "L_Bypass", "policy_name": "Block: HaGeZi Bypass Prevention", "action": "block", "identity_condition": TARGET_IDENTITY, "apply_offload": True, "include": ["HaGeZi Bypass Prevention"], "exclude": []},
    {"prefix": "L_Social", "policy_name": "Block: HaGeZi Social", "action": "block", "identity_condition": TARGET_IDENTITY, "apply_offload": True, "include": ["HaGeZi Social"], "exclude": []},
    {"prefix": "L_NSFW", "policy_name": "Block: HaGeZi NSFW", "action": "block", "identity_condition": None, "apply_offload": False, "include": ["Hagezi NSFW"], "exclude": []},
    {"prefix": "L_Fake", "policy_name": "Block: HaGeZi Fake", "action": "block", "identity_condition": None, "apply_offload": False, "include": ["HaGeZi Fake"], "exclude": []},
    {"prefix": "L_NoSafeSearch", "policy_name": "Block: HaGeZi No SafeSearch", "action": "block", "identity_condition": None, "apply_offload": False, "include": ["HaGeZi No SafeSearch"], "exclude": []},
]

if Config.ENABLE_TIF_FULL:
    POLICIES.append({"prefix": "L_TIF", "policy_name": "Block: HaGeZi TIF Full", "action": "block", "identity_condition": None, "apply_offload": False, "include": ["HaGeZi TIF Full"], "exclude": []})

# ---------------------------------------------------------------------------
# 2. Cloudflare API Client
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        retry = Retry(total=Config.MAX_RETRIES, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(pool_connections=Config.MAX_WORKERS, pool_maxsize=Config.MAX_WORKERS, max_retries=retry)
        self.session.mount("https://", adapter)

    def _request(self, method, endpoint, **kwargs):
        retries = Config.MAX_RETRIES
        delay = 2
        while retries > 0:
            resp = self.session.request(method, f"{self.base_url}/{endpoint}", headers=self.headers, timeout=Config.REQUEST_TIMEOUT, **kwargs)
            if resp.status_code == 429:
                retries -= 1
                logger.warning(f"Rate limited (429) on {endpoint}. Retrying in {delay}s... ({retries} left)")
                time.sleep(delay)
                delay *= 2 
                continue
            if not resp.ok:
                logger.error(f"Cloudflare API Error [{resp.status_code}]: {resp.text}")
            resp.raise_for_status()
            return resp.json()
        raise requests.exceptions.HTTPError("Exhausted retries due to Cloudflare API rate limits (429).", response=resp)

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
    def update_list(self, lid, name, items, desc=""):          return self._request("PUT",    f"lists/{lid}",  json={"name": name, "items": items, "description": desc})
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
        logger.critical(f"Critical failure fetching top list {url}: {e}")
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

def parse_adguard_tld_list(session: requests.Session) -> tuple[list[str], set[str]]:
    allowed_domains, tlds = set(), []
    try:
        resp = session.get(ADGUARD_TLD_URL, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith(("!", "#", "[")): continue
            if line.startswith("||"):
                parts = line.split("^$denyallow=")
                raw_tld = parts[0].replace("||", "").replace("*.", "").replace("^", "")
                if raw_tld: tlds.append(raw_tld)
                if len(parts) > 1:
                    for dom in parts[1].split("|"):
                        dom_cleaned = dom.strip().lower()
                        if dom_cleaned: allowed_domains.add(dom_cleaned)
        if tlds: logger.info(f"Parsed AdGuard TLDs: {len(tlds)} TLD blocks, {len(allowed_domains)} whitelists.")
        return tlds, allowed_domains
    except Exception as exc:
        logger.error(f"Failed to parse AdGuard TLD data: {exc}")
    return [], set()

def is_valid_domain(domain: str) -> tuple[str | None, str | None]:
    domain = domain.strip().strip(".")
    if not domain or any(c in domain for c in "*/[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None, None
    if Config.ENABLE_TLD_KW_FILTERING:
        if domain.split(".")[-1] in TLD_SET: return domain, "tld"
        if KW_PATTERN and KW_PATTERN.search(domain): return domain, "kw"
    return domain, None

def fetch_url(session: requests.Session, name: str, url: str, checker: RelevanceChecker = None):
    kept_domains, tld_offloadable, kw_offloadable, irrelevant_count = set(), set(), set(), 0
    try:
        resp = session.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"): continue
            cleaned, offload_reason = is_valid_domain(line.split()[-1].lower())
            if cleaned: 
                if checker and not checker.is_relevant(cleaned): irrelevant_count += 1
                elif offload_reason == "tld": tld_offloadable.add(cleaned)
                elif offload_reason == "kw": kw_offloadable.add(cleaned)
                else: kept_domains.add(cleaned)
        logger.info(f"Fetched {name}: {len(kept_domains):,} kept (TLD Offload: {len(tld_offloadable):,}, KW: {len(kw_offloadable):,}, Pruned: {irrelevant_count:,})")
    except Exception as exc:
        logger.error(f"Error fetching {name}: {exc}")
        raise exc
    return name, kept_domains, tld_offloadable, kw_offloadable, len(tld_offloadable), len(kw_offloadable), irrelevant_count

def optimize_domains(domains: set[str]) -> list[str]:
    """
    Optimizes domain structures cleanly removing deeper subdomains.
    Leverages clean component segments instead of basic tail-end checks.
    """
    sorted_domains = sorted(domains, key=lambda d: d.split('.')[::-1])
    optimized = []
    last_kept_parts = None

    for dom in sorted_domains:
        current_parts = dom.split('.')
        if last_kept_parts and len(current_parts) > len(last_kept_parts):
            if current_parts[-len(last_kept_parts):] == last_kept_parts:
                continue
        optimized.append(dom)
        last_kept_parts = current_parts
    return optimized

def build_policy_sets(policies_config, fetched_lists):
    sets = []
    base_household_set = fetched_lists.get("HaGeZi Normal", (set(), set(), set()))[0]

    for policy in policies_config:
        p_set, re_injected_count = set(), 0
        apply_offload = policy.get("apply_offload", False)
        
        for inc in policy.get("include", []):
            kept, tld_off, kw_off = fetched_lists.get(inc, (set(), set(), set()))
            p_set |= kept
            if not apply_offload:
                p_set |= tld_off
                p_set |= kw_off
                re_injected_count += (len(tld_off) + len(kw_off))
                
        for exc in policy.get("exclude", []):
            kept, tld_off, kw_off = fetched_lists.get(exc, (set(), set(), set()))
            p_set -= kept
            if not apply_offload:
                p_set -= tld_off
                p_set -= kw_off
        
        if policy["prefix"] != "L_Normal" and "HaGeZi Normal" not in policy.get("exclude", []):
            p_set -= base_household_set

        sets.append((policy, optimize_domains(p_set)))
        if not apply_offload and re_injected_count > 0:
            logger.info(f"Policy '{policy['policy_name']}': Re-injected {re_injected_count:,} baseline paths.")
    return sets

# ---------------------------------------------------------------------------
# 4. Cloudflare Sync & Cleanup
# ---------------------------------------------------------------------------
def sync_tld_regex_rule(cf: CloudflareAPI, existing_rules: list, tlds: list[str]) -> list[str]:
    if not tlds: return []
    active_rules, base_name, chunk_size = [], "Block: HaGeZi Most Abused TLDs", 30
    tld_chunks = [tlds[i:i + chunk_size] for i in range(0, len(tlds), chunk_size)]
    expr_parts = [f'any(dns.domains[*] matches "(?i)\\.(?:{"|".join(chunk)})$")' for chunk in tld_chunks]
    base_traffic = " or ".join(expr_parts)
    
    for target in OFFLOAD_TARGETS:
        rule_name = f"{base_name} {target['suffix']}" if target['suffix'] else base_name
        active_rules.append(rule_name)
        traffic_expr = f"({target['traffic_cond']}) and ({base_traffic})" if target['traffic_cond'] else base_traffic
        existing_rule = next((r for r in existing_rules if r["name"] == rule_name), None)
        is_enabled = existing_rule.get("enabled", True) if existing_rule else True

        payload = {"name": rule_name, "action": "block", "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
        if target['identity_cond']: payload["identity"] = target['identity_cond']
            
        if existing_rule:
            if existing_rule.get("traffic", "") == traffic_expr and existing_rule.get("identity", "") == (target['identity_cond'] or ""):
                logger.info(f"Rule {rule_name} unchanged. Skipping.")
            else:
                cf.update_rule(existing_rule["id"], payload)
                logger.info(f"Rule updated: {rule_name}")
        else: 
            cf.create_rule(payload)
            logger.info(f"Rule created: {rule_name}")
    return active_rules

def sync_kw_regex_rule(cf: CloudflareAPI, existing_rules: list, keywords: list[str]) -> list[str]:
    if not keywords: return []
    active_rules, base_name, chunk_size = [], "Block: NSFW Explicit Keywords", 30
    kw_chunks = [keywords[i:i + chunk_size] for i in range(0, len(keywords), chunk_size)]
    expr_parts = [f'any(dns.domains[*] matches "(?i).*({"|".join(chunk)}).*")' for chunk in kw_chunks]
    base_traffic = " or ".join(expr_parts)
    
    for target in OFFLOAD_TARGETS:
        rule_name = f"{base_name} {target['suffix']}" if target['suffix'] else base_name
        active_rules.append(rule_name)
        traffic_expr = f"({target['traffic_cond']}) and ({base_traffic})" if target['traffic_cond'] else base_traffic
        existing_rule = next((r for r in existing_rules if r["name"] == rule_name), None)
        is_enabled = existing_rule.get("enabled", True) if existing_rule else True

        payload = {"name": rule_name, "action": "block", "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
        if target['identity_cond']: payload["identity"] = target['identity_cond']
        
        if existing_rule:
            if existing_rule.get("traffic", "") == traffic_expr and existing_rule.get("identity", "") == (target['identity_cond'] or ""):
                logger.info(f"Rule {rule_name} unchanged. Skipping.")
            else:
                cf.update_rule(existing_rule["id"], payload)
                logger.info(f"Rule updated: {rule_name}")
        else: 
            cf.create_rule(payload)
            logger.info(f"Rule created: {rule_name}")
    return active_rules

def sync_to_cloudflare(cf: CloudflareAPI, existing_lists: list[dict], existing_rules: list[dict], domains: list[str], policy: dict) -> tuple[list[str], list[str]]:
    if not domains: return [], []
    sorted_domains = sorted(domains)
    chunks = [sorted_domains[i : i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    
    policy_existing_lists = sorted([l for l in existing_lists if l["name"].startswith(policy["prefix"] + " ")], key=lambda x: x["name"])
    
    # Pre-map list data by index structural safety to remove thread-unsafe lookups
    list_mapping = {}
    for idx in range(len(chunks)):
        if idx < len(policy_existing_lists):
            list_mapping[idx] = policy_existing_lists[idx]

    def process_chunk(idx: int, chunk: list[str]) -> str:
        list_name = f"{policy['prefix']} {idx + 1:03d}"
        chunk_hash = hashlib.sha256(",".join(chunk).encode('utf-8')).hexdigest()
        items = [{"value": d} for d in chunk]
        
        if idx in list_mapping:
            existing = list_mapping[idx]
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
        used_ids = [f.result() for f in concurrent.futures.as_completed(futures)]

    list_items = [f"any(dns.domains[*] in ${lid})" for lid in used_ids]
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

def enforce_tld_rule_order(cf: CloudflareAPI):
    """
    Safely enforces precedence values directly via updates. Modifies metadata 
    directly without rule drop actions to avoid gaps in system security.
    """
    logger.info("Verifying rule precedence order...")
    rules = cf.get_rules()
    allow_rules = [r for r in rules if r["name"].startswith("Allow: HaGeZi TLD Exceptions")]
    block_rules = [r for r in rules if r["name"].startswith("Block: HaGeZi Most Abused TLDs")]
    if not allow_rules or not block_rules: return
        
    for block_rule in block_rules:
        if any(r["precedence"] >= block_rule["precedence"] for r in allow_rules):
            logger.info(f"Correcting priority for: {block_rule['name']} via direct PUT metadata shift...")
            try:
                target_precedence = min(r["precedence"] for r in allow_rules) + 10
                payload = {
                    "name": block_rule["name"], 
                    "action": block_rule["action"], 
                    "traffic": block_rule["traffic"], 
                    "enabled": block_rule.get("enabled", True), 
                    "filters": block_rule.get("filters", ["dns"]),
                    "precedence": target_precedence
                }
                if block_rule.get("identity"): payload["identity"] = block_rule["identity"]
                cf.update_rule(block_rule["id"], payload)
                logger.info(f"Updated priority metadata layout for {block_rule['name']}.")
            except Exception as e: logger.error(f"Could not update precedence configuration layers: {e}")

# ---------------------------------------------------------------------------
# 5. Main Execution
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    download_session = requests.Session()
    dl_retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    download_session.mount("https://", HTTPAdapter(pool_connections=Config.MAX_WORKERS, pool_maxsize=Config.MAX_WORKERS, max_retries=dl_retry))

    checker = RelevanceChecker(download_session)
    checker.build_dataset(max_workers=Config.MAX_WORKERS)

    tlds_list, raw_allowed_domains = [], set()
    if Config.ENABLE_TLD_KW_FILTERING:
        tlds_list, raw_allowed_domains = parse_adguard_tld_list(download_session)
    
    global TLD_SET, KW_PATTERN
    if tlds_list: TLD_SET = set(tld.lower() for tld in tlds_list)
    kw_str = "|".join(Config.OFFLOAD_KEYWORDS)
    if kw_str: KW_PATTERN = re.compile(f"(?i){kw_str}")

    fetched_lists = {}
    total_tld_offloaded = total_kw_offloaded = total_irrelevant_pruned = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_url, download_session, name, url, checker): name for name, url in BLOCKLIST_URLS.items()}
        for future in concurrent.futures.as_completed(futures):
            try:
                name, kept_set, tld_off, kw_off, tld_count, kw_count, irrelevant_count = future.result()
                fetched_lists[name] = (kept_set, tld_off, kw_off)
                total_tld_offloaded += tld_count
                total_kw_offloaded += kw_count
                total_irrelevant_pruned += irrelevant_count
            except Exception:
                logger.error("A critical blocklist compilation failure occurred. Terminating transaction.")
                return

    compiled_policies = build_policy_sets(POLICIES, fetched_lists)
    optimized_allow_domains = optimize_domains(raw_allowed_domains) if raw_allowed_domains else []
    total_domains = sum(len(domains) for _, domains in compiled_policies) + len(optimized_allow_domains)

    if total_domains > Config.TOTAL_QUOTA:
        logger.error(f"Total compiled size ({total_domains:,}) hits quota limits. Process halted.")
        return

    logger.info(f"Domains mapped to TLD rules: {total_tld_offloaded:,} | Keyword rules: {total_kw_offloaded:,}")
    logger.info(f"Domains pruned via Relevance Filter: {total_irrelevant_pruned:,}")
    logger.info(f"Target payload footprint to sync: {total_domains:,} elements.")

    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()

    # --- SMART PRE-CLEANUP ---
    valid_prefixes = tuple(p["prefix"] for p in POLICIES)
    valid_rule_bases = {p["policy_name"] for p in POLICIES}
    if Config.ENABLE_TLD_KW_FILTERING:
        valid_prefixes += ("L_AllowTLD",)
        valid_rule_bases.update(["Block: HaGeZi Most Abused TLDs", "Allow: HaGeZi TLD Exceptions", "Block: NSFW Explicit Keywords"])

    for rule in existing_rules[:]:
        if any(kw in rule["name"] for kw in ["IoT Bypass", "Custom", "Keywords"]): continue
        if any(target in rule["name"] for target in Config.SCRUB_TARGETS):
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
    # -------------------------

    all_active_list_ids, all_active_rule_names = [], []

    if Config.ENABLE_TLD_KW_FILTERING and optimized_allow_domains:
        allow_policy = {"prefix": "L_AllowTLD", "policy_name": "Allow: HaGeZi TLD Exceptions", "action": "allow", "identity_condition": TARGET_IDENTITY}
        used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_allow_domains, allow_policy)
        all_active_list_ids.extend([uid for uid in used_ids if uid not in all_active_list_ids])
        all_active_rule_names.extend(rule_names)

    if Config.ENABLE_TLD_KW_FILTERING and tlds_list:
        all_active_rule_names.extend(sync_tld_regex_rule(cf, existing_rules, tlds_list))
            
    if Config.ENABLE_TLD_KW_FILTERING and Config.OFFLOAD_KEYWORDS:
        all_active_rule_names.extend(sync_kw_regex_rule(cf, existing_rules, Config.OFFLOAD_KEYWORDS))

    for policy, optimized_domains in compiled_policies:
        used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_domains, policy)
        all_active_list_ids.extend(used_ids)
        all_active_rule_names.extend(rule_names)

    cleanup_orphans(cf, existing_lists, existing_rules, all_active_list_ids, all_active_rule_names)
    if Config.ENABLE_TLD_KW_FILTERING: enforce_tld_rule_order(cf)

    logger.info(f"Sync complete. Network timeline iteration: {time.perf_counter() - start:.2f} seconds.")

if __name__ == "__main__":
    main()
