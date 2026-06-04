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
    NULLNET_LOCATION_ID     = "5c13043a5e1342e18138dd024a98b8c9"
    
    # --- TOGGLES ---
    ENABLE_TLD_KW_FILTERING = True
    ENABLE_TIF_FULL         = True # Toggle for adding TIF Full
    
    # Static custom explicit keywords used to drop matching domains locally
    OFFLOAD_KEYWORDS = [
        "blowjob", "threesome", "gangbang", "deepthroat", "bukkake", 
        "tits", "fuck", "onlyfans", "porn", "xxx", "sex",
    ]
    
    MAX_LIST_SIZE           = 1000
    MAX_RETRIES             = 5
    TOTAL_QUOTA             = 300_000
    REQUEST_TIMEOUT         = (5, 25)
    MAX_WORKERS             = 5

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
        "ProUser",
        "ProHome"
    ]

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL", "SECONDARY_EMAIL") if not getattr(cls, k)]
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
    "HaGeZi Pro Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
    "Hagezi NSFW": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
    "HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "HaGeZi TIF Full": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
}

# ---------------------------------------------------------------------------
# Offloading Target Definitions
# Splits rules logically to satisfy Cloudflare's strict Traffic/Identity API limitations
# ---------------------------------------------------------------------------
OFFLOAD_TARGETS = [
    {"suffix": "(Roaming)", "traffic_cond": None, "identity_cond": f'identity.email == "{Config.PRIMARY_EMAIL}"'},
    {"suffix": "(Home)", "traffic_cond": f'dns.location in {{"{Config.NULLNET_LOCATION_ID}"}}', "identity_cond": None}
]

POLICIES = [
    # 1. Household Layer: Applies globally. MUST NOT offload domains, otherwise non-Pro users lose protection.
    {"prefix": "L_Normal", "policy_name": "Block: HaGeZi Normal (Household Base)", "action": "block", "identity_condition": None, "apply_offload": False, "include": ["HaGeZi Normal"], "exclude": []},
    
    # 2. Pro User Layer: Covered by the explicit TLD/KW regex rules, so offloading is TRUE.
    {"prefix": "L_ProUser", "policy_name": "Block: HaGeZi Pro Mini (Primary User Roaming)", "action": "block", "identity_condition": f'identity.email == "{Config.PRIMARY_EMAIL}"', "apply_offload": True, "include": ["HaGeZi Pro Mini"], "exclude": []},

    # 3. Pro Home Layer: Covered by the explicit TLD/KW regex rules, so offloading is TRUE.
    {"prefix": "L_ProHome", "policy_name": "Block: HaGeZi Pro Mini (Home Network Location)", "action": "block", "identity_condition": f'dns.location in {{"{Config.NULLNET_LOCATION_ID}"}}', "apply_offload": True, "include": ["HaGeZi Pro Mini"], "exclude": []},
    
    # 4. Generic Blocklists: Applies globally. MUST NOT offload.
    {"prefix": "L_NSFW", "policy_name": "Block: HaGeZi NSFW", "action": "block", "identity_condition": None, "apply_offload": False, "include": ["Hagezi NSFW"], "exclude": []},
    {"prefix": "L_Fake", "policy_name": "Block: HaGeZi Fake", "action": "block", "identity_condition": None, "apply_offload": False, "include": ["HaGeZi Fake"], "exclude": []},
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
        adapter = HTTPAdapter(
            pool_connections=Config.MAX_WORKERS, 
            pool_maxsize=Config.MAX_WORKERS,
            max_retries=retry
        )
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
        results = []
        page = 1
        while True:
            resp = self._request("GET", f"{endpoint}?page={page}&per_page=100")
            data = resp.get("result") or []
            results.extend(data)
            
            info = resp.get("result_info")
            if not info or page >= info.get("total_pages", 1):
                break
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
            futures = [
                executor.submit(fetch_top_list, url, col, skip, comp, self.session)
                for url, col, skip, comp in TOP_LISTS
            ]
            for future in concurrent.futures.as_completed(futures):
                self.master_allowlist.update(future.result())
        logger.info(f"Relevance dataset built. Total unique root domains: {len(self.master_allowlist):,}")

    def is_relevant(self, domain: str) -> bool:
        clean_domain = domain.lower().strip('.')
        if clean_domain.startswith("www."):
            clean_domain = clean_domain[4:]
        return has_suffix_match(clean_domain, self.master_allowlist)

def parse_adguard_tld_list(session: requests.Session) -> tuple[list[str], set[str]]:
    allowed_domains = set()
    tlds = []
    try:
        resp = session.get(ADGUARD_TLD_URL, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        
        for line in resp.text.splitlines():
            line = line.strip()
            # Ignore headers, brackets, and comments
            if not line or line.startswith("!") or line.startswith("#") or line.startswith("["): 
                continue
                
            if line.startswith("||"):
                parts = line.split("^$denyallow=")
                # Clean up to isolate strictly the raw string of the TLD
                raw_tld = parts[0].replace("||", "").replace("*.", "").replace("^", "")
                if raw_tld:
                    tlds.append(raw_tld)
                
                if len(parts) > 1:
                    allowed_parts = parts[1].split("|")
                    for dom in allowed_parts:
                        dom_cleaned = dom.strip().lower()
                        if dom_cleaned:
                            allowed_domains.add(dom_cleaned)
                            
        if tlds:
            logger.info(f"Parsed AdGuard TLDs: {len(tlds)} TLD blocks, extracted {len(allowed_domains)} raw whitelisted domains.")
        return tlds, allowed_domains
    except Exception as exc:
        logger.error(f"Failed to fetch or parse AdGuard TLD database: {exc}")
    return [], set()

def is_valid_domain(domain: str) -> tuple[str | None, str | None]:
    domain = domain.strip().strip(".")
    if not domain or any(c in domain for c in "*/[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None, None
    
    if Config.ENABLE_TLD_KW_FILTERING:
        tld = domain.split(".")[-1]
        if tld in TLD_SET:
            return domain, "tld"
        if KW_PATTERN and KW_PATTERN.search(domain):
            return domain, "kw"
            
    return domain, None

def fetch_url(session: requests.Session, name: str, url: str, checker: RelevanceChecker = None):
    kept_domains = set()
    tld_offloadable = set()
    kw_offloadable = set()
    all_parsed_from_list = set()
    irrelevant_count = 0
    try:
        resp = session.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"): continue
            cleaned, offload_reason = is_valid_domain(line.split()[-1].lower())
            
            if cleaned: 
                # Capture the domain BEFORE relevance pruning drops it, so we can cross-reference it against the allowlist
                all_parsed_from_list.add(cleaned)
                
                if checker and not checker.is_relevant(cleaned):
                    irrelevant_count += 1
                elif offload_reason == "tld":
                    tld_offloadable.add(cleaned)
                elif offload_reason == "kw":
                    kw_offloadable.add(cleaned)
                else:
                    kept_domains.add(cleaned)
        logger.info(f"Fetched {name}: {len(kept_domains):,} kept (Offloadable TLD: {len(tld_offloadable):,}, KW: {len(kw_offloadable):,}, Irrelevant: {irrelevant_count:,})")
    except Exception as exc:
        logger.error(f"Error fetching {name} from {url}: {exc}")
        raise exc

    return name, kept_domains, tld_offloadable, kw_offloadable, all_parsed_from_list, len(tld_offloadable), len(kw_offloadable), irrelevant_count

def optimize_domains(domains: set[str]) -> list[str]:
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized, last_kept = [], None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."): continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]

def build_policy_sets(policies_config, fetched_lists):
    sets = []
    for policy in policies_config:
        p_set = set()
        apply_offload = policy.get("apply_offload", False)
        re_injected_count = 0
        
        for inc in policy.get("include", []):
            kept, tld_off, kw_off = fetched_lists.get(inc, (set(), set(), set()))
            p_set |= kept
            # If offloading is False for this policy, we re-inject the TLD/KW domains back in.
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
                
        sets.append((policy, optimize_domains(p_set)))
        
        if not apply_offload and re_injected_count > 0:
            logger.info(f"Policy '{policy['policy_name']}': Re-injected {re_injected_count:,} domains to ensure full global coverage.")
            
    return sets

# ---------------------------------------------------------------------------
# 4. Cloudflare Sync & Cleanup
# ---------------------------------------------------------------------------
def sync_tld_regex_rule(cf: CloudflareAPI, existing_rules: list, tlds: list[str]) -> list[str]:
    if not tlds:
        return []
        
    active_rules = []
    base_name = "Block: HaGeZi Most Abused TLDs"
    chunk_size = 30
    tld_chunks = [tlds[i:i + chunk_size] for i in range(0, len(tlds), chunk_size)]
    
    expr_parts = []
    for chunk in tld_chunks:
        regex_str = "|".join(chunk)
        expr_parts.append(f'any(dns.domains[*] matches "(?i)\\.(?:{regex_str})$")')
        
    base_traffic = " or ".join(expr_parts)
    
    for target in OFFLOAD_TARGETS:
        rule_name = f"{base_name} {target['suffix']}"
        active_rules.append(rule_name)
        
        traffic_expr = base_traffic
        if target['traffic_cond']:
            traffic_expr = f"({target['traffic_cond']}) and ({base_traffic})"
            
        existing_rule = next((r for r in existing_rules if r["name"] == rule_name), None)
        is_enabled = existing_rule.get("enabled", True) if existing_rule else True

        payload = {"name": rule_name, "action": "block", "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
        if target['identity_cond']:
            payload["identity"] = target['identity_cond']
            
        if existing_rule:
            existing_traffic = existing_rule.get("traffic", "")
            existing_identity = existing_rule.get("identity", "")
            
            if existing_traffic == traffic_expr and existing_identity == (target['identity_cond'] or "") and existing_rule.get("enabled") == is_enabled:
                logger.info(f"Firewall rule {rule_name} unchanged. Skipping update.")
            else:
                cf.update_rule(existing_rule["id"], payload)
                logger.info(f"Firewall rule updated: {rule_name}")
        else: 
            cf.create_rule(payload)
            logger.info(f"Firewall rule created: {rule_name}")
            
    return active_rules

def sync_kw_regex_rule(cf: CloudflareAPI, existing_rules: list, keywords: list[str]) -> list[str]:
    if not keywords:
        return []
        
    active_rules = []
    base_name = "Block: NSFW Explicit Keywords"
    chunk_size = 30
    kw_chunks = [keywords[i:i + chunk_size] for i in range(0, len(keywords), chunk_size)]
    
    expr_parts = []
    for chunk in kw_chunks:
        kw_str = "|".join(chunk)
        expr_parts.append(f'any(dns.domains[*] matches "(?i).*({kw_str}).*")')
        
    base_traffic = " or ".join(expr_parts)
    
    for target in OFFLOAD_TARGETS:
        rule_name = f"{base_name} {target['suffix']}"
        active_rules.append(rule_name)
        
        traffic_expr = base_traffic
        if target['traffic_cond']:
            traffic_expr = f"({target['traffic_cond']}) and ({base_traffic})"
            
        existing_rule = next((r for r in existing_rules if r["name"] == rule_name), None)
        is_enabled = existing_rule.get("enabled", True) if existing_rule else True

        payload = {"name": rule_name, "action": "block", "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
        if target['identity_cond']:
            payload["identity"] = target['identity_cond']
        
        if existing_rule:
            existing_traffic = existing_rule.get("traffic", "")
            existing_identity = existing_rule.get("identity", "")
            
            if existing_traffic == traffic_expr and existing_identity == (target['identity_cond'] or "") and existing_rule.get("enabled") == is_enabled:
                logger.info(f"Firewall rule {rule_name} unchanged. Skipping update.")
            else:
                cf.update_rule(existing_rule["id"], payload)
                logger.info(f"Firewall rule updated: {rule_name}")
        else: 
            cf.create_rule(payload)
            logger.info(f"Firewall rule created: {rule_name}")
            
    return active_rules

def sync_to_cloudflare(cf: CloudflareAPI, existing_lists: list[dict], existing_rules: list[dict], domains: list[str], policy: dict) -> tuple[list[str], list[str]]:
    if not domains: return [], []
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
        used_ids = [f.result() for f in concurrent.futures.as_completed(futures)]

    list_items = [f"any(dns.domains[*] in ${lid})" for lid in used_ids]
    
    traffic_expr = ""
    identity_expr = ""

    # Intelligently route or distribute the condition
    cond = policy.get("identity_condition")
    if cond:
        if cond.startswith("identity.") and " or " not in cond and " and " not in cond:
            identity_expr = cond
            traffic_expr = " or ".join(list_items)
        else:
            # Explicitly bind complex network/identity conditions to every individual list chunk
            traffic_expr = " or ".join([f"({cond} and {item})" for item in list_items])
    else:
        traffic_expr = " or ".join(list_items)

    final_rule_name = policy['policy_name']
    active_rule_names = [final_rule_name]
    
    action = policy.get("action", "block")
    existing_rule = next((r for r in existing_rules if r["name"] == final_rule_name), None)
    is_enabled = existing_rule.get("enabled", True) if existing_rule else True

    payload = {"name": final_rule_name, "action": action, "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
    if identity_expr:
        payload["identity"] = identity_expr
    
    if existing_rule:
        existing_traffic = existing_rule.get("traffic", "")
        existing_identity = existing_rule.get("identity", "")
        
        if existing_traffic == traffic_expr and existing_identity == identity_expr and existing_rule.get("enabled") == is_enabled:
            logger.info(f"Firewall rule {final_rule_name} unchanged. Skipping update.")
        else:
            cf.update_rule(existing_rule["id"], payload)
            logger.info(f"Firewall rule updated: {final_rule_name}")
    else: 
        cf.create_rule(payload)
        logger.info(f"Firewall rule created: {final_rule_name}")
            
    return used_ids, active_rule_names

def cleanup_orphans(cf: CloudflareAPI, existing_lists: list[dict], existing_rules: list[dict], active_list_ids: list[str], active_rule_names: list[str]):
    logger.info("Running post-sync cleanup of orphaned resources...")
    for r in existing_rules:
        if "IoT Bypass" in r["name"] or "Custom" in r["name"] or "Keywords" in r["name"]: continue
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
    logger.info("Verifying rule precedence order...")
    rules = cf.get_rules()
    
    allow_rules = [r for r in rules if r["name"].startswith("Allow: HaGeZi TLD Exceptions")]
    block_rules = [r for r in rules if r["name"].startswith("Block: HaGeZi Most Abused TLDs")]
    
    if not allow_rules or not block_rules:
        return
        
    for block_rule in block_rules:
        block_prec = block_rule["precedence"]
        out_of_order = any(r["precedence"] > block_prec for r in allow_rules)
        
        if out_of_order:
            logger.info(f"Reordering: Moving {block_rule['name']} below Allow exceptions...")
            try:
                cf.delete_rule(block_rule["id"])
                
                payload = {
                    "name": block_rule["name"],
                    "action": block_rule["action"],
                    "traffic": block_rule["traffic"],
                    "enabled": block_rule.get("enabled", True),
                    "filters": block_rule.get("filters", ["dns"])
                }
                if "identity" in block_rule and block_rule.get("identity"):
                    payload["identity"] = block_rule["identity"]
                    
                cf.create_rule(payload)
                logger.info(f"Successfully fixed rule precedence for {block_rule['name']}.")
            except Exception as e:
                logger.error(f"Could not reorder rule: {e}")

# ---------------------------------------------------------------------------
# 5. Main Execution
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    download_session = requests.Session()
    dl_retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    dl_adapter = HTTPAdapter(
        pool_connections=Config.MAX_WORKERS, 
        pool_maxsize=Config.MAX_WORKERS,
        max_retries=dl_retry
    )
    download_session.mount("https://", dl_adapter)

    checker = RelevanceChecker(download_session)
    checker.build_dataset(max_workers=Config.MAX_WORKERS)

    tlds_list = []
    raw_allowed_domains = set()
    if Config.ENABLE_TLD_KW_FILTERING:
        tlds_list, raw_allowed_domains = parse_adguard_tld_list(download_session)
    
    global TLD_SET, KW_PATTERN
    if tlds_list:
        TLD_SET = set(tld.lower() for tld in tlds_list)
        
    kw_str = "|".join(Config.OFFLOAD_KEYWORDS)
    if kw_str:
        KW_PATTERN = re.compile(f"(?i){kw_str}")

    fetched_lists = {}
    total_tld_offloaded = 0
    total_kw_offloaded = 0
    total_irrelevant_pruned = 0
    
    # Store everything intended to be blocked across all lists
    all_blocklist_domains = set()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_url, download_session, name, url, checker): name for name, url in BLOCKLIST_URLS.items()}
        for future in concurrent.futures.as_completed(futures):
            try:
                name, kept_set, tld_off, kw_off, all_parsed, tld_count, kw_count, irrelevant_count = future.result()
                fetched_lists[name] = (kept_set, tld_off, kw_off)
                
                # Add everything from this blocklist to the master aggregation set
                all_blocklist_domains.update(all_parsed)
                
                total_tld_offloaded += tld_count
                total_kw_offloaded += kw_count
                total_irrelevant_pruned += irrelevant_count
            except Exception as e:
                logger.error("A critical blocklist failed to download. Aborting sync to prevent accidental rule deletion.")
                return

    # Cross-reference the TLD allowlist against the complete blocklist universe
    final_allowed_domains = raw_allowed_domains - all_blocklist_domains
    dropped_allow_count = len(raw_allowed_domains) - len(final_allowed_domains)
    
    if dropped_allow_count > 0:
        logger.info(f"Cross-referenced allowlist against blocklists: Dropped {dropped_allow_count} explicitly blocked exception domains.")

    compiled_policies = build_policy_sets(POLICIES, fetched_lists)
    optimized_allow_domains = optimize_domains(final_allowed_domains) if final_allowed_domains else []
    total_domains = sum(len(domains) for _, domains in compiled_policies) + len(optimized_allow_domains)

    if total_domains > Config.TOTAL_QUOTA:
        logger.error(f"Total domains ({total_domains:,}) exceeds quota! Aborting.")
        return

    logger.info(f"Total domains offloadable by TLD rule: {total_tld_offloaded:,}")
    logger.info(f"Total domains offloadable by Keyword rule: {total_kw_offloaded:,}")
    logger.info(f"Total domains pruned by Relevance Filter: {total_irrelevant_pruned:,}")
    logger.info(f"Total domains to sync to Cloudflare: {total_domains:,}. Proceeding...")

    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()

    # --- SMART PRE-CLEANUP ---
    valid_prefixes = tuple(p["prefix"] for p in POLICIES)
    valid_rule_bases = {p["policy_name"] for p in POLICIES}
    
    if Config.ENABLE_TLD_KW_FILTERING:
        valid_prefixes += ("L_AllowTLD",)
        valid_rule_bases.add("Block: HaGeZi Most Abused TLDs")
        valid_rule_bases.add("Allow: HaGeZi TLD Exceptions")
        valid_rule_bases.add("Block: NSFW Explicit Keywords")

    logger.info("Scanning for abandoned policies to clear room for new ones...")
    for rule in existing_rules[:]:
        if "IoT Bypass" in rule["name"] or "Custom" in rule["name"] or "Keywords" in rule["name"]: continue
        if any(target in rule["name"] for target in Config.SCRUB_TARGETS):
            is_valid_base = any(rule["name"].startswith(base) for base in valid_rule_bases)
            if not is_valid_base:
                try:
                    cf.delete_rule(rule["id"])
                    existing_rules.remove(rule)
                    logger.info(f"Pre-cleaned abandoned rule: {rule['name']}")
                except Exception as e: logger.error(f"Could not delete abandoned rule {rule['name']}: {e}")

    for lst in existing_lists[:]:
        if "IoT Bypass" in lst["name"]: continue
        if any(target in lst["name"] for target in Config.SCRUB_TARGETS):
            if not any(lst["name"].startswith(pfx + " ") for pfx in valid_prefixes):
                try:
                    cf.delete_list(lst["id"])
                    existing_lists.remove(lst)
                    logger.info(f"Pre-cleaned abandoned list: {lst['name']}")
                except Exception as e: logger.error(f"Could not delete abandoned list {lst['name']}: {e}")
    # -------------------------

    all_active_list_ids = []
    all_active_rule_names = []

    if Config.ENABLE_TLD_KW_FILTERING and optimized_allow_domains:
        # Split allow rules identical to the block rules
        allow_policies = [
            {
                "prefix": "L_AllowTLD",
                "policy_name": "Allow: HaGeZi TLD Exceptions (Roaming)",
                "action": "allow",
                "identity_condition": f'identity.email == "{Config.PRIMARY_EMAIL}"'
            },
            {
                "prefix": "L_AllowTLD",
                "policy_name": "Allow: HaGeZi TLD Exceptions (Home)",
                "action": "allow",
                "identity_condition": f'dns.location in {{"{Config.NULLNET_LOCATION_ID}"}}'
            }
        ]
        
        for ap in allow_policies:
            used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_allow_domains, ap)
            # Reusing the L_AllowTLD prefix means the list generation happens once, saving quota.
            for uid in used_ids:
                if uid not in all_active_list_ids:
                    all_active_list_ids.append(uid)
            all_active_rule_names.extend(rule_names)

    if Config.ENABLE_TLD_KW_FILTERING and tlds_list:
        tld_rule_names = sync_tld_regex_rule(cf, existing_rules, tlds_list)
        all_active_rule_names.extend(tld_rule_names)
            
    if Config.ENABLE_TLD_KW_FILTERING and Config.OFFLOAD_KEYWORDS:
        kw_rule_names = sync_kw_regex_rule(cf, existing_rules, Config.OFFLOAD_KEYWORDS)
        all_active_rule_names.extend(kw_rule_names)

    for policy, optimized_domains in compiled_policies:
        used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_domains, policy)
        all_active_list_ids.extend(used_ids)
        all_active_rule_names.extend(rule_names)

    cleanup_orphans(cf, existing_lists, existing_rules, all_active_list_ids, all_active_rule_names)
    
    if Config.ENABLE_TLD_KW_FILTERING:
        enforce_tld_rule_order(cf)

    logger.info(f"Sync completed in {time.perf_counter() - start:.2f} seconds.")

if __name__ == "__main__":
    main()
