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
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# Global variables for the dynamically compiled filters
TLD_PATTERN = None
KW_PATTERN = None
ALLOWED_DOMAINS = set()

# ---------------------------------------------------------------------------
# 1. Config & Lists
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN               = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID              = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL           = os.environ.get("PRIMARY_EMAIL", "")   
    SECONDARY_EMAIL         = os.environ.get("SECONDARY_EMAIL", "")  
    
    # --- TOGGLES ---
    ENABLE_TLD_KW_FILTERING = True
    ENABLE_TIF_MINI         = True # Toggle for adding TIF Mini
    
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
        "L_"
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

# Raw URL for HaGeZi's Most Abused TLDs AdGuard-syntax list
ADGUARD_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

BLOCKLIST_URLS = {
    "HaGeZi Normal": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/normal-onlydomains.txt",
    "HaGeZi Ultimate": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
    "Hagezi NSFW": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
    "HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "HaGeZi Safesearch Not Support": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
    "HaGeZi Bypass Block": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "HaGeZi Anti Piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt", 
    "HaGeZi Dynamic DNS": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
    "HaGeZi Social": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
    "HaGeZi TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
}

POLICIES = [
    # Normal applies to ALL users (Base layer)
    {"prefix": "L_Normal", "policy_name": "Block: HaGeZi Normal (All Users)", "action": "block", "identity_condition": None, "include": ["HaGeZi Normal"], "exclude": []},
    
    # Combined Ultimate & Social Delta (minus Normal) applies to everyone EXCEPT Secondary
    {"prefix": "L_UltSoc", "policy_name": "Block: HaGeZi Ultimate & Social (Except Secondary)", "action": "block", "identity_condition": f'not(identity.email == "{Config.SECONDARY_EMAIL}")', "include": ["HaGeZi Ultimate", "HaGeZi Social"], "exclude": ["HaGeZi Normal"]},
    
    # Generic Blocklists (Apply to all)
    {"prefix": "L_NSFW", "policy_name": "Block: HaGeZi NSFW", "action": "block", "identity_condition": None, "include": ["Hagezi NSFW"], "exclude": []},
    {"prefix": "L_Fake", "policy_name": "Block: HaGeZi Fake", "action": "block", "identity_condition": None, "include": ["HaGeZi Fake"], "exclude": []},
    {"prefix": "L_NoSafe", "policy_name": "Block: HaGeZi Safesearch Not Support", "action": "block", "identity_condition": None, "include": ["HaGeZi Safesearch Not Support"], "exclude": []},
    {"prefix": "L_Bypass", "policy_name": "Block: HaGeZi Bypass Block", "action": "block", "identity_condition": None, "include": ["HaGeZi Bypass Block"], "exclude": []},
    {"prefix": "L_AntiPiracy", "policy_name": "Block: HaGeZi Anti Piracy", "action": "block", "identity_condition": None, "include": ["HaGeZi Anti Piracy"], "exclude": []},
    {"prefix": "L_DynDNS", "policy_name": "Block: HaGeZi Dynamic DNS", "action": "block", "identity_condition": None, "include": ["HaGeZi Dynamic DNS"], "exclude": []},
]

if Config.ENABLE_TIF_MINI:
    POLICIES.append({"prefix": "L_TIF", "policy_name": "Block: HaGeZi TIF Mini", "action": "block", "identity_condition": None, "include": ["HaGeZi TIF Mini"], "exclude": []})

# ---------------------------------------------------------------------------
# 2. Cloudflare API Client
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        retry = Retry(total=Config.MAX_RETRIES, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

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

    def get_lists(self):                                      return self._request("GET",    "lists").get("result") or []
    def get_rules(self):                                      return self._request("GET",    "rules").get("result") or []
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
        logger.error(f"Error fetching top list {url}: {e}")
    return set()

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

def parse_adguard_tld_list(session: requests.Session) -> list[str]:
    """Parses AdGuard syntax to dynamically extract structural blocked TLDs and exceptions."""
    global ALLOWED_DOMAINS
    try:
        resp = session.get(ADGUARD_TLD_URL, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        
        tlds = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("!"): 
                continue
                
            if line.startswith("||*."):
                parts = line.split("^$denyallow=")
                raw_tld = parts[0].replace("||*.", "").replace("^", "")
                if raw_tld:
                    tlds.append(raw_tld)
                
                if len(parts) > 1:
                    allowed_parts = parts[1].split("|")
                    for dom in allowed_parts:
                        dom_cleaned = dom.strip().lower()
                        if dom_cleaned:
                            ALLOWED_DOMAINS.add(dom_cleaned)
                            
        if tlds:
            logger.info(f"Parsed AdGuard TLDs: {len(tlds)} TLD blocks, extracted {len(ALLOWED_DOMAINS)} whitelisted domains.")
            return tlds
    except Exception as exc:
        logger.error(f"Failed to fetch or parse AdGuard TLD database: {exc}")
    return []

def is_valid_domain(domain: str) -> tuple[str | None, str | None]:
    domain = domain.strip().strip(".")
    if not domain or any(c in domain for c in "*/[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None, None
        
    if domain in ALLOWED_DOMAINS or any(domain.endswith("." + allowed) for allowed in ALLOWED_DOMAINS):
        return domain, None
    
    if Config.ENABLE_TLD_KW_FILTERING:
        if TLD_PATTERN and TLD_PATTERN.search(domain):
            return None, "tld"
        if KW_PATTERN and KW_PATTERN.search(domain):
            return None, "kw"
            
    return domain, None

def fetch_url(session: requests.Session, name: str, url: str, checker: RelevanceChecker = None) -> tuple[str, set[str], int, int, int]:
    valid_domains = set()
    tld_offloaded_count = 0
    kw_offloaded_count = 0
    irrelevant_count = 0
    try:
        resp = session.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"): continue
            cleaned, offload_reason = is_valid_domain(line.split()[-1].lower())
            
            if cleaned: 
                # Run through Relevance Filter
                if checker and not checker.is_relevant(cleaned):
                    irrelevant_count += 1
                else:
                    valid_domains.add(cleaned)
            elif offload_reason == "tld":
                tld_offloaded_count += 1
            elif offload_reason == "kw":
                kw_offloaded_count += 1
        logger.info(f"Fetched {name}: {len(valid_domains):,} kept (Offloaded TLD: {tld_offloaded_count:,}, KW: {kw_offloaded_count:,}, Irrelevant: {irrelevant_count:,})")
    except Exception as exc:
        logger.error(f"Error fetching {name}: {exc}")
    return name, valid_domains, tld_offloaded_count, kw_offloaded_count, irrelevant_count

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
        for inc in policy.get("include", []): p_set |= fetched_lists.get(inc, set())
        for exc in policy.get("exclude", []): p_set -= fetched_lists.get(exc, set())
        sets.append((policy, optimize_domains(p_set)))
    return sets

# ---------------------------------------------------------------------------
# 4. Cloudflare Sync & Cleanup
# ---------------------------------------------------------------------------
def sync_tld_regex_rule(cf: CloudflareAPI, existing_rules: list, tlds: list[str]) -> str:
    if not tlds:
        return ""
        
    rule_name = "Block: HaGeZi Most Abused TLDs"
    chunk_size = 30
    tld_chunks = [tlds[i:i + chunk_size] for i in range(0, len(tlds), chunk_size)]
    
    expr_parts = []
    for chunk in tld_chunks:
        regex_str = "|".join(chunk)
        expr_parts.append(f'any(dns.domains[*] matches "(?i)\\.(?:{regex_str})$")')
        
    traffic_expr = " or ".join(expr_parts)
    existing_rule = next((r for r in existing_rules if r["name"] == rule_name), None)
    is_enabled = existing_rule.get("enabled", True) if existing_rule else True

    payload = {"name": rule_name, "action": "block", "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
    
    if existing_rule:
        if existing_rule.get("traffic") == traffic_expr and existing_rule.get("enabled") == is_enabled:
            logger.info(f"Firewall rule {rule_name} unchanged. Skipping update.")
        else:
            cf.update_rule(existing_rule["id"], payload)
            logger.info(f"Firewall rule updated: {rule_name}")
    else: 
        cf.create_rule(payload)
        logger.info(f"Firewall rule created: {rule_name}")
        
    return rule_name

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

    traffic_expr = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in used_ids])
    final_rule_name = policy['policy_name']
    active_rule_names = [final_rule_name]
    
    action = policy.get("action", "block")
    existing_rule = next((r for r in existing_rules if r["name"] == final_rule_name), None)
    is_enabled = existing_rule.get("enabled", True) if existing_rule else True

    payload = {"name": final_rule_name, "action": action, "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
    if policy.get("identity_condition"): payload["identity"] = policy["identity_condition"]
    
    if existing_rule:
        if existing_rule.get("traffic") == traffic_expr and existing_rule.get("identity") == policy.get("identity_condition") and existing_rule.get("enabled") == is_enabled:
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
    block_rule = next((r for r in rules if r["name"] == "Block: HaGeZi Most Abused TLDs"), None)
    
    if not allow_rules or not block_rule:
        return
        
    block_prec = block_rule["precedence"]
    out_of_order = any(r["precedence"] > block_prec for r in allow_rules)
    
    if out_of_order:
        logger.info("Reordering: Moving TLD Block rule below Allow exceptions...")
        try:
            cf.delete_rule(block_rule["id"])
            
            payload = {
                "name": block_rule["name"],
                "action": block_rule["action"],
                "traffic": block_rule["traffic"],
                "enabled": block_rule.get("enabled", True),
                "filters": block_rule.get("filters", ["dns"])
            }
            if "identity" in block_rule and block_rule["identity"]:
                payload["identity"] = block_rule["identity"]
                
            cf.create_rule(payload)
            logger.info("Successfully fixed rule precedence.")
        except Exception as e:
            logger.error(f"Could not reorder rule: {e}")
    else:
        logger.info("Rule precedence is already correct.")

# ---------------------------------------------------------------------------
# 5. Main Execution
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    download_session = requests.Session()
    dl_retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    download_session.mount("https://", HTTPAdapter(max_retries=dl_retry))

    # Initialize Relevance Checker & build allowance list from top 1M datasets
    checker = RelevanceChecker(download_session)
    checker.build_dataset(max_workers=Config.MAX_WORKERS)

    tlds_list = []
    if Config.ENABLE_TLD_KW_FILTERING:
        tlds_list = parse_adguard_tld_list(download_session)
    
    # Compile structural offload rules separately into target engine components
    global TLD_PATTERN, KW_PATTERN
    if tlds_list:
        tld_regex_str = "|".join(tlds_list)
        TLD_PATTERN = re.compile(f"(?i)\\.(?:{tld_regex_str})$")
        
    kw_str = "|".join(Config.OFFLOAD_KEYWORDS)
    if kw_str:
        KW_PATTERN = re.compile(f"(?i){kw_str}")

    # Concurrently fetch and filter upstream lists tracking independent telemetry
    fetched_lists = {}
    total_tld_offloaded = 0
    total_kw_offloaded = 0
    total_irrelevant_pruned = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_url, download_session, name, url, checker): name for name, url in BLOCKLIST_URLS.items()}
        for future in concurrent.futures.as_completed(futures):
            name, valid_set, tld_count, kw_count, irrelevant_count = future.result()
            fetched_lists[name] = valid_set
            total_tld_offloaded += tld_count
            total_kw_offloaded += kw_count
            total_irrelevant_pruned += irrelevant_count

    compiled_policies = build_policy_sets(POLICIES, fetched_lists)
    optimized_allow_domains = optimize_domains(ALLOWED_DOMAINS) if ALLOWED_DOMAINS else []
    total_domains = sum(len(domains) for _, domains in compiled_policies) + len(optimized_allow_domains)

    if total_domains > Config.TOTAL_QUOTA:
        logger.error(f"Total domains ({total_domains:,}) exceeds quota! Aborting.")
        return

    logger.info(f"Total domains offloaded by TLD rule: {total_tld_offloaded:,}")
    logger.info(f"Total domains offloaded by Keyword rule: {total_kw_offloaded:,}")
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
        allow_policy = {
            "prefix": "L_AllowTLD",
            "policy_name": "Allow: HaGeZi TLD Exceptions",
            "action": "allow"
        }
        used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_allow_domains, allow_policy)
        all_active_list_ids.extend(used_ids)
        all_active_rule_names.extend(rule_names)

    if Config.ENABLE_TLD_KW_FILTERING and tlds_list:
        tld_rule_name = sync_tld_regex_rule(cf, existing_rules, tlds_list)
        if tld_rule_name:
            all_active_rule_names.append(tld_rule_name)

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
