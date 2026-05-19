import os
import re
import logging
import requests
import concurrent.futures
import time
import hashlib
from collections import Counter
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# Global variables
TLD_PATTERN = None
ALLOWED_DOMAINS = set()

# ---------------------------------------------------------------------------
# 1. Config & Autonomous Thresholds
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN               = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID              = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL           = os.environ.get("PRIMARY_EMAIL", "")   
    SECONDARY_EMAIL         = os.environ.get("SECONDARY_EMAIL", "")  
    ACTIVE_TIER             = os.environ.get("ACTIVE_TIER", "pro++").strip().lower()
    
    ENABLE_TLD_KW_FILTERING = True
    
    # AUTONOMOUS THRESHOLDS
    DYNAMIC_KW_THRESHOLD    = 100  # A word must appear 100+ times to become a regex rule
    DYNAMIC_BASE_THRESHOLD  = 20   # A root domain must have 20+ subdomains to become a regex rule
    DYNAMIC_KW_MIN_LEN      = 4    # Minimum characters for a dynamic keyword

    # Safety nets to prevent catastrophic regex blocks
    SAFE_INFRA_DOMAINS = {"github.com", "google.com", "apple.com", "microsoft.com", "windows.com", "amazonaws.com", "cloudflare.com", "fastly.net", "azure.com", "cloudfront.net"}
    SAFE_TERMS = {
        "com", "net", "org", "edu", "gov", "info", "xyz", "co", "io", "me",
        "server", "cloud", "update", "online", "store", "shop", "portal", "network", "system", 
        "service", "domain", "connect", "client", "mobile", "global", "static", "content", 
        "public", "assets", "api", "app", "cdn", "www", "wpad", "ns1", "ns2", "mail", "dns",
        "web", "host", "dev", "login", "secure", "proxy", "vpn", "search", "link"
    }

    MAX_LIST_SIZE           = 1000
    MAX_RETRIES             = 5
    TOTAL_QUOTA             = 300_000
    REQUEST_TIMEOUT         = (5, 25)
    MAX_WORKERS             = 5
    CLOUDFLARE_REGEX_MAX    = 3500

    SCRUB_TARGETS = ["Base", "Pro++", "Ultimate", "Social", "Block:", "Allow:", "L_", "AI Dynamic"]

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL", "SECONDARY_EMAIL") if not getattr(cls, k)]
        if missing:
            raise EnvironmentError(f"Missing environment variables: {', '.join(missing)}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|"
    r"^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|"
    r"^(?:[A-Fa-f0-9]{1,4}:)*:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*$"
)

ADGUARD_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/spam-tlds.txt"

BLOCKLIST_URLS = {
    "HaGeZi Pro Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.mini-onlydomains.txt",
    "HaGeZi Pro++ Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus.mini-onlydomains.txt",
    "HaGeZi Ultimate Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate.mini-onlydomains.txt",
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
    {"prefix": "L_Pro", "policy_name": "Block: HaGeZi Pro Mini", "action": "block", "identity_condition": None, "include": ["HaGeZi Pro Mini"], "exclude": []},
    {"prefix": "L_NSFW", "policy_name": "Block: HaGeZi NSFW", "action": "block", "identity_condition": None, "include": ["Hagezi NSFW"], "exclude": []},
    {"prefix": "L_Fake", "policy_name": "Block: HaGeZi Fake", "action": "block", "identity_condition": None, "include": ["HaGeZi Fake"], "exclude": []},
    {"prefix": "L_NoSafe", "policy_name": "Block: HaGeZi Safesearch Not Support", "action": "block", "identity_condition": None, "include": ["HaGeZi Safesearch Not Support"], "exclude": []},
    {"prefix": "L_Bypass", "policy_name": "Block: HaGeZi Bypass Block", "action": "block", "identity_condition": None, "include": ["HaGeZi Bypass Block"], "exclude": []},
    {"prefix": "L_AntiPiracy", "policy_name": "Block: HaGeZi Anti Piracy", "action": "block", "identity_condition": None, "include": ["HaGeZi Anti Piracy"], "exclude": []},
    {"prefix": "L_DynDNS", "policy_name": "Block: HaGeZi Dynamic DNS", "action": "block", "identity_condition": None, "include": ["HaGeZi Dynamic DNS"], "exclude": []},
    {"prefix": "L_Social", "policy_name": "Block: HaGeZi Social (Primary Only)", "action": "block", "identity_condition": f'identity.email == "{Config.PRIMARY_EMAIL}"', "include": ["HaGeZi Social"], "exclude": []},
    {"prefix": "L_TIF", "policy_name": "Block: HaGeZi TIF Mini", "action": "block", "identity_condition": None, "include": ["HaGeZi TIF Mini"], "exclude": []},
]

if Config.ACTIVE_TIER == "pro++":
    POLICIES.append({"prefix": "L_ProPlus", "policy_name": "Block: HaGeZi Pro++ Mini (Except Secondary)", "action": "block", "identity_condition": f'not(identity.email == "{Config.SECONDARY_EMAIL}")', "include": ["HaGeZi Pro++ Mini"], "exclude": ["HaGeZi Pro Mini"]})
elif Config.ACTIVE_TIER == "ultimate":
    POLICIES.append({"prefix": "L_Ultimate", "policy_name": "Block: HaGeZi Ultimate Mini (Except Secondary)", "action": "block", "identity_condition": f'not(identity.email == "{Config.SECONDARY_EMAIL}")', "include": ["HaGeZi Ultimate Mini"], "exclude": ["HaGeZi Pro Mini"]})

# ---------------------------------------------------------------------------
# 2. Cloudflare API Client
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=Retry(total=Config.MAX_RETRIES, backoff_factor=1, status_forcelist=[500, 502, 503, 504])))

    def _request(self, method, endpoint, **kwargs):
        retries, delay = Config.MAX_RETRIES, 2
        while retries > 0:
            resp = self.session.request(method, f"{self.base_url}/{endpoint}", headers=self.headers, timeout=Config.REQUEST_TIMEOUT, **kwargs)
            if resp.status_code == 429:
                retries -= 1
                time.sleep(delay)
                delay *= 2 
                continue
            resp.raise_for_status()
            return resp.json()
        raise requests.exceptions.HTTPError("API limits exhausted.", response=resp)

    def get_lists(self): return self._request("GET", "lists").get("result") or []
    def get_rules(self): return self._request("GET", "rules").get("result") or []
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")
    def create_list(self, name, items, desc=""): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items, "description": desc})
    def update_list(self, lid, name, items, desc=""): return self._request("PUT", f"lists/{lid}", json={"name": name, "items": items, "description": desc})
    def create_rule(self, data): return self._request("POST", "rules", json=data)
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json=data)

# ---------------------------------------------------------------------------
# 3. Parsing & Autonomous Logic
# ---------------------------------------------------------------------------
def parse_adguard_tld_list(session: requests.Session) -> list[str]:
    global ALLOWED_DOMAINS
    try:
        resp = session.get(ADGUARD_TLD_URL, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        tlds = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("!"): continue
            if line.startswith("||*."):
                parts = line.split("^$denyallow=")
                raw_tld = parts[0].replace("||*.", "").replace("^", "")
                if raw_tld: tlds.append(raw_tld)
                if len(parts) > 1:
                    for dom in parts[1].split("|"):
                        if dom.strip(): ALLOWED_DOMAINS.add(dom.strip().lower())
        return tlds
    except Exception as exc:
        logger.error(f"Failed to fetch AdGuard TLDs: {exc}")
        return []

def get_base_domain(domain):
    parts = domain.split('.')
    return ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) <= 2 else ".".join(parts[-2:])

def run_autonomous_profiling(all_domains):
    word_counts, domain_counts = Counter(), Counter()
    for domain in all_domains:
        root = get_base_domain(domain)
        if root not in Config.SAFE_INFRA_DOMAINS: 
            domain_counts[root] += 1
        
        for t in re.split(r'[\.\-_]', domain):
            if len(t) >= Config.DYNAMIC_KW_MIN_LEN and t.isalpha() and t not in Config.SAFE_TERMS: 
                word_counts[t] += 1

    dynamic_kws = [w for w, c in word_counts.items() if c >= Config.DYNAMIC_KW_THRESHOLD]
    dynamic_bases = [d for d, c in domain_counts.items() if c >= Config.DYNAMIC_BASE_THRESHOLD]
    
    logger.info(f"AI Profiler extracted {len(dynamic_kws)} keywords and {len(dynamic_bases)} dynamic base domains.")
    return dynamic_kws, dynamic_bases

def fetch_url(session: requests.Session, name: str, url: str) -> tuple[str, set[str]]:
    valid_domains = set()
    try:
        resp = session.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"): continue
            
            domain = line.split()[-1].lower().strip().strip(".")
            if not domain or any(c in domain for c in "*/[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
                continue
            
            valid_domains.add(domain)
        logger.info(f"Fetched {name}: {len(valid_domains):,} raw domains.")
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
# 4. Cloudflare Sync & Cleanup
# ---------------------------------------------------------------------------
def chunk_for_cloudflare(items):
    chunks, current_chunk, current_len = [], [], 0
    for item in items:
        if current_len + len(item) + 1 > Config.CLOUDFLARE_REGEX_MAX:
            chunks.append(current_chunk)
            current_chunk, current_len = [item], len(item)
        else:
            current_chunk.append(item)
            current_len += len(item) + 1
    if current_chunk: chunks.append(current_chunk)
    return chunks

def sync_regex_rules(cf, existing_rules, rule_type, items, prefix):
    if not items: return []
    chunks = chunk_for_cloudflare(items)
    active_names = []
    
    for i, chunk in enumerate(chunks):
        rule_name = f"{prefix} {i+1:02d}"
        active_names.append(rule_name)
        
        joined = "|".join(map(re.escape, chunk))
        if rule_type == "tld":
            traffic = f'any(dns.domains[*] matches "(?i)\\.(?:{joined})$")'
        elif rule_type == "kw":
            traffic = f'any(dns.domains[*] matches "(?i)(?:^|[\\\\.\\\\-])({joined})(?:[\\\\.\\\\-]|$)")'
        elif rule_type == "base":
            traffic = f'any(dns.domains[*] matches "(?i)(^|\\\\.)({joined})$")'
            
        payload = {"name": rule_name, "action": "block", "enabled": True, "filters": ["dns"], "traffic": traffic}
        existing = next((r for r in existing_rules if r["name"] == rule_name), None)
        
        if existing:
            if existing.get("traffic") != traffic: 
                cf.update_rule(existing["id"], payload)
                logger.info(f"Updated dynamic rule: {rule_name}")
        else: 
            cf.create_rule(payload)
            logger.info(f"Created dynamic rule: {rule_name}")
            
    return active_names

def sync_to_cloudflare(cf, existing_lists, existing_rules, domains, policy):
    if not domains: return [], []
    sorted_domains = sorted(domains)
    chunks = [sorted_domains[i : i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    policy_existing_lists = sorted([l for l in existing_lists if l["name"].startswith(policy["prefix"] + " ")], key=lambda x: x["name"])
    
    def process_chunk(idx, chunk):
        list_name = f"{policy['prefix']} {idx + 1:03d}"
        chunk_hash = hashlib.sha256(",".join(chunk).encode('utf-8')).hexdigest()
        items = [{"value": d} for d in chunk]
        if idx < len(policy_existing_lists):
            existing = policy_existing_lists[idx]
            if existing.get("description") == chunk_hash: return existing["id"]
            cf.update_list(existing["id"], list_name, items, desc=chunk_hash)
            return existing["id"]
        res = cf.create_list(list_name, items, desc=chunk_hash)
        return res["result"]["id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
        used_ids = [f.result() for f in concurrent.futures.as_completed([executor.submit(process_chunk, i, c) for i, c in enumerate(chunks)])]

    traffic = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in used_ids])
    payload = {"name": policy['policy_name'], "action": policy.get("action", "block"), "enabled": True, "filters": ["dns"], "traffic": traffic}
    if policy.get("identity_condition"): payload["identity"] = policy["identity_condition"]
    
    existing_rule = next((r for r in existing_rules if r["name"] == policy['policy_name']), None)
    if existing_rule:
        if existing_rule.get("traffic") != traffic or existing_rule.get("identity") != payload.get("identity"):
            cf.update_rule(existing_rule["id"], payload)
    else: 
        cf.create_rule(payload)
        
    return used_ids, [policy['policy_name']]

def enforce_tld_rule_order(cf):
    rules = cf.get_rules()
    allow_rules = [r for r in rules if r["name"].startswith("Allow: HaGeZi TLD Exceptions")]
    block_rules = [r for r in rules if r["name"].startswith("Block: AI Dynamic TLD")]
    if not allow_rules or not block_rules: return
        
    allow_prec = min(r["precedence"] for r in allow_rules)
    out_of_order = any(r["precedence"] < allow_prec for r in block_rules)
    
    if out_of_order:
        logger.info("Reordering: Moving Block rules below Allow exceptions...")
        for br in block_rules:
            cf.delete_rule(br["id"])
            payload = {"name": br["name"], "action": br["action"], "traffic": br["traffic"], "enabled": br.get("enabled", True), "filters": ["dns"]}
            cf.create_rule(payload)

# ---------------------------------------------------------------------------
# 5. Main Execution
# ---------------------------------------------------------------------------
def main():
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    sess = requests.Session()
    sess.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])))

    tlds_list = parse_adguard_tld_list(sess) if Config.ENABLE_TLD_KW_FILTERING else []

    # 1. Fetch raw lists
    fetched_lists = {}
    all_raw_domains = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_url, sess, name, url): name for name, url in BLOCKLIST_URLS.items()}
        for future in concurrent.futures.as_completed(futures):
            name, valid_set = future.result()
            fetched_lists[name] = valid_set
            all_raw_domains.update(valid_set)

    # 2. Autonomous AI Profiling
    dynamic_kws, dynamic_bases = run_autonomous_profiling(all_raw_domains)

    # Compile the filters
    kw_joined = '|'.join(map(re.escape, dynamic_kws))
    base_joined = '|'.join([d.replace('.', r'\.') for d in dynamic_bases])
    tld_joined = '|'.join(map(re.escape, tlds_list))
    
    kw_pat = re.compile(f"(?i)(?:^|[\\.\\-])(?:{kw_joined})(?:[\\.\\-]|$)") if dynamic_kws else None
    base_pat = re.compile(f"(?i)(?:^|\\.)(?:{base_joined})$") if dynamic_bases else None
    tld_pat = re.compile(f"(?i)\\.(?:{tld_joined})$") if tlds_list else None

    # 3. Apply the filters locally to strip domains
    filtered_fetched_lists = {}
    total_stripped = 0
    for name, domains in fetched_lists.items():
        filtered = set()
        for d in domains:
            if d in ALLOWED_DOMAINS or any(d.endswith("." + a) for a in ALLOWED_DOMAINS):
                filtered.add(d)
                continue
            if kw_pat and kw_pat.search(d): continue
            if base_pat and base_pat.search(d): continue
            if tld_pat and tld_pat.search(d): continue
            filtered.add(d)
        
        total_stripped += (len(domains) - len(filtered))
        filtered_fetched_lists[name] = filtered

    logger.info(f"AI Profiling offloaded {total_stripped:,} domains from exact-match lists!")

    # 4. Build Policy Sets
    compiled_policies = []
    for policy in POLICIES:
        p_set = set()
        for inc in policy.get("include", []): p_set |= filtered_fetched_lists.get(inc, set())
        for exc in policy.get("exclude", []): p_set -= filtered_fetched_lists.get(exc, set())
        compiled_policies.append((policy, optimize_domains(p_set)))

    optimized_allow_domains = optimize_domains(ALLOWED_DOMAINS) if ALLOWED_DOMAINS else []
    total_domains = sum(len(domains) for _, domains in compiled_policies) + len(optimized_allow_domains)

    if total_domains > Config.TOTAL_QUOTA:
        logger.error(f"Total domains ({total_domains:,}) exceeds quota! Aborting.")
        return

    logger.info(f"Total specific domains to sync to Cloudflare: {total_domains:,}")

    # 5. Cloudflare Sync Execution
    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()
    
    all_active_list_ids = []
    all_active_rule_names = []

    # Sync Allow List
    if Config.ENABLE_TLD_KW_FILTERING and optimized_allow_domains:
        allow_policy = {"prefix": "L_AllowTLD", "policy_name": "Allow: HaGeZi TLD Exceptions", "action": "allow"}
        used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_allow_domains, allow_policy)
        all_active_list_ids.extend(used_ids)
        all_active_rule_names.extend(rule_names)

    # Sync Dynamic Regex Rules
    all_active_rule_names.extend(sync_regex_rules(cf, existing_rules, "tld", tlds_list, "Block: AI Dynamic TLD"))
    all_active_rule_names.extend(sync_regex_rules(cf, existing_rules, "kw", dynamic_kws, "Block: AI Dynamic Keyword"))
    all_active_rule_names.extend(sync_regex_rules(cf, existing_rules, "base", dynamic_bases, "Block: AI Dynamic Base"))

    # Sync Standard Policies
    for policy, optimized_domains in compiled_policies:
        used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_domains, policy)
        all_active_list_ids.extend(used_ids)
        all_active_rule_names.extend(rule_names)

    # 6. Orphan Cleanup
    for r in existing_rules:
        if r["name"] not in all_active_rule_names and any(target in r["name"] for target in Config.SCRUB_TARGETS):
            try:
                cf.delete_rule(r["id"])
                logger.info(f"Deleted Orphaned Rule: {r['name']}")
            except Exception as e: pass

    for l in existing_lists:
        if l["id"] not in all_active_list_ids and any(target in l["name"] for target in Config.SCRUB_TARGETS):
            try:
                cf.delete_list(l["id"])
                logger.info(f"Deleted Orphaned List: {l['name']}")
            except Exception as e: pass

    if Config.ENABLE_TLD_KW_FILTERING: enforce_tld_rule_order(cf)
    logger.info(f"Sync completed in {time.perf_counter() - start:.2f} seconds.")

if __name__ == "__main__":
    main()
