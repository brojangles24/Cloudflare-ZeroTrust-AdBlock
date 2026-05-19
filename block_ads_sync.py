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

# Global regex patterns compiled at runtime
TLD_PATTERN = None
NSFW_NUCLEAR_PATTERN = None
NSFW_BOUNDARY_PATTERN = None
DYNAMIC_DOMAIN_PATTERN = None
ALLOWED_DOMAINS = set()

# ---------------------------------------------------------------------------
# 1. Config & Lists
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN               = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID              = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL           = os.environ.get("PRIMARY_EMAIL", "")   
    SECONDARY_EMAIL         = os.environ.get("SECONDARY_EMAIL", "")  
    
    ACTIVE_TIER             = os.environ.get("ACTIVE_TIER", "pro++").strip().lower()
    ENABLE_TLD_KW_FILTERING = True

    # --- TIER 1: NUCLEAR NSFW (Pure Wildcard) ---
    # Highly specific strings that will never appear in a legitimate domain.
    # Dropped instantly if they match ANY part of the domain string.
    NSFW_NUCLEAR_KEYWORDS = [
        "pornhub", "onlyfans", "xvideos", "chaturbate", "bukkake", 
        "deepthroat", "camgirl", "hentai", "xnxx", "xhamster", "rule34"
    ]

    # --- TIER 2: BOUNDARY NSFW (Anchored Match) ---
    # Shorter/ambiguous terms. Wrapped in token anchors to prevent 
    # breaking neutral sites like essex.gov.uk or popcorn.com.
    NSFW_BOUNDARY_KEYWORDS = [
        "sex", "xxx", "porn", "nude", "milf", "slut", "fetish", "adult"
    ]

    # --- TIER 3: DYNAMIC SPECIFICITY ENGINE (Ad/Tracker Learning) ---
    # Identifies root domains spawning massive sub-allocations across lists.
    BASE_EXACT_DOMAINS = [
        "doubleclick.net", "appsflyersdk.com", "amazon-adsystem.com", 
        "scorecardresearch.com", "crashlytics.com", "datadoghq.com"
    ]
    DYNAMIC_DOMAIN_MIN_FREQ = 15 
    CLOUDFLARE_REGEX_MAX_CHAR = 3500

    # Explicit protection layer to bypass potential downstream upstream poisoning
    SAFE_INFRA_DOMAINS = {
        "github.com", "google.com", "apple.com", "microsoft.com", 
        "windows.com", "amazonaws.com", "cloudflare.com", "fastly.net", "azure.com"
    }
    
    OFFLOAD_DOMAINS = []
    MAX_LIST_SIZE = 1000
    MAX_RETRIES = 5
    TOTAL_QUOTA = 300_000
    REQUEST_TIMEOUT = (5, 25)
    MAX_WORKERS = 5
    SCRUB_TARGETS = ["Base", "Pro++", "Ultimate", "Social", "Block:", "Allow:", "L_"]

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL", "SECONDARY_EMAIL") if not getattr(cls, k)]
        if missing: raise EnvironmentError(f"Missing environment variables: {', '.join(missing)}")

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
    "HaGeZi Anti Piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt", 
    "HaGeZi Dynamic DNS": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
    "HaGeZi Social": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
    "HaGeZi TIF Mini": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
}

POLICIES = [
    {"prefix": "L_Pro", "policy_name": "Block: HaGeZi Pro Mini", "action": "block", "identity_condition": None, "include": ["HaGeZi Pro Mini"], "exclude": []},
    {"prefix": "L_NSFW", "policy_name": "Block: HaGeZi NSFW", "action": "block", "identity_condition": None, "include": ["Hagezi NSFW"], "exclude": []},
    {"prefix": "L_Fake", "policy_name": "Block: HaGeZi Fake", "action": "block", "identity_condition": None, "include": ["HaGeZi Fake"], "exclude": []},
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
        self.session.mount("https://", HTTPAdapter(max_retries=Retry(total=Config.MAX_RETRIES, backoff_factor=2, status_forcelist=[500, 502, 503, 504])))

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

    def _paginate(self, endpoint):
        results, page = [], 1
        while True:
            resp = self._request("GET", f"{endpoint}?page={page}&per_page=100")
            data = resp.get("result") or []
            results.extend(data)
            if page >= resp.get("result_info", {}).get("total_pages", 1) or not data: break
            page += 1
        return results

    def get_lists(self): return self._paginate("lists")
    def get_rules(self): return self._paginate("rules")
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")
    def create_list(self, name, items, desc=""): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items, "description": desc})
    def update_list(self, lid, name, items, desc=""): return self._request("PUT", f"lists/{lid}", json={"name": name, "items": items, "description": desc})
    def create_rule(self, data): return self._request("POST", "rules", json=data)
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json=data)

# ---------------------------------------------------------------------------
# 3. Dynamic Base Domain Engine
# ---------------------------------------------------------------------------
def get_base_domain(domain: str) -> str:
    parts = domain.split('.')
    if len(parts) < 2: return domain
    if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) <= 2: return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def extract_dynamic_domains(all_domains: set[str]) -> list[str]:
    domain_counts = Counter()
    for domain in all_domains:
        base = get_base_domain(domain.lower())
        if base not in Config.SAFE_INFRA_DOMAINS:
            domain_counts[base] += 1
            
    dynamic_bases = [dom for dom, count in domain_counts.items() if count >= Config.DYNAMIC_DOMAIN_MIN_FREQ]
    final_domains = list(set(Config.BASE_EXACT_DOMAINS + dynamic_bases))
    
    truncated_domains, current_len = [], 0
    base_overhead = len('any(dns.domains[*] matches "(?i)(^|\\\\.)()$")')
    
    for dom in sorted(final_domains, key=len):
        escaped_len = len(dom.replace(".", r"\.")) + 1
        if (base_overhead + current_len + escaped_len) < Config.CLOUDFLARE_REGEX_MAX_CHAR:
            truncated_domains.append(dom)
            current_len += escaped_len
        else: break
    return truncated_domains

# ---------------------------------------------------------------------------
# Core Utilities
# ---------------------------------------------------------------------------
def is_valid_domain(domain: str) -> tuple[str | None, str | None]:
    domain = domain.strip().strip(".")
    if not domain or any(c in domain for c in "*/[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None, None
    if domain in ALLOWED_DOMAINS or any(domain.endswith("." + allowed) for allowed in ALLOWED_DOMAINS):
        return domain, None
        
    if Config.ENABLE_TLD_KW_FILTERING:
        if TLD_PATTERN and TLD_PATTERN.search(domain): return None, "tld"
        if NSFW_NUCLEAR_PATTERN and NSFW_NUCLEAR_PATTERN.search(domain): return None, "nsfw_nuclear"
        if NSFW_BOUNDARY_PATTERN and NSFW_BOUNDARY_PATTERN.search(domain): return None, "nsfw_boundary"
        if DYNAMIC_DOMAIN_PATTERN and DYNAMIC_DOMAIN_PATTERN.search(domain): return None, "dynamic_tracker"
        
    return domain, None

def optimize_domains(domains):
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized, last_kept = [], None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."): continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]

# ---------------------------------------------------------------------------
# Cloudflare Automation
# ---------------------------------------------------------------------------
def sync_regex_rule(cf, existing_rules, items, rule_name, rule_type):
    if not items: return ""
    expr_parts = []
    
    if rule_type == "tld":
        chunks = [items[i:i + 30] for i in range(0, len(items), 30)]
        for chunk in chunks: expr_parts.append(f'any(dns.domains[*] matches "(?i)\\.(?:{"|".join(chunk)})$")')
        
    elif rule_type == "nsfw_nuclear":
        regex_str = "|".join(re.escape(kw) for kw in items)
        expr_parts.append(f'any(dns.domains[*] matches "(?i)({regex_str})")')
        
    elif rule_type == "nsfw_boundary":
        regex_str = "|".join(re.escape(kw) for kw in items)
        expr_parts.append(f'any(dns.domains[*] matches "(?i)(?:^|[\\\\.\\\\-])({regex_str})(?:[\\\\.\\\\-]|$)")')
        
    elif rule_type == "base_domain":
        escaped_items = [d.replace(".", r"\.") for d in items]
        regex_str = "|".join(escaped_items)
        expr_parts.append(f'any(dns.domains[*] matches "(?i)(^|\\\\.)({regex_str})$")')
        
    traffic_expr = " or ".join(expr_parts)
    existing_rule = next((r for r in existing_rules if r["name"] == rule_name), None)
    
    payload = {"name": rule_name, "action": "block", "enabled": True, "filters": ["dns"], "traffic": traffic_expr}
    if existing_rule:
        if existing_rule.get("traffic") != traffic_expr:
            cf.update_rule(existing_rule["id"], payload)
            logger.info(f"Updated Firewall Rule: {rule_name}")
    else: 
        cf.create_rule(payload)
        logger.info(f"Created Firewall Rule: {rule_name}")
    return rule_name

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

    traffic_expr = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in used_ids])
    payload = {"name": policy['policy_name'], "action": policy.get("action", "block"), "enabled": True, "filters": ["dns"], "traffic": traffic_expr}
    if policy.get("identity_condition"): payload["identity"] = policy["identity_condition"]
    
    existing = next((r for r in existing_rules if r["name"] == policy['policy_name']), None)
    if existing:
        if existing.get("traffic") != traffic_expr or existing.get("identity") != policy.get("identity_condition"):
            cf.update_rule(existing["id"], payload)
    else: cf.create_rule(payload)
    return used_ids, [policy['policy_name']]

def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    sess = requests.Session()
    sess.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])))

    tlds_list = []
    if Config.ENABLE_TLD_KW_FILTERING:
        try:
            r = sess.get(ADGUARD_TLD_URL, timeout=Config.REQUEST_TIMEOUT)
            r.raise_for_status()
            for line in r.text.splitlines():
                if line.startswith("||*."):
                    parts = line.split("^$denyallow=")
                    raw = parts[0].replace("||*.", "").replace("^", "")
                    if raw: tlds_list.append(raw)
                    if len(parts) > 1:
                        for d in parts[1].split("|"): ALLOWED_DOMAINS.add(d.strip().lower())
        except: pass
    
    raw_lists, all_raw_domains = {}, set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        def fetch(n, u):
            doms = set()
            try:
                r = sess.get(u, timeout=Config.REQUEST_TIMEOUT)
                for line in r.text.splitlines():
                    if not line or line[0] in ("#", "!", "/"): continue
                    c = line.split()[-1].lower().strip().strip(".")
                    if c and "." in c and not IP_PATTERN.match(c): doms.add(c)
            except: pass
            return n, doms
            
        futures = {pool.submit(fetch, n, u): n for n, u in BLOCKLIST_URLS.items()}
        for f in concurrent.futures.as_completed(futures):
            n, raw = f.result()
            raw_lists[n] = raw
            all_raw_domains.update(raw)

    if Config.ENABLE_TLD_KW_FILTERING: Config.OFFLOAD_DOMAINS = extract_dynamic_domains(all_raw_domains)

    global TLD_PATTERN, NSFW_NUCLEAR_PATTERN, NSFW_BOUNDARY_PATTERN, DYNAMIC_DOMAIN_PATTERN
    if tlds_list: TLD_PATTERN = re.compile(f"(?i)\\.(?:{'|'.join(tlds_list)})$")
    
    if Config.NSFW_NUCLEAR_KEYWORDS:
        NSFW_NUCLEAR_PATTERN = re.compile(f"(?i){'|'.join(re.escape(kw) for kw in Config.NSFW_NUCLEAR_KEYWORDS)}")
        
    if Config.NSFW_BOUNDARY_KEYWORDS:
        NSFW_BOUNDARY_PATTERN = re.compile(f"(?i)(?:^|[\\.\\-])(?:{'|'.join(re.escape(kw) for kw in Config.NSFW_BOUNDARY_KEYWORDS)})(?:[\\.\\-]|$)")
        
    if Config.OFFLOAD_DOMAINS:
        escaped_domains = [d.replace(".", r"\.") for d in Config.OFFLOAD_DOMAINS]
        DYNAMIC_DOMAIN_PATTERN = re.compile(f"(?i)(?:^|\\.)(?:{'|'.join(escaped_domains)})$")

    fetched_lists = {}
    offloaded = {"tld": 0, "nuclear": 0, "boundary": 0, "tracker": 0}
    
    for name, raw_domains in raw_lists.items():
        filtered_set = set()
        for dom in raw_domains:
            cleaned, reason = is_valid_domain(dom)
            if cleaned: filtered_set.add(cleaned)
            elif reason == "tld": offloaded["tld"] += 1
            elif reason == "nsfw_nuclear": offloaded["nuclear"] += 1
            elif reason == "nsfw_boundary": offloaded["boundary"] += 1
            elif reason == "dynamic_tracker": offloaded["tracker"] += 1
        fetched_lists[name] = filtered_set

    compiled_policies = []
    for policy in POLICIES:
        p_set = set()
        for inc in policy.get("include", []): p_set |= fetched_lists.get(inc, set())
        for exc in policy.get("exclude", []): p_set -= fetched_lists.get(exc, set())
        compiled_policies.append((policy, optimize_domains(p_set)))
        
    opt_allow = optimize_domains(ALLOWED_DOMAINS) if ALLOWED_DOMAINS else []
    total_doms = sum(len(d) for _, d in compiled_policies) + len(opt_allow)

    if total_doms > Config.TOTAL_QUOTA:
        logger.error(f"Quota Exceeded: {total_doms:,} domains")
        return

    logger.info(f"Offloads -> TLDs: {offloaded['tld']:,} | Trackers: {offloaded['tracker']:,} | Nuclear NSFW: {offloaded['nuclear']:,} | Boundary NSFW: {offloaded['boundary']:,}")
    logger.info(f"Syncing {total_doms:,} domains to Cloudflare.")

    existing_lists, existing_rules = cf.get_lists(), cf.get_rules()
    valid_rule_bases = {p["policy_name"] for p in POLICIES}
    
    if Config.ENABLE_TLD_KW_FILTERING:
        valid_rule_bases.update({
            "Block: HaGeZi Most Abused TLDs", "Allow: HaGeZi TLD Exceptions", 
            "Block: Dynamic Exact Base Domains", "Block: NSFW Nuclear Keywords", 
            "Block: NSFW Boundary Keywords"
        })

    all_ids, all_rules = [], []

    if Config.ENABLE_TLD_KW_FILTERING and opt_allow:
        ids, rns = sync_to_cloudflare(cf, existing_lists, existing_rules, opt_allow, {"prefix": "L_AllowTLD", "policy_name": "Allow: HaGeZi TLD Exceptions", "action": "allow"})
        all_ids.extend(ids); all_rules.extend(rns)

    if Config.ENABLE_TLD_KW_FILTERING:
        if tlds_list: all_rules.append(sync_regex_rule(cf, existing_rules, tlds_list, "Block: HaGeZi Most Abused TLDs", "tld"))
        if Config.OFFLOAD_DOMAINS: all_rules.append(sync_regex_rule(cf, existing_rules, Config.OFFLOAD_DOMAINS, "Block: Dynamic Exact Base Domains", "base_domain"))
        if Config.NSFW_NUCLEAR_KEYWORDS: all_rules.append(sync_regex_rule(cf, existing_rules, Config.NSFW_NUCLEAR_KEYWORDS, "Block: NSFW Nuclear Keywords", "nsfw_nuclear"))
        if Config.NSFW_BOUNDARY_KEYWORDS: all_rules.append(sync_regex_rule(cf, existing_rules, Config.NSFW_BOUNDARY_KEYWORDS, "Block: NSFW Boundary Keywords", "nsfw_boundary"))

    for pol, doms in compiled_policies:
        ids, rns = sync_to_cloudflare(cf, existing_lists, existing_rules, doms, pol)
        all_ids.extend(ids); all_rules.extend(rns)

    for r in existing_rules:
        if r["name"] not in all_rules and any(t in r["name"] for t in Config.SCRUB_TARGETS):
            if not any(r["name"].startswith(base) for base in valid_rule_bases):
                try: cf.delete_rule(r["id"])
                except: pass
                
    for l in existing_lists:
        if l["id"] not in all_ids and any(t in l["name"] for t in Config.SCRUB_TARGETS):
            try: cf.delete_list(l["id"])
            except: pass

    logger.info(f"Finished in {time.perf_counter() - start:.2f}s.")

if __name__ == "__main__": main()
