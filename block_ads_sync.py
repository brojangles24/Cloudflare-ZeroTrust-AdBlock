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

# ---------------------------------------------------------------------------
# 1. Config & Autonomous Thresholds
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN               = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID              = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL           = os.environ.get("PRIMARY_EMAIL", "")   
    SECONDARY_EMAIL         = os.environ.get("SECONDARY_EMAIL", "")  
    ACTIVE_TIER             = os.environ.get("ACTIVE_TIER", "pro++").strip().lower()

    NUCLEAR_THRESHOLD       = 100
    BOUNDARY_THRESHOLD      = 50
    BASE_DOMAIN_THRESHOLD   = 20
    DYNAMIC_KW_MIN_LEN      = 3 

    SAFE_INFRA_DOMAINS = {"github.com", "google.com", "apple.com", "microsoft.com", "windows.com", "amazonaws.com", "cloudflare.com", "fastly.net", "azure.com"}
    SAFE_INFRA_TERMS = {"server", "cloud", "update", "online", "store", "shop", "portal", "network", "system", "service", "domain", "connect", "client", "mobile", "global", "static", "content", "public", "assets", "api", "app", "cdn", "www", "wpad", "ns1", "ns2", "mail", "dns"}
    TELEMETRY_TRIGGERS = ["telemetry", "metrics", "analytics", "adsystem", "pixel", "log"]

    # Structural regex checks (Punycode, extreme dashes/lengths)
    STRUCTURAL_REGEX = [r"(?:.*-){4,}", r"[0-9]{8,}", r"[a-z0-9]{30,}\.", r"^(?:xn--).*(?:xn--)", r"\.xn--[a-z0-9\-]+$"]

    CLOUDFLARE_REGEX_MAX_CHAR = 3500
    MAX_LIST_SIZE = 1000
    MAX_RETRIES = 5
    REQUEST_TIMEOUT = (5, 25)
    MAX_WORKERS = 5

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL", "SECONDARY_EMAIL") if not getattr(cls, k)]
        if missing:
            raise EnvironmentError(f"Missing environment variables: {', '.join(missing)}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

IP_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|^(?:[A-Fa-f0-9]{1,4}:)*:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*$")

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

    def _paginate(self, endpoint):
        results, page = [], 1
        while True:
            resp = self._request("GET", f"{endpoint}?page={page}&per_page=100")
            data = resp.get("result") or []
            results.extend(data)
            if page >= resp.get("result_info", {}).get("total_pages", 1) or not data: 
                break
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
# 3. Engines
# ---------------------------------------------------------------------------
def get_base_domain(domain):
    parts = domain.split('.')
    return ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) <= 2 else ".".join(parts[-2:])

def run_autonomous_profiling(all_domains):
    word_counts, domain_counts = Counter(), Counter()
    for domain in all_domains:
        root = get_base_domain(domain.lower())
        if root not in Config.SAFE_INFRA_DOMAINS: 
            domain_counts[root] += 1
        
        tokens = re.split(r'[\.\-_]', domain.lower())
        for t in tokens:
            if len(t) >= Config.DYNAMIC_KW_MIN_LEN and t.isalpha() and t not in Config.SAFE_INFRA_TERMS: 
                word_counts[t] += 1
    
    nuclear = [w for w, c in word_counts.items() if c >= Config.NUCLEAR_THRESHOLD]
    boundary = [w for w, c in word_counts.items() if Config.BOUNDARY_THRESHOLD <= c < Config.NUCLEAR_THRESHOLD]
    bases = [d for d, c in domain_counts.items() if c >= Config.BASE_DOMAIN_THRESHOLD]
    
    def limit_items(items):
        """Keep combined regex length strictly under Cloudflare limits."""
        acc, current_len = [], 0
        for i in items:
            if current_len + len(i) + 1 > Config.CLOUDFLARE_REGEX_MAX_CHAR: 
                break
            acc.append(i)
            current_len += len(i) + 1
        return acc

    return limit_items(nuclear), limit_items(boundary), limit_items(bases)

class DomainFilter:
    """Encapsulates the pre-compiled regex objects for fast filtering."""
    def __init__(self, nuc, bnd, bases, burners):
        self.nuc_pat = re.compile(f"(?i){'|'.join(map(re.escape, nuc))}") if nuc else None
        self.bnd_pat = re.compile(f"(?i)(?:^|[\\.\\-])(?:{'|'.join(map(re.escape, bnd))})(?:[\\.\\-]|$)") if bnd else None
        self.dyn_pat = re.compile(f"(?i)(?:^|\\.)(?:{'|'.join([d.replace('.', r'\.') for d in bases])})$") if bases else None
        self.str_pat = re.compile(f"(?i)(?:{'|'.join(Config.STRUCTURAL_REGEX)})")
        self.burners = burners

    def is_valid(self, domain: str):
        domain = domain.strip().strip(".")
        if not domain or "." not in domain or IP_PATTERN.match(domain): return None
        
        root = get_base_domain(domain)
        if root in Config.SAFE_INFRA_DOMAINS and any(t in domain for t in Config.TELEMETRY_TRIGGERS):
            self.burners.add(domain)
            return None
        
        if self.nuc_pat and self.nuc_pat.search(domain): return None
        if self.bnd_pat and self.bnd_pat.search(domain): return None
        if self.dyn_pat and self.dyn_pat.search(domain): return None
        if self.str_pat.search(domain): return None
        
        return domain

# ---------------------------------------------------------------------------
# 4. Syncing Logic
# ---------------------------------------------------------------------------
def sync_regex_rule(cf, existing_rules, items, rule_name, rule_type):
    if not items: 
        return ""
    
    if rule_type == "nuclear":
        joined = "|".join(re.escape(k) for k in items)
        traffic = f'any(dns.domains[*] matches "(?i)({joined})")'
    elif rule_type == "boundary":
        joined = "|".join(re.escape(k) for k in items)
        traffic = f'any(dns.domains[*] matches "(?i)(?:^|[\\\\.\\\\-])({joined})(?:[\\\\.\\\\-]|$)")'
    elif rule_type == "structural":
        joined = "|".join(items)
        traffic = f'any(dns.domains[*] matches "(?i)({joined})")'
    elif rule_type == "base":
        joined = "|".join(re.escape(k) for k in items)
        traffic = f'any(dns.domains[*] matches "(?i)(^|\\\\.)({joined})$")'
    else:
        return ""
    
    payload = {"name": rule_name, "action": "block", "enabled": True, "filters": ["dns"], "traffic": traffic}
    existing = next((r for r in existing_rules if r["name"] == rule_name), None)
    
    if existing:
        if existing.get("traffic") != traffic: 
            logger.info(f"Updating regex rule: {rule_name}")
            cf.update_rule(existing["id"], payload)
    else: 
        logger.info(f"Creating regex rule: {rule_name}")
        cf.create_rule(payload)
        
    return rule_name

def sync_to_cloudflare(cf, existing_lists, existing_rules, domains, policy):
    if not domains: return [], []
    sorted_domains = sorted(domains)
    chunks = [sorted_domains[i : i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    
    policy_existing_lists = sorted([l for l in existing_lists if l["name"].startswith(policy["prefix"] + " ")], key=lambda x: x["name"])
    used_ids = []

    def process_chunk(idx, chunk):
        list_name = f"{policy['prefix']} {idx + 1:03d}"
        chunk_hash = hashlib.sha256(",".join(chunk).encode('utf-8')).hexdigest()
        items = [{"value": d} for d in chunk]
        
        if idx < len(policy_existing_lists):
            existing = policy_existing_lists[idx]
            if existing.get("description") == chunk_hash: 
                return existing["id"]
            cf.update_list(existing["id"], list_name, items, desc=chunk_hash)
            return existing["id"]
            
        res = cf.create_list(list_name, items, desc=chunk_hash)
        return res["result"]["id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
        futures = [executor.submit(process_chunk, i, c) for i, c in enumerate(chunks)]
        for f in concurrent.futures.as_completed(futures):
            used_ids.append(f.result())

    unused_lists = [l for l in policy_existing_lists if l["id"] not in used_ids]
    for old_list in unused_lists:
        logger.info(f"Deleting unused list: {old_list['name']}")
        cf.delete_list(old_list["id"])

    traffic = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in used_ids])
    payload = {"name": policy['policy_name'], "action": policy.get("action", "block"), "enabled": True, "filters": ["dns"], "traffic": traffic}
    
    if policy.get("identity_condition"): 
        payload["identity"] = policy["identity_condition"]
    
    existing_rule = next((r for r in existing_rules if r["name"] == policy['policy_name']), None)
    if existing_rule:
        if existing_rule.get("traffic") != traffic or existing_rule.get("identity") != payload.get("identity"):
            logger.info(f"Updating policy rule: {policy['policy_name']}")
            cf.update_rule(existing_rule["id"], payload)
    else: 
        logger.info(f"Creating policy rule: {policy['policy_name']}")
        cf.create_rule(payload)
        
    return used_ids, [policy['policy_name']]

def main():
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    sess = requests.Session()
    
    domains_by_list = {}
    all_raw_domains = set()

    logger.info("Fetching blocklists...")
    def fetch_url(url):
        try:
            r = sess.get(url, timeout=Config.REQUEST_TIMEOUT)
            r.raise_for_status()
            return {line.split()[-1].lower().strip().strip(".") for line in r.text.splitlines() if line and line[0] not in ("#", "!", "/")}
        except Exception as e: 
            logger.warning(f"Failed fetching {url}: {e}")
            return set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        future_to_name = {pool.submit(fetch_url, url): name for name, url in BLOCKLIST_URLS.items()}
        for f in concurrent.futures.as_completed(future_to_name):
            list_name = future_to_name[f]
            results = f.result()
            domains_by_list[list_name] = results
            all_raw_domains.update(results)

    logger.info(f"Running autonomous profiling on {len(all_raw_domains)} domains...")
    nuc, bnd, bases = run_autonomous_profiling(all_raw_domains)
    burner_subdomains = set()
    
    domain_filter = DomainFilter(nuc, bnd, bases, burner_subdomains)
    
    filtered_domains_by_list = {}
    for list_name, raw_domain_set in domains_by_list.items():
        valid_domains = set()
        for d in raw_domain_set:
            validated = domain_filter.is_valid(d)
            if validated: valid_domains.add(validated)
        filtered_domains_by_list[list_name] = valid_domains

    logger.info("Syncing Rules & Lists to Cloudflare...")
    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()
    
    sync_regex_rule(cf, existing_rules, nuc, "Block: AI Nuclear Keywords", "nuclear")
    sync_regex_rule(cf, existing_rules, bnd, "Block: AI Boundary Keywords", "boundary")
    sync_regex_rule(cf, existing_rules, bases, "Block: AI Dynamic Base Domains", "base")
    sync_regex_rule(cf, existing_rules, Config.STRUCTURAL_REGEX, "Block: AI Structural Heuristics", "structural")
    
    if burner_subdomains:
        sync_regex_rule(cf, existing_rules, sorted(list(burner_subdomains))[:50], "Block: AI Dynamic Burners", "base")

    for pol in POLICIES:
        policy_domains = set()
        for inc in pol.get("include", []):
            policy_domains.update(filtered_domains_by_list.get(inc, set()))
            
        for exc in pol.get("exclude", []):
            policy_domains.difference_update(filtered_domains_by_list.get(exc, set()))
            
        if policy_domains:
            sync_to_cloudflare(cf, existing_lists, existing_rules, policy_domains, pol)

    logger.info(f"Finished execution successfully in {time.perf_counter() - start:.2f}s.")

if __name__ == "__main__": 
    main()
