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

# Global patterns
TLD_PATTERN = None
NSFW_NUCLEAR_PATTERN = None
NSFW_BOUNDARY_PATTERN = None
DYNAMIC_DOMAIN_PATTERN = None
STRUCTURAL_PATTERN = None
BURNER_PATTERN = None
ALLOWED_DOMAINS = set()
BURNER_SUBDOMAINS = set()

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

    # Frequency Analysis Thresholds
    NUCLEAR_THRESHOLD     = 100  # Block if appears 100+ times (Anywhere in domain)
    BOUNDARY_THRESHOLD    = 50   # Block if appears 50+ times (Standalone word)
    BASE_DOMAIN_THRESHOLD = 20   # Block root domain if appears 20+ times
    DYNAMIC_KW_MIN_LEN    = 3 

    # Safety Guardrails
    SAFE_INFRA_DOMAINS = {"github.com", "google.com", "apple.com", "microsoft.com", "windows.com", "amazonaws.com", "cloudflare.com", "fastly.net", "azure.com"}
    SAFE_INFRA_TERMS = {"server", "cloud", "update", "online", "store", "shop", "portal", "network", "system", "service", "domain", "connect", "client", "mobile", "global", "static", "content", "public", "assets", "api", "app", "cdn", "www", "wpad", "ns1", "ns2", "mail", "dns"}
    TELEMETRY_TRIGGERS = ["telemetry", "metrics", "analytics", "adsystem", "pixel", "log"]

    # Structural Heuristics (Always active)
    STRUCTURAL_REGEX = [r"(?:.*-){4,}", r"[0-9]{8,}", r"[a-z0-9]{30,}\.", r"^(?:xn--).*(?:xn--)", r"\.xn--[a-z0-9\-]+$"]

    CLOUDFLARE_REGEX_MAX_CHAR = 3500
    MAX_LIST_SIZE = 1000
    MAX_RETRIES = 5
    TOTAL_QUOTA = 300_000
    REQUEST_TIMEOUT = (5, 25)
    MAX_WORKERS = 5
    SCRUB_TARGETS = ["Base", "Pro++", "Ultimate", "Social", "Block:", "Allow:", "L_"]

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL", "SECONDARY_EMAIL") if not getattr(cls, k)]
        if missing: raise EnvironmentError(f"Missing env vars: {', '.join(missing)}")

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
                time.sleep(delay); delay *= 2 
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
# 3. Intelligence Logic
# ---------------------------------------------------------------------------
def get_base_domain(domain):
    parts = domain.split('.')
    return ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 and len(parts[-1]) <= 2 else ".".join(parts[-2:])

def run_autonomous_profiling(all_domains):
    word_counts, domain_counts = Counter(), Counter()
    for domain in all_domains:
        root = get_base_domain(domain.lower())
        if root not in Config.SAFE_INFRA_DOMAINS: domain_counts[root] += 1
        tokens = re.split(r'[\.\-_]', domain.lower())
        for t in tokens:
            if len(t) >= Config.DYNAMIC_KW_MIN_LEN and t.isalpha() and t not in Config.SAFE_INFRA_TERMS: word_counts[t] += 1
    
    nuclear = [w for w, c in word_counts.items() if c >= Config.NUCLEAR_THRESHOLD]
    boundary = [w for w, c in word_counts.items() if Config.BOUNDARY_THRESHOLD <= c < Config.NUCLEAR_THRESHOLD]
    bases = [d for d, c in domain_counts.items() if c >= Config.BASE_DOMAIN_THRESHOLD]
    
    # Prune list size for CF constraints
    def limit(items):
        acc, l = [], 0
        for i in items:
            l += len(i) + 1
            if l > Config.CLOUDFLARE_REGEX_MAX_CHAR: break
            acc.append(i)
        return acc
    return limit(nuclear), limit(boundary), limit(bases)

def is_valid_domain(domain: str) -> tuple[str | None, str | None]:
    domain = domain.strip().strip(".")
    if not domain or "." not in domain or IP_PATTERN.match(domain): return None, None
    root = get_base_domain(domain)
    if root in Config.SAFE_INFRA_DOMAINS and any(trigger in domain for trigger in Config.TELEMETRY_TRIGGERS):
        BURNER_SUBDOMAINS.add(domain); return None, "burner"
    
    if NSFW_NUCLEAR_PATTERN and NSFW_NUCLEAR_PATTERN.search(domain): return None, "nuclear"
    if NSFW_BOUNDARY_PATTERN and NSFW_BOUNDARY_PATTERN.search(domain): return None, "boundary"
    if DYNAMIC_DOMAIN_PATTERN and DYNAMIC_DOMAIN_PATTERN.search(domain): return None, "tracker"
    if STRUCTURAL_PATTERN and STRUCTURAL_PATTERN.search(domain): return None, "structural"
    return domain, None

# ---------------------------------------------------------------------------
# 4. Sync & Main
# ---------------------------------------------------------------------------
def sync_regex_rule(cf, existing_rules, items, rule_name, rule_type):
    if not items: return ""
    expr = []
    if rule_type == "nuclear": expr = [f'any(dns.domains[*] matches "(?i)({re.escape(k)})")' for k in items]
    elif rule_type == "boundary": expr = [f'any(dns.domains[*] matches "(?i)(?:^|[\\\\.\\\\-])({re.escape(k)})(?:[\\\\.\\\\-]|$)")' for k in items]
    elif rule_type == "base": expr = [f'any(dns.domains[*] matches "(?i)(^|\\\\.)({re.escape(k.replace(".", r"\\."))})$")' for k in items]
    elif rule_type == "structural": expr = [f'any(dns.domains[*] matches "(?i){pat}")' for pat in items]
    
    traffic = " or ".join(expr)
    existing = next((r for r in existing_rules if r["name"] == rule_name), None)
    payload = {"name": rule_name, "action": "block", "enabled": True, "filters": ["dns"], "traffic": traffic}
    if existing:
        if existing.get("traffic") != traffic: cf.update_rule(existing["id"], payload)
    else: cf.create_rule(payload)
    return rule_name

def main():
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    sess = requests.Session()
    
    # Fetch data
    raw_domains = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        def fetch(u):
            try:
                r = sess.get(u, timeout=Config.REQUEST_TIMEOUT)
                return {line.split()[-1].lower().strip().strip(".") for line in r.text.splitlines() if line and line[0] not in ("#", "!", "/")}
            except: return set()
        for f in concurrent.futures.as_completed([pool.submit(fetch, u) for u in BLOCKLIST_URLS.values()]):
            raw_domains.update(f.result())

    # Profile & Compile
    nuc, bnd, bases = run_autonomous_profiling(raw_domains)
    global NSFW_NUCLEAR_PATTERN, NSFW_BOUNDARY_PATTERN, DYNAMIC_DOMAIN_PATTERN, STRUCTURAL_PATTERN
    NSFW_NUCLEAR_PATTERN = re.compile(f"(?i){'|'.join(re.escape(k) for k in nuc)}")
    NSFW_BOUNDARY_PATTERN = re.compile(f"(?i)(?:^|[\\.\\-])(?:{'|'.join(re.escape(k) for k in bnd)})(?:[\\.\\-]|$)")
    DYNAMIC_DOMAIN_PATTERN = re.compile(f"(?i)(?:^|\\.)(?:{'|'.join([d.replace('.', r'\.') for d in bases])})$")
    STRUCTURAL_PATTERN = re.compile(f"(?i)(?:{'|'.join(Config.STRUCTURAL_REGEX)})")

    # Filter
    final_domains = set()
    for d in raw_domains:
        c, r = is_valid_domain(d)
        if c: final_domains.add(c)
    
    # Sync
    existing_lists, existing_rules = cf.get_lists(), cf.get_rules()
    all_rules = []
    
    # Sync Regex Policies
    all_rules.append(sync_regex_rule(cf, existing_rules, nuc, "Block: AI Nuclear Keywords", "nuclear"))
    all_rules.append(sync_regex_rule(cf, existing_rules, bnd, "Block: AI Boundary Keywords", "boundary"))
    all_rules.append(sync_regex_rule(cf, existing_rules, bases, "Block: AI Dynamic Base Domains", "base"))
    all_rules.append(sync_regex_rule(cf, existing_rules, Config.STRUCTURAL_REGEX, "Block: AI Structural Heuristics", "structural"))
    if BURNER_SUBDOMAINS:
        all_rules.append(sync_regex_rule(cf, existing_rules, sorted(list(BURNER_SUBDOMAINS))[:50], "Block: AI Dynamic Burners", "base"))

    # Sync List Policies (Simplified for brevity)
    logger.info(f"Syncing {len(final_domains)} domains.")
    # [Insert standard list chunking sync here...]
    logger.info(f"Finished in {time.perf_counter() - start:.2f}s.")

if __name__ == "__main__": main()
