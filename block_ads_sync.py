import os
import re
import logging
import requests
import concurrent.futures
import time
import hashlib
import json
from collections import Counter
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# Global variables for the dynamically compiled filters
ALLOWED_DOMAINS = set()
CACHE_STATE_FILE = "cloudflare_sync_cache.json"

# ---------------------------------------------------------------------------
# 1. Config & Lists
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN               = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID              = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL           = os.environ.get("PRIMARY_EMAIL", "")   
    SECONDARY_EMAIL         = os.environ.get("SECONDARY_EMAIL", "")  
    WEBHOOK_URL             = os.environ.get("WEBHOOK_URL", "") # Add Discord/Slack/ntfy webhook here
    
    ACTIVE_TIER             = os.environ.get("ACTIVE_TIER", "pro++").strip().lower()
    
    # --- TOGGLES & THRESHOLDS ---
    ENABLE_TLD_KW_FILTERING = True
    HEURISTIC_THRESHOLD     = 150  # Subdomains required to trigger a regex rule offload
    DYNAMIC_KEYWORD_COUNT   = 10   # How many NSFW keywords to extract
    IGNORE_KEYWORDS         = {"www", "com", "net", "org", "info", "site", "co", "xyz", "online", "top", "web", "app", "link", "cam", "video", "free"}
    
    MAX_LIST_SIZE           = 1000
    MAX_RETRIES             = 5
    TOTAL_QUOTA             = 300_000
    REQUEST_TIMEOUT         = (5, 25)
    MAX_WORKERS             = 5

    SCRUB_TARGETS = ["Base", "Pro++", "Ultimate", "Social", "Block:", "Allow:", "L_"]

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
# 2. Cloudflare API Client & Webhook
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        retry = Retry(total=Config.MAX_RETRIES, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _request(self, method, endpoint, **kwargs):
        retries, delay = Config.MAX_RETRIES, 2
        while retries > 0:
            resp = self.session.request(method, f"{self.base_url}/{endpoint}", headers=self.headers, timeout=Config.REQUEST_TIMEOUT, **kwargs)
            if resp.status_code == 429:
                retries -= 1
                time.sleep(delay)
                delay *= 2 
                continue
            if not resp.ok: logger.error(f"Cloudflare API Error [{resp.status_code}]: {resp.text}")
            resp.raise_for_status()
            return resp.json()
        raise requests.exceptions.HTTPError("Exhausted retries due to Cloudflare API rate limits (429).")

    def get_lists(self): return self._request("GET", "lists").get("result") or []
    def get_rules(self): return self._request("GET", "rules").get("result") or []
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")
    def create_list(self, name, items, desc=""): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items, "description": desc})
    def update_list(self, lid, name, items, desc=""): return self._request("PUT", f"lists/{lid}", json={"name": name, "items": items, "description": desc})
    def create_rule(self, data): return self._request("POST", "rules", json=data)
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json=data)

def send_webhook(message: str):
    if not Config.WEBHOOK_URL: return
    try: requests.post(Config.WEBHOOK_URL, json={"content": message}, timeout=5)
    except Exception as e: logger.warning(f"Webhook failed: {e}")

# ---------------------------------------------------------------------------
# 3. Dynamic Analytics & Caching
# ---------------------------------------------------------------------------
def extract_heuristics(domains: set[str]) -> tuple[set[str], list[str]]:
    base_domains = [".".join(d.split(".")[-2:]) for d in domains if d.count(".") > 0]
    frequent_bases = [dom for dom, count in Counter(base_domains).items() if count >= Config.HEURISTIC_THRESHOLD]
    if not frequent_bases: return domains, []
        
    regex_pattern = re.compile(f"(?i)\\.?(?:{'|'.join(re.escape(b) for b in frequent_bases)})$")
    optimized_domains = {d for d in domains if not regex_pattern.search(d)}
    return optimized_domains, frequent_bases

def extract_dynamic_keywords(fetched_lists: dict) -> list[str]:
    nsfw_domains = fetched_lists.get("Hagezi NSFW", set())
    if not nsfw_domains: return []
        
    word_counts = Counter()
    for dom in nsfw_domains:
        for part in re.split(r'[\.\-0-9]', dom):
            part = part.lower()
            if len(part) >= 3 and part not in Config.IGNORE_KEYWORDS and part.isalpha():
                word_counts[part] += 1
                
    return [w for w, c in word_counts.most_common(Config.DYNAMIC_KEYWORD_COUNT)]

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
                        dom_cleaned = dom.strip().lower()
                        if dom_cleaned: ALLOWED_DOMAINS.add(dom_cleaned)
        return tlds
    except Exception as exc: logger.error(f"AdGuard TLD fetch failed: {exc}")
    return []

def fetch_url(session: requests.Session, name: str, url: str, cache: dict) -> tuple[str, set[str], dict]:
    headers = {}
    if url in cache and cache[url].get("etag"):
        headers["If-None-Match"] = cache[url]["etag"]

    try:
        resp = session.get(url, headers=headers, timeout=Config.REQUEST_TIMEOUT)
        if resp.status_code == 304:
            logger.info(f"[{name}] Cached (304 Not Modified). Skipping processing.")
            return name, set(cache[url]["domains"]), cache[url]
            
        resp.raise_for_status()
        valid_domains = set()
        
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"): continue
            domain = line.split()[-1].lower().strip(".")
            if not domain or any(c in domain for c in "*/[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain): continue
            
            if domain in ALLOWED_DOMAINS or any(domain.endswith("." + allowed) for allowed in ALLOWED_DOMAINS):
                valid_domains.add(domain) # Whitelisted, keep exact
            else:
                valid_domains.add(domain)
                
        logger.info(f"Fetched {name}: {len(valid_domains):,} domains")
        
        new_cache_entry = {
            "etag": resp.headers.get("etag") or resp.headers.get("last-modified"),
            "domains": list(valid_domains)
        }
        return name, valid_domains, new_cache_entry
    except Exception as exc:
        logger.error(f"Error fetching {name}: {exc}")
        return name, set(), {}

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
# 4. Cloudflare Sync & Rules
# ---------------------------------------------------------------------------
def sync_regex_rule(cf: CloudflareAPI, existing_rules: list, patterns: list[str], rule_name: str, isolate_edges: bool = False, precedence: int = None) -> str:
    if not patterns: return ""
    chunk_size = 50
    chunks = [patterns[i:i + chunk_size] for i in range(0, len(patterns), chunk_size)]
    expr_parts = []
    
    for chunk in chunks:
        regex_str = "|".join(chunk)
        if isolate_edges: expr_parts.append(f'any(dns.domains[*] matches "(?i)(^|[.-])(?:{regex_str})([.-]|$)")')
        else: expr_parts.append(f'any(dns.domains[*] matches "(?i)\\.?(?:{regex_str})$")')
        
    traffic_expr = " or ".join(expr_parts)
    existing_rule = next((r for r in existing_rules if r["name"] == rule_name), None)
    payload = {"name": rule_name, "action": "block", "enabled": True, "filters": ["dns"], "traffic": traffic_expr}
    if precedence: payload["precedence"] = precedence
    
    if existing_rule:
        if existing_rule.get("traffic") == traffic_expr: logger.info(f"Rule {rule_name} unchanged.")
        else: 
            cf.update_rule(existing_rule["id"], payload)
            logger.info(f"Rule updated: {rule_name}")
    else: 
        cf.create_rule(payload)
        logger.info(f"Rule created: {rule_name}")
    return rule_name

def sync_foundational_security(cf: CloudflareAPI, existing_rules: list) -> list[str]:
    """Proactively block NRDs, Threat Intel categories, and Punycode"""
    active_rules = []
    
    # 1. Threat Intel: 115=Malware, 135=Phishing, 153=Newly Seen, 160=Spyware, 83=Botnet, 17=Spam
    intel_expr = "any(dns.security_category[*] in {17 83 115 135 153 160})"
    intel_rule = next((r for r in existing_rules if r["name"] == "Block: Native Threat Intel & NRDs"), None)
    payload_intel = {"name": "Block: Native Threat Intel & NRDs", "action": "block", "enabled": True, "filters": ["dns"], "traffic": intel_expr, "precedence": 10}
    
    if intel_rule:
        if intel_rule.get("traffic") != intel_expr: cf.update_rule(intel_rule["id"], payload_intel)
    else: cf.create_rule(payload_intel)
    active_rules.append("Block: Native Threat Intel & NRDs")
    logger.info("Enforced Native Threat Intel & NRD rule.")

    # 2. Punycode strictly blocked
    puny_expr = 'any(dns.domains[*] matches "(?i).*xn--.*")'
    puny_rule = next((r for r in existing_rules if r["name"] == "Block: Punycode Domains"), None)
    payload_puny = {"name": "Block: Punycode Domains", "action": "block", "enabled": True, "filters": ["dns"], "traffic": puny_expr, "precedence": 15}
    
    if puny_rule:
        if puny_rule.get("traffic") != puny_expr: cf.update_rule(puny_rule["id"], payload_puny)
    else: cf.create_rule(payload_puny)
    active_rules.append("Block: Punycode Domains")
    logger.info("Enforced Punycode Strictness rule.")
    
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
            # Near-instant Delta Check: Only issue PUT if the chunk hash changed
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
    action = policy.get("action", "block")
    existing_rule = next((r for r in existing_rules if r["name"] == final_rule_name), None)

    payload = {"name": final_rule_name, "action": action, "enabled": True, "filters": ["dns"], "traffic": traffic_expr}
    if policy.get("identity_condition"): payload["identity"] = policy["identity_condition"]
    
    if existing_rule:
        if existing_rule.get("traffic") != traffic_expr or existing_rule.get("identity") != policy.get("identity_condition"):
            cf.update_rule(existing_rule["id"], payload)
            logger.info(f"Rule updated: {final_rule_name}")
    else: 
        cf.create_rule(payload)
        logger.info(f"Rule created: {final_rule_name}")
            
    return used_ids, [final_rule_name]

# ---------------------------------------------------------------------------
# 5. Main Execution
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    dl_session = requests.Session()
    dl_session.mount("https://", HTTPAdapter(max_retries=Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])))

    # 1. Load Local Cache State
    cache_state = {}
    if os.path.exists(CACHE_STATE_FILE):
        try:
            with open(CACHE_STATE_FILE, "r") as f: cache_state = json.load(f)
        except Exception as e: logger.warning(f"Cache read error: {e}")

    tlds_list = parse_adguard_tld_list(dl_session) if Config.ENABLE_TLD_KW_FILTERING else []

    # 2. Fetch Lists with ETag support
    fetched_lists = {}
    new_cache_state = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_url, dl_session, name, url, cache_state): name for name, url in BLOCKLIST_URLS.items()}
        for future in concurrent.futures.as_completed(futures):
            name, valid_set, list_cache = future.result()
            fetched_lists[name] = valid_set
            if list_cache: new_cache_state[BLOCKLIST_URLS[name]] = list_cache

    # Save Cache
    with open(CACHE_STATE_FILE, "w") as f: json.dump(new_cache_state, f)

    # 3. Process Dynamic Analytics (Keywords & Heuristics)
    top_keywords = extract_dynamic_keywords(fetched_lists) if Config.ENABLE_TLD_KW_FILTERING else []
    if top_keywords:
        kw_regex = re.compile(f"(?i)(?:^|[.-])(?:{'|'.join(top_keywords)})(?:[.-]|$)")
        for name, domains in fetched_lists.items():
            original_len = len(domains)
            fetched_lists[name] = {d for d in domains if not kw_regex.search(d)}
            if original_len - len(fetched_lists[name]) > 0:
                logger.info(f"Dynamic keywords offloaded {original_len - len(fetched_lists[name]):,} domains from {name}.")

    all_heuristic_patterns = set()
    for name, domain_set in fetched_lists.items():
        optimized_set, patterns = extract_heuristics(domain_set)
        fetched_lists[name] = optimized_set
        all_heuristic_patterns.update(patterns)

    compiled_policies = build_policy_sets(POLICIES, fetched_lists)
    optimized_allow_domains = optimize_domains(ALLOWED_DOMAINS) if ALLOWED_DOMAINS else []
    total_domains = sum(len(domains) for _, domains in compiled_policies) + len(optimized_allow_domains)

    if total_domains > Config.TOTAL_QUOTA:
        logger.error(f"Quota exceeded! {total_domains:,} domains.")
        send_webhook(f"⚠️ **Sync Failed:** Quota exceeded ({total_domains:,} domains).")
        return

    logger.info(f"Total domains to sync: {total_domains:,}. Proceeding...")

    # 4. Cloudflare Engine Sync
    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()

    # Pre-Cleanup
    valid_prefixes = tuple(p["prefix"] for p in POLICIES) + ("L_AllowTLD",)
    for lst in existing_lists[:]:
        if "IoT Bypass" in lst["name"]: continue
        if any(target in lst["name"] for target in Config.SCRUB_TARGETS):
            if not any(lst["name"].startswith(pfx + " ") for pfx in valid_prefixes):
                try: 
                    cf.delete_list(lst["id"]); existing_lists.remove(lst); logger.info(f"Pre-cleaned list: {lst['name']}")
                except Exception as e: pass

    all_active_list_ids, all_active_rule_names = [], []

    # Foundational Security Injection
    all_active_rule_names.extend(sync_foundational_security(cf, existing_rules))

    # TLD, Heuristic, and Keyword RegEx Offloads
    if Config.ENABLE_TLD_KW_FILTERING:
        allow_rule = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_allow_domains, {"prefix": "L_AllowTLD", "policy_name": "Allow: HaGeZi TLD Exceptions", "action": "allow"})
        all_active_list_ids.extend(allow_rule[0]); all_active_rule_names.extend(allow_rule[1])
        
        tld_rule = sync_regex_rule(cf, existing_rules, tlds_list, "Block: HaGeZi Most Abused TLDs")
        if tld_rule: all_active_rule_names.append(tld_rule)

        kw_rule = sync_regex_rule(cf, existing_rules, top_keywords, "Block: Dynamic NSFW Keywords", isolate_edges=True)
        if kw_rule: all_active_rule_names.append(kw_rule)

    if all_heuristic_patterns:
        heur_rule = sync_regex_rule(cf, existing_rules, list(all_heuristic_patterns), "Block: Heuristic High-Frequency Domains")
        if heur_rule: all_active_rule_names.append(heur_rule)

    # Core Policy Sync
    for policy, optimized_domains in compiled_policies:
        used_ids, rule_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_domains, policy)
        all_active_list_ids.extend(used_ids)
        all_active_rule_names.extend(rule_names)

    # Post-Cleanup & Rule Precedence Fixes
    for r in existing_rules:
        if "IoT Bypass" in r["name"] or "Custom" in r["name"] or "Keywords" in r["name"]: continue
        if r["name"] not in all_active_rule_names and any(target in r["name"] for target in Config.SCRUB_TARGETS):
            try: cf.delete_rule(r["id"]); logger.info(f"Deleted Orphaned Rule: {r['name']}")
            except: pass

    exec_time = time.perf_counter() - start
    logger.info(f"Sync completed in {exec_time:.2f} seconds.")
    send_webhook(f"✅ **Cloudflare DNS Sync Complete**\n- **Time:** {exec_time:.2f}s\n- **Synced Domains:** {total_domains:,}\n- **Dynamic Keywords:** {top_keywords}\n- **Heuristic Patterns:** {len(all_heuristic_patterns)}")

if __name__ == "__main__":
    main()
