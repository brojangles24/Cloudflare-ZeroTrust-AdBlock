import os
import re
import logging
import requests
import concurrent.futures
import time
import hashlib
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
    
    # Reads the tier from GitHub Variables. Defaults to "pro++" if missing.
    ACTIVE_TIER             = os.environ.get("ACTIVE_TIER", "pro++").strip().lower()
    
    # --- TOGGLES ---
    ENABLE_TLD_KW_FILTERING = True
    
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
        "Social",
        "Block:",
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

# User-Defined Regex for aggressive TLD and anywhere-keyword filtering
FILTER_PATTERN = re.compile(
    r"(?i)(\.(tk|ml|ga|cf|gq|pw|sbs|icu|top|xin|gdn|bid|cfd|monster|stream|webcam|download|zip|mov|bond|lol|quest|surf|casa|date)$)|(blowjob|threesome|gangbang|deepthroat|bukkake|titfuck|shemale|onlyfans|pornhub|xvideos|xnxx|porn|xxx|sex|adult)"
)

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

# Base policies that ALWAYS apply (NSFW Added Back In)
POLICIES = [
    {
        "prefix": "L_Pro",
        "policy_name": "Block: HaGeZi Pro Mini",
        "identity_condition": None,
        "include": ["HaGeZi Pro Mini"],
        "exclude": []
    },
    {
        "prefix": "L_NSFW",
        "policy_name": "Block: HaGeZi NSFW",
        "identity_condition": None,
        "include": ["Hagezi NSFW"],
        "exclude": []
    },
    {
        "prefix": "L_Fake",
        "policy_name": "Block: HaGeZi Fake",
        "identity_condition": None,
        "include": ["HaGeZi Fake"],
        "exclude": []
    },
    {
        "prefix": "L_NoSafe",
        "policy_name": "Block: HaGeZi Safesearch Not Support",
        "identity_condition": None,
        "include": ["HaGeZi Safesearch Not Support"],
        "exclude": []
    },
    {
        "prefix": "L_Bypass",
        "policy_name": "Block: HaGeZi Bypass Block",
        "identity_condition": None,
        "include": ["HaGeZi Bypass Block"],
        "exclude": []
    },
    {
        "prefix": "L_AntiPiracy",
        "policy_name": "Block: HaGeZi Anti Piracy",
        "identity_condition": None,
        "include": ["HaGeZi Anti Piracy"],
        "exclude": []
    },
    {
        "prefix": "L_DynDNS",
        "policy_name": "Block: HaGeZi Dynamic DNS",
        "identity_condition": None,
        "include": ["HaGeZi Dynamic DNS"],
        "exclude": []
    },
    {
        "prefix": "L_Social",
        "policy_name": "Block: HaGeZi Social (Primary Only)",
        "identity_condition": f'identity.email == "{Config.PRIMARY_EMAIL}"', 
        "include": ["HaGeZi Social"],
        "exclude": []
    },
    {
        "prefix": "L_TIF",
        "policy_name": "Block: HaGeZi TIF Mini",
        "identity_condition": None,
        "include": ["HaGeZi TIF Mini"],
        "exclude": []
    },
]


# Dynamically inject the correct Tier Delta based on GitHub Variables
if Config.ACTIVE_TIER == "pro++":
    POLICIES.append({
        "prefix": "L_ProPlus",
        "policy_name": "Block: HaGeZi Pro++ Mini (Except Secondary)",
        "identity_condition": f'not(identity.email == "{Config.SECONDARY_EMAIL}")',
        "include": ["HaGeZi Pro++ Mini"],
        "exclude": ["HaGeZi Pro Mini"] 
    })
    logger.info("Active Tier set to: Pro++")
    
elif Config.ACTIVE_TIER == "ultimate":
    POLICIES.append({
        "prefix": "L_Ultimate",
        "policy_name": "Block: HaGeZi Ultimate Mini (Except Secondary)",
        "identity_condition": f'not(identity.email == "{Config.SECONDARY_EMAIL}")',
        "include": ["HaGeZi Ultimate Mini"],
        "exclude": ["HaGeZi Pro Mini"] 
    })
    logger.info("Active Tier set to: Ultimate")

else:
    logger.info("Active Tier set to: Pro. No delta list required.")


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
    def create_list(self, name, items, desc=""):              return self._request("POST",   "lists",          json={"name": name, "type": "DOMAIN", "items": items, "description": desc})
    def update_list(self, lid, name, items, desc=""):         return self._request("PUT",    f"lists/{lid}",   json={"name": name, "items": items, "description": desc})
    def create_rule(self, data):                              return self._request("POST",   "rules",          json=data)
    def update_rule(self, rid, data):                         return self._request("PUT",    f"rules/{rid}",   json=data)

# ---------------------------------------------------------------------------
# 3. Domain Logic
# ---------------------------------------------------------------------------
def is_valid_domain(domain: str) -> tuple[str | None, bool]:
    domain = domain.strip().strip(".")
    if not domain or any(c in domain for c in "*/[]") or "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None, False
    
    if Config.ENABLE_TLD_KW_FILTERING:
        if FILTER_PATTERN.search(domain):
            return None, True # Returns True indicating it was successfully offloaded by our custom filter
            
    return domain, False

def fetch_url(session: requests.Session, name: str, url: str) -> tuple[str, set[str], int]:
    valid_domains = set()
    offloaded_count = 0
    
    try:
        resp = session.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"): continue
            
            cleaned, is_offloaded = is_valid_domain(line.split()[-1].lower())
            
            if cleaned: 
                valid_domains.add(cleaned)
            elif is_offloaded:
                offloaded_count += 1
                
        logger.info(f"Fetched {name}: {len(valid_domains):,} domains (Offloaded: {offloaded_count:,})")
    except Exception as exc:
        logger.error(f"Error fetching {name}: {exc}")
        
    return name, valid_domains, offloaded_count

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
def sync_to_cloudflare(cf: CloudflareAPI, existing_lists: list[dict], existing_rules: list[dict], domains: list[str], policy: dict) -> tuple[list[str], str]:
    if not domains: return [], None
    sorted_domains = sorted(domains)
    chunks = [sorted_domains[i : i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)]
    
    policy_existing_lists = sorted([l for l in existing_lists if policy["prefix"] in l["name"]], key=lambda x: x["name"])
    
    def process_chunk(idx: int, chunk: list[str]) -> str:
        list_name = f"{policy['prefix']} {idx + 1:03d}"
        chunk_hash = hashlib.sha256(",".join(chunk).encode('utf-8')).hexdigest()
        items = [{"value": d} for d in chunk]
        
        if idx < len(policy_existing_lists):
            existing = policy_existing_lists[idx]
            if existing.get("description") == chunk_hash:
                return existing["id"]
            
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
    
    existing_rule = next((r for r in existing_rules if r["name"] == policy["policy_name"]), None)
    is_enabled = existing_rule.get("enabled", True) if existing_rule else True

    payload = {"name": policy["policy_name"], "action": "block", "enabled": is_enabled, "filters": ["dns"], "traffic": traffic_expr}
    
    if policy.get("identity_condition"):
        payload["identity"] = policy["identity_condition"]
    
    if existing_rule:
        if existing_rule.get("traffic") == traffic_expr and existing_rule.get("identity") == policy.get("identity_condition") and existing_rule.get("enabled") == is_enabled:
            logger.info(f"Firewall rule {policy['policy_name']} unchanged. Skipping update.")
        else:
            cf.update_rule(existing_rule["id"], payload)
            logger.info(f"Firewall rule updated: {policy['policy_name']}")
    else: 
        cf.create_rule(payload)
        logger.info(f"Firewall rule created: {policy['policy_name']}")

    return used_ids, policy["policy_name"]

def cleanup_orphans(cf: CloudflareAPI, existing_lists: list[dict], existing_rules: list[dict], active_list_ids: list[str], active_rule_names: list[str]):
    logger.info("Running post-sync cleanup of orphaned resources...")
    
    for r in existing_rules:
        if "IoT Bypass" in r["name"]: continue
        if r["name"] not in active_rule_names and any(target in r["name"] for target in Config.SCRUB_TARGETS):
            try:
                cf.delete_rule(r["id"])
                logger.info(f"Deleted Orphaned Rule: {r['name']}")
            except Exception as e:
                logger.error(f"Could not delete rule {r['name']}: {e}")

    for l in existing_lists:
        if "IoT Bypass" in l["name"]: continue
        if l["id"] not in active_list_ids and any(target in l["name"] for target in Config.SCRUB_TARGETS):
            try:
                cf.delete_list(l["id"])
                logger.info(f"Deleted Orphaned List: {l['name']}")
            except Exception as e:
                logger.error(f"Could not delete list {l['name']}: {e}")

# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()
    Config.validate()
    cf = CloudflareAPI()
    
    download_session = requests.Session()
    dl_retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    download_session.mount("https://", HTTPAdapter(max_retries=dl_retry))

    fetched_lists = {}
    total_offloaded = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {pool.submit(fetch_url, download_session, name, url): name for name, url in BLOCKLIST_URLS.items()}
        for future in concurrent.futures.as_completed(futures):
            name, valid_set, offloaded_count = future.result()
            fetched_lists[name] = valid_set
            total_offloaded += offloaded_count

    compiled_policies = build_policy_sets(POLICIES, fetched_lists)
    total_domains = sum(len(domains) for _, domains in compiled_policies)

    if total_domains > Config.TOTAL_QUOTA:
        logger.error(f"Total domains ({total_domains:,}) exceeds {Config.TOTAL_QUOTA:,} quota! Aborting script.")
        return

    logger.info(f"Total domains offloaded by Regex filter: {total_offloaded:,}")
    logger.info(f"Total domains to sync to Cloudflare: {total_domains:,}. Proceeding...")

    # Take a single global snapshot
    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()

    # --- SMART PRE-CLEANUP ---
    valid_prefixes = tuple(p["prefix"] for p in POLICIES)
    valid_rule_names = set(p["policy_name"] for p in POLICIES)

    logger.info("Scanning for abandoned policies to clear room for new ones...")
    for rule in existing_rules[:]:
        if "IoT Bypass" in rule["name"]: continue
        if any(target in rule["name"] for target in Config.SCRUB_TARGETS):
            if rule["name"] not in valid_rule_names:
                try:
                    cf.delete_rule(rule["id"])
                    existing_rules.remove(rule)
                    logger.info(f"Pre-cleaned abandoned rule: {rule['name']}")
                except Exception as e:
                    logger.error(f"Could not delete abandoned rule {rule['name']}: {e}")

    for lst in existing_lists[:]:
        if "IoT Bypass" in lst["name"]: continue
        if any(target in lst["name"] for target in Config.SCRUB_TARGETS):
            if not any(lst["name"].startswith(pfx) for pfx in valid_prefixes):
                try:
                    cf.delete_list(lst["id"])
                    existing_lists.remove(lst)
                    logger.info(f"Pre-cleaned abandoned list: {lst['name']}")
                except Exception as e:
                    logger.error(f"Could not delete abandoned list {lst['name']}: {e}")
    # -------------------------

    all_active_list_ids = []
    all_active_rule_names = []

    for policy, optimized_domains in compiled_policies:
        used_ids, rule_name = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized_domains, policy)
        if rule_name:  
            all_active_list_ids.extend(used_ids)
            all_active_rule_names.append(rule_name)

    cleanup_orphans(cf, existing_lists, existing_rules, all_active_list_ids, all_active_rule_names)

    logger.info(f"Total time: {time.perf_counter() - start:.2f} seconds.")

if __name__ == "__main__":
    main()
