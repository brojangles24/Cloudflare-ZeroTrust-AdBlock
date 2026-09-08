import concurrent.futures
import gzip
import hashlib
import io
import logging
import os
import re
import sys
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ---------------------------------------------------------------------------
# Config & Constants
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL = os.environ.get("PRIMARY_EMAIL", "")
    SECONDARY_EMAIL = os.environ.get("SECONDARY_EMAIL", "")
    TERTIARY_EMAIL = os.environ.get("TERTIARY_EMAIL", "")

    MAX_LIST_SIZE = 1000
    MAX_RETRIES = 5
    TOTAL_QUOTA = 300_000
    REQUEST_TIMEOUT = (5, 25)
    DOWNLOAD_TIMEOUT = 90
    MAX_WORKERS = 5

    PRECEDENCE = {
        "Allow: Spam Exceptions": 100,
        "Block: Relaxed Profile": 200,
        "Block: Restrictive Profile": 300,
    }

    MANAGED_LIST_PREFIXES = ("L_Relaxed ", "L_Restrictive ", "L_AllowSpam ")
    MANAGED_RULE_NAMES = set(PRECEDENCE.keys())

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL") if not getattr(cls, k)]
        if missing:
            raise EnvironmentError(f"Missing mandatory environment variables: {', '.join(missing)}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Patterns & Sources
# ---------------------------------------------------------------------------
IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|"
    r"^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|^(?:[A-Fa-f0-9]{1,4}:)*:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*$"
)

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)

BLOCKLIST_SOURCES = [
    {"name": "HaGeZi Normal", "url": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt"], "enable_relevance": True},
    {"name": "HaGeZi Pro", "url": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt"], "enable_relevance": True},
    {"name": "Hagezi NSFW", "url": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt", "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt"], "enable_relevance": True},
    {"name": "HaGeZi Badware", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt", "enable_relevance": True},
    {"name": "HaGeZi Fake", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt", "enable_relevance": True},
    {"name": "HaGeZi TIF Full", "url": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt"], "enable_relevance": True},
    {"name": "Cyber Threat Intel", "url": ["https://raw.githubusercontent.com/DNSBunker/CTI/refs/heads/main/domains.txt"], "enable_relevance": False},
    {"name": "HaGeZi Social", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt", "enable_relevance": True},
    {"name": "HaGeZi No SafeSearch", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt", "enable_relevance": True},
    {"name": "HaGeZi Bypass Prevention", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt", "enable_relevance": True},
    {"name": "HaGeZi Anti Piracy", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt", "enable_relevance": True},
    {"name": "HaGeZi DynDNS", "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt", "enable_relevance": True},
    {"name": "NoAI", "url": "https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt", "enable_relevance": True},
]

SPAM_ALLOW_SOURCE = {
    "name": "HaGeZi Spam Allow",
    "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-allow-onlydomains.txt",
    "enable_relevance": False
}

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
    ("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://builtwith.com/dl/builtwith-top1m.zip", 0, False, "zip"),
]

# ---------------------------------------------------------------------------
# Identity & Policies
# ---------------------------------------------------------------------------
excluded_emails = [e.strip().lower() for e in (Config.SECONDARY_EMAIL, Config.TERTIARY_EMAIL) if e.strip()]
TARGET_IDENTITY = f"not(identity.email in {{{' '.join(f'\"{e}\"' for e in excluded_emails)}}})" if excluded_emails else None

def get_active_policies():
    policies = [
        {
            "prefix": "L_Relaxed",
            "policy_name": "Block: Relaxed Profile",
            "action": "block",
            "identity_condition": None,
            "category_condition": "any(dns.security_category[*] in {178 80 187 83 176 175 117 131 134 153}) or any(dns.content_category[*] in {133})",
            "include": ["HaGeZi Normal", "Hagezi NSFW", "HaGeZi Badware", "HaGeZi Fake", "HaGeZi No SafeSearch", "HaGeZi TIF Full", "Cyber Threat Intel", "HaGeZi DynDNS", "HaGeZi Anti Piracy"],
            "exclude": [],
            "use_spam_tld": True,
        },
        {
            "prefix": "L_Restrictive",
            "policy_name": "Block: Restrictive Profile",
            "action": "block",
            "identity_condition": TARGET_IDENTITY,
            "category_condition": "any(dns.security_category[*] in {151 191 188 68}) or any(dns.content_category[*] in {67 125}) or any(app.ids[*] in {534 541 572 600 604 618 628 633 1110 1122 1130 1135 1138 1853 2678 2680 2826 2831 2844 2845 2848 2852 3097 3098}) or any(dns.domains[*] in {\"web.archive.org\" \"steamcommunity.com\" \"linkvertise.com\" \"vercel.com\"})",
            "include": ["HaGeZi Pro", "HaGeZi Bypass Prevention", "HaGeZi Social", "NoAI"],
            "exclude": ["HaGeZi Normal"],
            "use_spam_tld": False,
        }
    ]

    if any(p.get("use_spam_tld", False) for p in policies):
        policies.append({
            "prefix": "L_AllowSpam",
            "policy_name": "Allow: Spam Exceptions",
            "action": "allow",
            "identity_condition": None,
            "category_condition": None,
            "include": ["HaGeZi Spam Allow"],
            "exclude": [],
            "use_spam_tld": False,
        })
    return policies

# ---------------------------------------------------------------------------
# Cloudflare API Client
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.session = requests.Session()
        adapter = HTTPAdapter(pool_connections=Config.MAX_WORKERS, pool_maxsize=Config.MAX_WORKERS + 2, max_retries=Retry(total=0))
        self.session.mount("https://", adapter)

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        retries, delay = Config.MAX_RETRIES, 2
        while True:
            try:
                res = self.session.request(method, url, headers=self.headers, timeout=Config.REQUEST_TIMEOUT, **kwargs)
                if res.ok:
                    return res.json()
                if res.status_code not in (429, 500, 502, 503, 504):
                    res.raise_for_status()
            except requests.exceptions.RequestException:
                if retries < 0:
                    raise

            retries -= 1
            if retries < 0:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 60)

    def _get_paginated(self, endpoint):
        results, page = [], 1
        while True:
            resp = self._request("GET", f"{endpoint}?page={page}&per_page=100")
            results.extend(resp.get("result") or [])
            if page >= (resp.get("result_info") or {}).get("total_pages", 1):
                break
            page += 1
        return results

    def get_lists(self): return self._get_paginated("lists")
    def get_rules(self): return self._get_paginated("rules")
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")
    def create_list(self, name, items, desc=""): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items, "description": desc})
    def update_list(self, lid, name, items, desc=""): return self._request("PUT", f"lists/{lid}", json={"name": name, "items": items, "description": desc})
    def create_rule(self, data): return self._request("POST", "rules", json={**data, "rule_settings": {"block_page_enabled": False}})
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json={**data, "rule_settings": {"block_page_enabled": False}})

# ---------------------------------------------------------------------------
# Domain Logic & Relevance Filtering
# ---------------------------------------------------------------------------
def has_suffix_match(host: str, lookup_set: set[str]) -> bool:
    if host in lookup_set:
        return True
    parts = host.split(".")
    return any(".".join(parts[i:]) in lookup_set for i in range(1, len(parts)))

def is_valid_domain(domain: str) -> str | None:
    domain = domain.strip().lower()
    if not domain: return None
    if domain.startswith("*."): domain = domain[2:]
    if domain.startswith("||"):
        domain = domain[2:].split("^", 1)[0].split("$", 1)[0]
    domain = domain.strip(' \t\r\n"\'.,;')
    if not domain or any(c in domain for c in "/[]*|^$()=?\\") or IP_PATTERN.match(domain):
        return None
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return domain if DOMAIN_PATTERN.fullmatch(domain) else None

def parse_blocklist_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith(("#", "!", "/")):
        return None
    parts = line.split()
    if len(parts) >= 2 and IP_PATTERN.match(parts[0]):
        return is_valid_domain(parts[1])
    return is_valid_domain(parts[0])

def fetch_top_list(url, col_idx, skip_header, compression, session):
    try:
        r = session.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=Config.DOWNLOAD_TIMEOUT)
        r.raise_for_status()
        content = r.content
        
        if compression == "zip":
            with io.BytesIO(content) as b, io.zipfile.ZipFile(b) as z:
                name = next(n for n in z.namelist() if not n.endswith("/"))
                with z.open(name) as f, io.TextIOWrapper(f, encoding="utf-8", errors="ignore") as tf:
                    lines = tf.readlines()
        elif compression == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as gz, io.TextIOWrapper(gz, encoding="utf-8", errors="ignore") as tf:
                lines = tf.readlines()
        else:
            lines = r.text.splitlines()

        domains = set()
        for i, line in enumerate(lines):
            if skip_header and i == 0: continue
            parts = line.strip().split(",")
            if len(parts) > col_idx:
                if clean := is_valid_domain(parts[col_idx].strip()):
                    domains.add(clean)
        return url, domains
    except Exception as e:
        logger.warning(f"Failed fetching top list {url}: {e}")
        return url, set()

class RelevanceChecker:
    def __init__(self, session):
        self.master_allowlist = set()
        self.session = session

    def build_dataset(self, max_workers=5):
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(fetch_top_list, url, col, skip, comp, self.session) for url, col, skip, comp in TOP_LISTS]
            for f in concurrent.futures.as_completed(futures):
                url, domains = f.result()
                self.master_allowlist.update(domains)

    def is_relevant(self, domain: str) -> bool:
        clean = domain.lower().strip(".")
        if clean.startswith("www."): clean = clean[4:]
        return has_suffix_match(clean, self.master_allowlist)

def fetch_url(session, name, url, checker=None):
    kept, irrelevant = set(), 0
    urls = [url] if isinstance(url, str) else url
    for target in urls:
        resp = session.get(target, headers={"User-Agent": "Mozilla/5.0"}, timeout=Config.DOWNLOAD_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            if cleaned := parse_blocklist_line(line):
                if checker and not checker.is_relevant(cleaned):
                    irrelevant += 1
                else:
                    kept.add(cleaned)
    return name, kept, irrelevant

def fetch_raw_tlds(session):
    resp = session.get(SPAM_TLD_URL, headers={"User-Agent": "Mozilla/5.0"}, timeout=Config.DOWNLOAD_TIMEOUT)
    resp.raise_for_status()
    tlds = set()
    for line in resp.text.splitlines():
        val = line.strip().lower()
        if not val or val.startswith(("#", "!", "/")): continue
        if val.startswith("||"): val = val[2:]
        val = val.split("^", 1)[0].split("$", 1)[0].strip(" .")
        if val and "." not in val and "*" not in val and re.fullmatch(r"[a-z0-9-]{2,63}", val):
            tlds.add(val)
    if not tlds: raise RuntimeError("Spam TLD source returned zero usable TLDs.")
    return sorted(tlds)

def optimize_domains(domains: set[str]) -> list[str]:
    sorted_doms = sorted(domains, key=lambda d: d.split(".")[::-1])
    optimized, last = [], None
    for dom in sorted_doms:
        if last and dom.endswith("." + last): continue
        optimized.append(dom)
        last = dom
    return optimized

def build_policy_sets(policies_config, fetched_lists, spam_tlds):
    sets, spam_set = [], set(spam_tlds)
    base_household = fetched_lists.get("HaGeZi Normal", set())
    all_blocked = {d for name, doms in fetched_lists.items() if name != "HaGeZi Spam Allow" for d in doms}
    
    for policy in policies_config:
        p_set = set()
        for inc in policy.get("include", []):
            if inc in fetched_lists: p_set.update(fetched_lists[inc])
        for exc in policy.get("exclude", []):
            if exc in fetched_lists: p_set.difference_update(fetched_lists[exc])
            
        if policy.get("action") == "allow":
            p_set.difference_update(all_blocked)
        elif policy["prefix"] != "L_Normal" and "HaGeZi Normal" not in policy.get("include", []) and base_household:
            p_set = {dom for dom in p_set if not has_suffix_match(dom, base_household)}
            
        if policy.get("action") == "block" and spam_set:
            p_set = {dom for dom in p_set if dom.rsplit(".", 1)[-1] not in spam_set}
            
        sets.append((policy, optimize_domains(p_set)))
    return sets

# ---------------------------------------------------------------------------
# Cloudflare Sync & Cleanup
# ---------------------------------------------------------------------------
def sync_to_cloudflare(cf, existing_lists, existing_rules, domains, policy, raw_tld_expr=""):
    if not domains and not raw_tld_expr and not policy.get("category_condition"):
        return [], []

    policy_lists = sorted([l for l in existing_lists if l.get("name", "").startswith(policy["prefix"] + " ")], key=lambda x: x["name"])
    used_ids = []

    if domains:
        chunks = [domains[i:i + Config.MAX_LIST_SIZE] for i in range(0, len(domains), Config.MAX_LIST_SIZE)]
        def process_chunk(idx, chunk):
            list_name = f"{policy['prefix']} {idx + 1:03d}"
            chunk_hash = hashlib.sha256(",".join(chunk).encode()).hexdigest()
            items = [{"value": d} for d in chunk]
            if idx < len(policy_lists):
                existing = policy_lists[idx]
                if existing.get("description") == chunk_hash:
                    return existing["id"]
                cf.update_list(existing["id"], list_name, items, desc=chunk_hash)
                return existing["id"]
            return cf.create_list(list_name, items, desc=chunk_hash)["result"]["id"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            used_ids = list(executor.map(lambda args: process_chunk(*args), enumerate(chunks)))

    list_items = [f"any(dns.domains[*] in ${lid})" for lid in used_ids]
    if raw_tld_expr and policy.get("use_spam_tld", False):
        list_items.append(f"({raw_tld_expr})")
    if cat_expr := policy.get("category_condition"):
        list_items.append(cat_expr)

    cond = policy.get("identity_condition")
    if cond and "dns." in cond:
        traffic_expr = " or ".join(f"({cond} and {item})" for item in list_items)
        identity_expr = ""
    else:
        traffic_expr = " or ".join(list_items)
        identity_expr = cond or ""

    rule_name = policy["policy_name"]
    precedence = Config.PRECEDENCE[rule_name]
    existing_rule = next((r for r in existing_rules if r.get("name") == rule_name), None)

    payload = {
        "name": rule_name,
        "action": policy.get("action", "block"),
        "enabled": existing_rule.get("enabled", True) if existing_rule else True,
        "filters": ["dns"],
        "traffic": traffic_expr,
        "precedence": precedence,
    }
    if identity_expr: payload["identity"] = identity_expr

    if existing_rule:
        cf.update_rule(existing_rule["id"], payload)
    else:
        cf.create_rule(payload)

    return used_ids, [rule_name]

def detach_active_rules(cf, existing_rules, active_policies):
    detached = []
    for policy in active_policies:
        r_name = policy["policy_name"]
        if rule := next((r for r in existing_rules if r.get("name") == r_name), None):
            snapshot = {"id": rule["id"], "name": r_name, "action": rule.get("action", "block"), "enabled": rule.get("enabled", True), "filters": rule.get("filters", ["dns"]), "traffic": rule.get("traffic", ""), "precedence": rule.get("precedence"), "identity": rule.get("identity", "")}
            fallback = f"({policy['category_condition']})" if policy.get("category_condition") else 'any(dns.domains[*] == "detached.placeholder")'
            cf.update_rule(rule["id"], {"name": r_name, "action": rule.get("action", "block"), "enabled": rule.get("enabled", True), "filters": rule.get("filters", ["dns"]), "traffic": fallback, "precedence": Config.PRECEDENCE[r_name]})
            detached.append(snapshot)
    return detached

def cleanup_orphans(cf, existing_lists, existing_rules, active_list_ids, active_rule_names):
    for rule in existing_rules:
        if rule.get("name") in Config.MANAGED_RULE_NAMES and rule.get("name") not in active_rule_names:
            try: cf.delete_rule(rule["id"])
            except Exception: pass
    for lst in existing_lists:
        if any(lst.get("name", "").startswith(p) for p in Config.MANAGED_LIST_PREFIXES) and lst.get("id") not in active_list_ids:
            try: cf.delete_list(lst["id"])
            except Exception: pass

# ---------------------------------------------------------------------------
# Main Execution
# ---------------------------------------------------------------------------
def main():
    start = time.perf_counter()
    try:
        Config.validate()
        cf, active_policies = CloudflareAPI(), get_active_policies()
        
        active_sources = list(BLOCKLIST_SOURCES)
        if any("HaGeZi Spam Allow" in p.get("include", []) for p in active_policies):
            active_sources.append(SPAM_ALLOW_SOURCE)

        dl_session = requests.Session()
        dl_session.mount("https://", HTTPAdapter(pool_connections=Config.MAX_WORKERS, pool_maxsize=Config.MAX_WORKERS + 2, max_retries=Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])))

        checker = RelevanceChecker(dl_session)
        checker.build_dataset(max_workers=Config.MAX_WORKERS)
        
        tld_raw = fetch_raw_tlds(dl_session)
        tld_expr = f'any(dns.domains[*] matches "(?i)\\.({"|".join(re.escape(t) for t in tld_raw)})$")' if tld_raw else ""

        fetched_lists = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            futures = {pool.submit(fetch_url, dl_session, s["name"], s["url"], checker if s.get("enable_relevance") else None): s for s in active_sources}
            for f in concurrent.futures.as_completed(futures):
                name, kept, _ = f.result()
                fetched_lists[name] = kept

        compiled = build_policy_sets(active_policies, fetched_lists, tld_raw)
        total_doms = sum(len(doms) for _, doms in compiled)
        if total_doms > Config.TOTAL_QUOTA:
            logger.critical("Payload exceeds quota.")
            return 1

        existing_lists, existing_rules = cf.get_lists(), cf.get_rules()
        snapshots = detach_active_rules(cf, existing_rules, active_policies)

        try:
            all_ids, all_rules = [], []
            for policy, optimized in compiled:
                t_expr = tld_expr if policy.get("use_spam_tld") else ""
                u_ids, r_names = sync_to_cloudflare(cf, existing_lists, existing_rules, optimized, policy, raw_tld_expr=t_expr)
                all_ids.extend(u_ids)
                all_rules.extend(r_names)
            cleanup_orphans(cf, existing_lists, existing_rules, all_ids, all_rules)
        except Exception as e:
            logger.critical(f"Sync failed: {e}")
            for snap in snapshots:
                cf.update_rule(snap["id"], {k: v for k, v in snap.items() if k != "id"})
            return 1

        logger.info(f"Sync complete in {time.perf_counter() - start:.2f}s with {total_doms:,} domains.")
        return 0
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```[cite: 1]
