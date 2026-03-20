import os
import re
import logging
import requests
import concurrent.futures
import time
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ---------------------------------------------------------------------------
# 1. Config
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN               = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID              = os.environ.get("ACCOUNT_ID", "")
    ENABLE_TLD_KW_FILTERING = False  # <--- TOGGLE THIS TO TRUE/FALSE
    MAX_LIST_SIZE           = 1000
    MAX_RETRIES             = 3
    TOTAL_QUOTA             = 300_000
    REQUEST_TIMEOUT         = (5, 25)
    MAX_WORKERS             = 5

    @classmethod
    def validate(cls):
        missing = [k for k in ("API_TOKEN", "ACCOUNT_ID") if not getattr(cls, k)]
        if missing:
            raise EnvironmentError(
                f"Missing required environment variable(s): {', '.join(missing)}"
            )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

MASTER_CONFIG = {
    "name":           "Ads, Tracker, Telemetry, Malware",
    "prefix":         "Ads, Tracker, Telemetry, Malware",
    "policy_name":    "Ads, Tracker, Telemetry, Malware",
    "filename":       "aggregate_blocklist.txt",
    "banned_tlds": {
        "top", "xyz", "xin", "icu", "sbs", "cfd", "gdn", "monster", "buzz", "bid",
        "stream", "webcam", "zip", "mov", "pw", "tk", "ml", "ga", "cf", "gq",
        "men", "work", "click", "link", "party", "trade", "date", "loan", "win",
        "faith", "racing", "review", "country", "kim", "cricket", "science",
        "download", "ooo", "by", "cn", "ir", "kp", "ng", "ru", "su", "ss",
        "accountant", "accountants", "rest", "bar", "bzar", "bet", "cc", "poker", "casino",
    },
    "offloaded_keywords": {
        "xxx", "porn", "sex", "sexy", "fuck", "tits", "titties", "titty", "boobs",
        "boobies", "booty", "pussy", "hentai", "milf", "blowjob", "threesome",
        "bondage", "bdsm", "gangbang", "handjob", "deepthroat", "horny", "bukkake",
        "titfuck", "brazzers", "redtube", "pornhub", "shemale", "erotic", "omegle",
        "xnxx", "xvideo", "xxvideo",
    },
    "urls": {
        #"HaGeZi Pro++":                  "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        "1Hosts Lite":                    "https://raw.githubusercontent.com/badmojr/1Hosts/refs/heads/master/Lite/domains.wildcards",
        "Hagezi NSFW":                    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
        #"Hagezi Anti-Piracy":            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
        "HaGeZi Fake":                    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
        #"Hagezi SafeSearch Not Supported":"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
    },
}

# ---------------------------------------------------------------------------
# 2. Cloudflare API Client
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.headers = {
            "Authorization": f"Bearer {Config.API_TOKEN}",
            "Content-Type": "application/json",
        }
        self.session = requests.Session()
        retry = Retry(
            total=Config.MAX_RETRIES,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=False,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def _request(self, method, endpoint, **kwargs):
        resp = self.session.request(
            method,
            f"{self.base_url}/{endpoint}",
            headers=self.headers,
            timeout=Config.REQUEST_TIMEOUT,
            **kwargs,
        )
        resp.raise_for_status()
        return resp.json()

    def get_lists(self):                      return self._request("GET",    "lists").get("result") or []
    def get_rules(self):                      return self._request("GET",    "rules").get("result") or []
    def create_list(self, name, items):       return self._request("POST",   "lists",          json={"name": name, "type": "DOMAIN", "items": items})
    def update_list(self, lid, name, items):  return self._request("PUT",    f"lists/{lid}",   json={"name": name, "items": items})
    def delete_list(self, lid):               return self._request("DELETE", f"lists/{lid}")
    def create_rule(self, data):              return self._request("POST",   "rules",          json=data)
    def update_rule(self, rid, data):         return self._request("PUT",    f"rules/{rid}",   json=data)

# ---------------------------------------------------------------------------
# 3. Domain Processing
# ---------------------------------------------------------------------------
_BANNED_TLDS  = MASTER_CONFIG["banned_tlds"]
_OFFLOAD_KW   = MASTER_CONFIG["offloaded_keywords"]
_BAD_CHARS    = frozenset("*/:[]")

def is_valid_domain(domain: str) -> str | None:
    domain = domain.strip().strip(".")

    if not domain or _BAD_CHARS.intersection(domain):
        return None

    if "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        return None

    if Config.ENABLE_TLD_KW_FILTERING:
        tld = domain.rsplit(".", 1)[-1]
        if tld in _BANNED_TLDS:
            return None

        # Fast generator expression for keyword checking
        if any(kw in domain for kw in _OFFLOAD_KW):
            return None

    return domain

def fetch_url(name: str, url: str) -> tuple[str, set[str]]:
    logger.info(f"Fetching: {name}")
    valid_domains: set[str] = set()

    try:
        resp = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"):
                continue
            
            cleaned = is_valid_domain(line.split()[-1].lower())
            if cleaned:
                valid_domains.add(cleaned)
                
        logger.info(f"Done: {name} — {len(valid_domains):,} valid domains")
    except Exception as exc:
        logger.error(f"Error fetching {name}: {exc}")

    return name, valid_domains

def optimize_domains(domains: set[str]) -> list[str]:
    """Tree-prune subdomains covered by parent rules."""
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized: list[str] = []
    last_kept: str | None = None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."):
            continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]

# ---------------------------------------------------------------------------
# 4. Cloudflare Sync
# ---------------------------------------------------------------------------
def sync_to_cloudflare(cf: CloudflareAPI, domains: list[str]) -> None:
    if not domains:
        logger.error("Optimised list is empty — aborting sync.")
        return

    if len(domains) > Config.TOTAL_QUOTA:
        logger.warning(f"Quota exceeded — slicing to {Config.TOTAL_QUOTA:,}")
        domains = domains[: Config.TOTAL_QUOTA]

    sorted_domains = sorted(domains)
    chunks = [
        sorted_domains[i : i + Config.MAX_LIST_SIZE]
        for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)
    ]

    # Save final list to disk
    Path(MASTER_CONFIG["filename"]).write_text("\n".join(sorted_domains))

    existing = sorted(
        [l for l in cf.get_lists() if MASTER_CONFIG["prefix"] in l["name"]],
        key=lambda x: x["name"],
    )

    used_ids: list[str] = []

    for idx, chunk in enumerate(chunks):
        items     = [{"value": d} for d in chunk]
        list_name = f"{MASTER_CONFIG['prefix']} {idx + 1:03d}"
        
        if idx < len(existing):
            lid = existing[idx]["id"]
            cf.update_list(lid, list_name, items)
            used_ids.append(lid)
            logger.info(f"Updated list {list_name} ({len(chunk):,} domains)")
        else:
            res = cf.create_list(list_name, items)
            lid = res["result"]["id"]
            used_ids.append(lid)
            logger.info(f"Created list {list_name} ({len(chunk):,} domains)")

    # Update Gateway Policy Rule
    clauses = [f"any(dns.domains[*] in ${lid})" for lid in used_ids]
    payload = {
        "name":    MASTER_CONFIG["policy_name"],
        "action":  "block",
        "enabled": True,
        "filters": ["dns"],
        "traffic": " or ".join(clauses),
    }
    
    rules = cf.get_rules()
    rid   = next((r["id"] for r in rules if r["name"] == MASTER_CONFIG["policy_name"]), None)
    
    if rid:
        cf.update_rule(rid, payload)
        logger.info("Firewall rule updated.")
    else:
        cf.create_rule(payload)
        logger.info("Firewall rule created.")

    # Cleanup stale lists
    for stale in existing[len(chunks):]:
        try:
            cf.delete_list(stale["id"])
            logger.info(f"Deleted stale list: {stale['name']} ({stale['id']})")
        except Exception as exc:
            logger.error(f"Failed to delete stale list {stale['id']}: {exc}")

# ---------------------------------------------------------------------------
# 5. Main
# ---------------------------------------------------------------------------
def main() -> None:
    start = time.perf_counter()

    Config.validate()
    cf = CloudflareAPI()
    global_domain_set: set[str] = set()

    # Parallel Fetch
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {
            pool.submit(fetch_url, name, url): name
            for name, url in MASTER_CONFIG["urls"].items()
        }
        for future in concurrent.futures.as_completed(futures):
            _, valid_set = future.result()
            global_domain_set |= valid_set

    logger.info(f"Total unique domains ingested: {len(global_domain_set):,}")

    # Optimize (Tree Pruning)
    optimized = optimize_domains(global_domain_set)
    logger.info(f"Total domains after tree-pruning: {len(optimized):,}")

    # Cloudflare Sync
    sync_to_cloudflare(cf, optimized)

    logger.info(f"Sync complete in {time.perf_counter() - start:.2f} seconds.")

if __name__ == "__main__":
    main()
