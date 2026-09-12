import concurrent.futures
import gzip
import hashlib
import io
import logging
import os
import re
import shutil
import tempfile
import time
import zipfile
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

try:
    import tomllib
except ImportError:
    import tomli as tomllib

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S")
logger = logging.getLogger("cf_sync")

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$|"
    r"^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|"
    r"^(?:[A-Fa-f0-9]{1,4}:)*:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*$"
)

DEFAULT_TOP_LISTS = [
    {"url": "https://tranco-list.eu/top-1m.csv.zip", "col": 1, "skip_header": False, "compression": "zip"},
    {"url": "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", "col": 0, "skip_header": True, "compression": "gzip"},
    {"url": "https://downloads.majestic.com/majestic_million.csv", "col": 2, "skip_header": True, "compression": "raw"},
    {"url": "https://www.domcop.com/files/top/top10milliondomains.csv.zip", "col": 1, "skip_header": True, "compression": "zip"},
    {"url": "https://builtwith.com/dl/builtwith-top1m.zip", "col": 0, "skip_header": False, "compression": "zip"},
]

def load_config() -> dict:
    cfg_path = Path("config.toml")
    if not cfg_path.exists():
        raise FileNotFoundError("config.toml not found.")
    with open(cfg_path, "rb") as f:
        cfg = tomllib.load(f)

    cfg["api_token"] = os.environ.get("API_TOKEN", "").strip()
    cfg["account_id"] = os.environ.get("ACCOUNT_ID", "").strip()
    cfg["primary_email"] = os.environ.get("PRIMARY_EMAIL", "").strip()

    if not cfg["api_token"] or not cfg["account_id"] or not cfg["primary_email"]:
        raise EnvironmentError("Missing API_TOKEN, ACCOUNT_ID, or PRIMARY_EMAIL in environment.")

    excluded = []
    for var in ("SECONDARY_EMAIL", "TERTIARY_EMAIL"):
        val = os.environ.get(var, "").strip()
        if val and val not in excluded:
            excluded.append(val)

    extra_env = os.environ.get("EXCLUDED_EMAILS", "").strip()
    if extra_env:
        for email in extra_env.split(","):
            cleaned = email.strip()
            if cleaned and cleaned not in excluded:
                excluded.append(cleaned)

    cfg["target_identity"] = f"not(identity.email in {{{' '.join(f'\"{e}\"' for e in excluded)}}})" if excluded else None
    return cfg

def create_session(workers: int) -> requests.Session:
    s = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=None
    )
    adapter = HTTPAdapter(pool_connections=workers, pool_maxsize=workers + 2, max_retries=retry_strategy)
    s.mount("https://", adapter)
    return s

class CloudflareAPI:
    def __init__(self, cfg: dict):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{cfg['account_id']}/gateway"
        self.headers = {"Authorization": f"Bearer {cfg['api_token']}", "Content-Type": "application/json"}
        self.session = create_session(cfg["settings"]["max_workers"])
        self.timeout = tuple(cfg["settings"]["request_timeout"])

    def req(self, method: str, endpoint: str, **kwargs) -> dict:
        url = f"{self.base_url}/{endpoint}"
        retries = 5
        base_delay = 2

        for attempt in range(retries):
            resp = self.session.request(method, url, headers=self.headers, timeout=self.timeout, **kwargs)
            
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                wait_time = int(retry_after) if retry_after and retry_after.isdigit() else (base_delay * (2 ** attempt))
                logger.warning(f"Rate limited (429) on {endpoint}. Backing off for {wait_time}s.")
                time.sleep(wait_time)
                continue

            if not resp.ok:
                logger.error(f"Cloudflare API error [{resp.status_code}] on {endpoint}: {resp.text}")
                resp.raise_for_status()

            return resp.json()

        raise RuntimeError(f"Exceeded max retries on Cloudflare endpoint: {endpoint}")

    def paginate(self, endpoint: str) -> list[dict]:
        results, page = [], 1
        while True:
            resp = self.req("GET", f"{endpoint}?page={page}&per_page=100")
            results.extend(resp.get("result") or [])
            info = resp.get("result_info") or {}
            if page >= info.get("total_pages", 1):
                break
            page += 1
        return results

    def get_lists(self) -> list[dict]: return self.paginate("lists")
    def get_rules(self) -> list[dict]: return self.paginate("rules")
    def delete_list(self, lid: str): return self.req("DELETE", f"lists/{lid}")
    def delete_rule(self, rid: str): return self.req("DELETE", f"rules/{rid}")
    def create_list(self, name: str, items: list[dict], desc: str = ""):
        return self.req("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items, "description": desc})
    def update_list(self, lid: str, name: str, items: list[dict], desc: str = ""):
        return self.req("PUT", f"lists/{lid}", json={"name": name, "items": items, "description": desc})
    def create_rule(self, data: dict):
        return self.req("POST", "rules", json={**data, "rule_settings": {"block_page_enabled": False}})
    def update_rule(self, rid: str, data: dict):
        return self.req("PUT", f"rules/{rid}", json={**data, "rule_settings": {"block_page_enabled": False}})

def parse_sources(sources_table: dict) -> list[dict]:
    parsed = []
    for name, data in sources_table.items():
        if isinstance(data, str):
            parsed.append({"name": name, "urls": [data], "enable_relevance": True})
        elif isinstance(data, list):
            parsed.append({"name": name, "urls": data, "enable_relevance": True})
        elif isinstance(data, dict):
            urls = data.get("urls") or [data.get("url")]
            parsed.append({"name": name, "urls": urls, "enable_relevance": data.get("relevance", True)})
    return parsed

def compile_category_expression(p: dict) -> str:
    expr_parts = []
    if p.get("security_categories"):
        ids = " ".join(str(i) for i in p["security_categories"])
        expr_parts.append(f"any(dns.security_category[*] in {{{ids}}})")
    if p.get("content_categories"):
        ids = " ".join(str(i) for i in p["content_categories"])
        expr_parts.append(f"any(dns.content_category[*] in {{{ids}}})")
    if p.get("app_ids"):
        ids = " ".join(str(i) for i in p["app_ids"])
        expr_parts.append(f"any(app.ids[*] in {{{ids}}})")
    if p.get("domains"):
        doms = " ".join(f'"{d}"' for d in p["domains"])
        expr_parts.append(f"any(dns.domains[*] in {{{doms}}})")
    return " or ".join(expr_parts)

def has_suffix_match(host: str, lookup_set: set[str]) -> bool:
    if host in lookup_set:
        return True
    idx = host.find(".")
    while idx != -1:
        if host[idx + 1:] in lookup_set:
            return True
        idx = host.find(".", idx + 1)
    return False

def is_valid_domain(domain: str) -> str | None:
    d = domain.strip().lower().removeprefix("*.").strip(".")
    if not d or "." not in d or any(c in d for c in "*/[]"):
        return None
    try:
        d = d.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    if IP_PATTERN.match(d):
        return None
    return d

def _parse_csv_stream(iterable, col: int, skip_header: bool) -> set[str]:
    domains = set()
    for i, line in enumerate(iterable):
        if skip_header and i == 0:
            continue
        parts = line.split(",")
        if len(parts) > col:
            d = parts[col].strip().lower().strip('"')
            if d and "." in d:
                domains.add(d)
    return domains

def fetch_top_list_streamed(item: dict, session: requests.Session) -> set[str]:
    url = item["url"]
    col = item["col"]
    skip_header = item["skip_header"]
    compression = item["compression"]

    try:
        with tempfile.NamedTemporaryFile(delete=True) as tmp:
            with session.get(url, headers={"User-Agent": "Mozilla/5.0"}, stream=True, timeout=90) as r:
                r.raise_for_status()
                shutil.copyfileobj(r.raw, tmp)
            tmp.seek(0)

            if compression == "zip":
                with zipfile.ZipFile(tmp.name) as z:
                    with z.open(z.namelist()[0]) as zf, io.TextIOWrapper(zf, encoding="utf-8", errors="ignore") as text_io:
                        return _parse_csv_stream(text_io, col, skip_header)
            elif compression == "gzip":
                with gzip.open(tmp.name, mode="rt", encoding="utf-8", errors="ignore") as gz:
                    return _parse_csv_stream(gz, col, skip_header)
            else:
                with open(tmp.name, "r", encoding="utf-8", errors="ignore") as f:
                    return _parse_csv_stream(f, col, skip_header)
    except Exception as e:
        logger.warning(f"Failed to fetch top list ({url}): {e}")
        return set()

class RelevanceChecker:
    def __init__(self, session: requests.Session, workers: int):
        self.master_allowlist: set[str] = set()
        self.session = session
        self.workers = workers

    def build_dataset(self) -> None:
        logger.info("Building relevance dataset from authority sources...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [executor.submit(fetch_top_list_streamed, item, self.session) for item in DEFAULT_TOP_LISTS]
            for f in concurrent.futures.as_completed(futures):
                self.master_allowlist.update(f.result())
        logger.info(f"Relevance dataset built: {len(self.master_allowlist):,} root domains.")

    def is_relevant(self, domain: str) -> bool:
        clean = domain.lower().strip(".")
        if clean.startswith("www."):
            clean = clean[4:]
        return has_suffix_match(clean, self.master_allowlist)

def fetch_feed_source(session: requests.Session, name: str, urls: list[str], checker: RelevanceChecker | None, timeout: tuple) -> tuple[str, set[str], int]:
    kept, pruned = set(), 0
    for u in urls:
        resp = session.get(u, timeout=timeout)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in "#!/":
                continue
            clean = is_valid_domain(line.split()[-1])
            if clean:
                if checker and not checker.is_relevant(clean):
                    pruned += 1
                else:
                    kept.add(clean)

    logger.info(f"Fetched {name}: {len(kept):,} kept (Pruned: {pruned:,})")
    return name, kept, pruned

def fetch_spam_tlds(session: requests.Session, url: str, timeout: tuple) -> tuple[str, set[str]]:
    try:
        resp = session.get(url, timeout=timeout)
        resp.raise_for_status()
        tlds = set()
        for line in resp.text.splitlines():
            line = line.strip().lower()
            if line and line[0] not in "#!/":
                clean = line.split()[-1].strip(".")
                if clean and "." not in clean and "*" not in clean:
                    tlds.add(clean)
        expr = rf'any(dns.domains[*] matches "(?i)\.({"|".join(sorted(tlds))})$")' if tlds else ""
        return expr, tlds
    except Exception as e:
        logger.error(f"TLD list compilation failed: {e}")
        return "", set()

def optimize_domains(domains: set[str]) -> list[str]:
    sorted_domains = sorted(domains, key=lambda d: d.split(".")[::-1])
    optimized, last_kept = [], None
    for dom in sorted_domains:
        if last_kept and dom.endswith(f".{last_kept}"):
            continue
        optimized.append(dom)
        last_kept = dom
    return optimized

def build_policy_sets(policies: list[dict], fetched: dict, spam_tlds: set[str] = None) -> list[tuple[dict, list[str]]]:
    sets = []
    base_set = fetched.get("HaGeZi Normal", set())
    all_blocked = set().union(*(v for k, v in fetched.items() if k != "HaGeZi Spam Allow"))

    relaxed_tld_active = any(
        p.get("prefix") == "L_Relaxed" and p.get("use_spam_tld") 
        for p in policies
    )

    for p in policies:
        p_set = set()
        for inc in p.get("include", []):
            p_set.update(fetched.get(inc, ()))
        for exc in p.get("exclude", []):
            p_set.difference_update(fetched.get(exc, ()))

        if p.get("action") == "allow":
            p_set.difference_update(all_blocked)
        else:
            if p.get("prefix") != "L_Normal" and "HaGeZi Normal" not in p.get("include", []) and "HaGeZi Normal" not in p.get("exclude", []) and base_set:
                p_set = {d for d in p_set if not has_suffix_match(d, base_set)}

            should_prune_tlds = False
            if p.get("use_spam_tld"):
                should_prune_tlds = True
            elif relaxed_tld_active and p.get("prefix") == "L_Restrictive":
                should_prune_tlds = True

            if should_prune_tlds and spam_tlds:
                p_set = {d for d in p_set if d.rsplit(".", 1)[-1] not in spam_tlds}

        sets.append((p, optimize_domains(p_set)))
    return sets

def sync_policy_in_place(cf: CloudflareAPI, cfg: dict, existing_lists: list[dict], existing_rules: list[dict], domains: list[str], policy: dict, tld_expr: str = "") -> tuple[list[str], list[str], list[str]]:
    prefix = policy["prefix"]
    policy_name = policy["name"]
    max_size = cfg["settings"]["max_list_size"]
    workers = cfg["settings"]["max_workers"]

    matched_lists = sorted([l for l in existing_lists if l["name"].startswith(f"{prefix} ")], key=lambda x: x["name"])
    chunks = [domains[i : i + max_size] for i in range(0, len(domains), max_size)] if domains else []

    active_ids = []
    surplus_lists = []

    def sync_chunk(idx: int, chunk: list[str]) -> str:
        name = f"{prefix} {idx + 1:03d}"
        chash = hashlib.sha256(",".join(chunk).encode()).hexdigest()
        items = [{"value": d} for d in chunk]

        if idx < len(matched_lists):
            target = matched_lists[idx]
            if target.get("description") == chash:
                return target["id"]
            cf.update_list(target["id"], name, items, desc=chash)
            logger.info(f"Updated {name} ({len(chunk)} domains)")
            return target["id"]
        else:
            res = cf.create_list(name, items, desc=chash)
            logger.info(f"Created {name} ({len(chunk)} domains)")
            return res["result"]["id"]

    if chunks:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            active_ids = list(pool.map(sync_chunk, range(len(chunks)), chunks))

    if len(matched_lists) > len(chunks):
        surplus_lists = matched_lists[len(chunks):]

    list_items = [f"any(dns.domains[*] in ${lid})" for lid in active_ids]
    if tld_expr and policy.get("use_spam_tld"):
        list_items.append(f"({tld_expr})")
    
    cat_expr = compile_category_expression(policy)
    if cat_expr:
        list_items.append(cat_expr)

    cond = cfg["target_identity"] if policy.get("restrict_users") else policy.get("identity_condition")
    if cond:
        traffic_expr = " or ".join(list_items) if "dns." not in cond else " or ".join(f"({cond} and {item})" for item in list_items)
        identity_expr = cond if "dns." not in cond else ""
    else:
        traffic_expr = " or ".join(list_items)
        identity_expr = ""

    if len(traffic_expr) > 4096:
        logger.warning(f"Expression for '{policy_name}' has {len(traffic_expr)} chars. Increase max_list_size to prevent truncation.")

    rule = next((r for r in existing_rules if r["name"] == policy_name), None)
    payload = {
        "name": policy_name,
        "action": policy.get("action", "block"),
        "enabled": rule.get("enabled", True) if rule else True,
        "filters": ["dns"],
        "traffic": traffic_expr
    }
    if identity_expr:
        payload["identity"] = identity_expr

    if rule:
        if rule.get("traffic") != traffic_expr or rule.get("identity", "") != identity_expr:
            cf.update_rule(rule["id"], payload)
            logger.info(f"Updated firewall rule: {policy_name}")
    else:
        cf.create_rule(payload)
        logger.info(f"Created firewall rule: {policy_name}")

    return active_ids, [l["id"] for l in surplus_lists], [policy_name]

def cleanup_orphans(cf: CloudflareAPI, cfg: dict, existing_lists: list[dict], existing_rules: list[dict], active_ids: list[str], surplus_ids: list[str], active_rules: list[str]):
    scrub_targets = cfg["settings"]["scrub_targets"]

    for sid in surplus_ids:
        try:
            cf.delete_list(sid)
            logger.info(f"Removed surplus list: {sid}")
        except Exception as e:
            logger.error(f"Failed deleting surplus list {sid}: {e}")

    for r in existing_rules:
        if any(k in r["name"] for k in ("IoT Bypass", "Custom", "Keywords")):
            continue
        if r["name"] not in active_rules and any(t in r["name"] for t in scrub_targets):
            try:
                cf.delete_rule(r["id"])
                logger.info(f"Removed orphaned rule: {r['name']}")
            except Exception as e:
                logger.error(f"Rule cleanup error ({r['name']}): {e}")

    for l in existing_lists:
        if "IoT Bypass" in l["name"]:
            continue
        if l["id"] not in active_ids and l["id"] not in surplus_ids and any(t in l["name"] for t in scrub_targets):
            try:
                cf.delete_list(l["id"])
                logger.info(f"Removed orphaned list: {l['name']}")
            except Exception as e:
                logger.error(f"List cleanup error ({l['name']}): {e}")

def main() -> None:
    start = time.perf_counter()
    cfg = load_config()
    cf = CloudflareAPI(cfg)
    workers = cfg["settings"]["max_workers"]
    timeout = tuple(cfg["settings"]["request_timeout"])

    policies = list(cfg.get("policies", {}).values())
    if any(p.get("use_spam_tld") for p in policies):
        spam_allow = cfg.get("spam_allow_source")
        if spam_allow:
            policies.append({
                "prefix": "L_AllowSpam",
                "name": "Allow: Spam Exceptions",
                "action": "allow",
                "include": [spam_allow["name"]],
                "exclude": [],
                "use_spam_tld": False
            })

    sources = parse_sources(cfg.get("sources", {}))
    if any(p.get("use_spam_tld") for p in policies) and "spam_allow_source" in cfg:
        sa = cfg["spam_allow_source"]
        sources.append({"name": sa["name"], "urls": [sa["url"]], "enable_relevance": True})

    session = create_session(workers)
    checker = None
    if any(s.get("enable_relevance") for s in sources):
        checker = RelevanceChecker(session, workers)
        checker.build_dataset()

    tld_url = cfg.get("tld", {}).get("url", "")
    tld_expr, spam_tlds = fetch_spam_tlds(session, tld_url, timeout) if tld_url else ("", set())

    fetched = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(fetch_feed_source, session, s["name"], s["urls"], checker if s.get("enable_relevance") else None, timeout): s["name"]
            for s in sources
        }
        for f in concurrent.futures.as_completed(futures):
            name = futures[f]
            try:
                name, kept, _ = f.result()
                fetched[name] = kept
            except Exception as e:
                if name == "HaGeZi Normal":
                    logger.critical(f"Critical baseline failure ({name}): {e}")
                    return
                logger.warning(f"Non-critical feed failure ({name}): {e}")

    compiled = build_policy_sets(policies, fetched, spam_tlds)
    total_domains = sum(len(d) for _, d in compiled)
    if total_domains > cfg["settings"]["total_quota"]:
        logger.error(f"Total domains ({total_domains:,}) exceeds quota ({cfg['settings']['total_quota']:,}).")
        return

    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()

    all_active_ids, all_surplus_ids, all_active_rules = [], [], []

    for policy, optimized_domains in compiled:
        expr = tld_expr if policy.get("use_spam_tld") else ""
        active_ids, surplus_ids, rule_names = sync_policy_in_place(
            cf, cfg, existing_lists, existing_rules, optimized_domains, policy, tld_expr=expr
        )
        all_active_ids.extend(active_ids)
        all_surplus_ids.extend(surplus_ids)
        all_active_rules.extend(rule_names)

    cleanup_orphans(
        cf, cfg, existing_lists, existing_rules, all_active_ids, all_surplus_ids, all_active_rules
    )

    logger.info(f"Sync complete in {time.perf_counter() - start:.2f}s.")

if __name__ == "__main__":
    main()
