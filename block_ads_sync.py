"""Cloudflare Gateway blocklist sync — fetches, filters, and applies DNS blocklists."""

import os
import re
import sys
import time
import gzip
import logging
import hashlib
import zipfile
import concurrent.futures
from collections import defaultdict
from io import BytesIO, TextIOWrapper

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ──────────────────────────────────────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────────────────────────────────────

class Config:
    API_TOKEN       = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID      = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL   = os.environ.get("PRIMARY_EMAIL", "")
    SECONDARY_EMAIL = os.environ.get("SECONDARY_EMAIL", "")
    TERTIARY_EMAIL  = os.environ.get("TERTIARY_EMAIL", "")

    ENABLE_RELEVANCE_FILTER = True
    MAX_LIST_SIZE           = 1000
    MAX_RETRIES             = 5
    TOTAL_QUOTA             = 300_000
    REQUEST_TIMEOUT         = (5, 25)
    MAX_WORKERS             = 5
    API_DELAY_S             = 0.15  # small pause between API calls to stay under rate limits

    SCRUB_TARGETS = [
        "Base", "Pro++", "Ultimate", "Normal", "Social",
        "Block:", "Allow:", "L_", "ProMini", "ProPlus",
        "ProUser", "ProHome", "Piracy", "DynDNS", "Hoster", "Restrictive",
    ]

    PROTECTED_KEYWORDS = ("IoT Bypass", "Custom", "Keywords")  # never touch these

    @classmethod
    def validate(cls) -> None:
        required = ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL")
        missing = [k for k in required if not getattr(cls, k)]
        if missing:
            raise EnvironmentError(f"Missing env vars: {', '.join(missing)}")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("cf-sync")

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"|^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$"
    r"|^(?:[A-Fa-f0-9]{1,4}:)*:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*$"
)

BLOCKLIST_URLS: dict[str, list[str]] = {
    "HaGeZi Normal": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt"],
    "HaGeZi Pro":    ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt"],
    "Hagezi NSFW": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
        "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    ],
    "HaGeZi Fake":   ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt"],
    "HaGeZi TIF Full": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt"],
    "HaGeZi Social": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt"],
    "HaGeZi No SafeSearch": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt"],
    "HaGeZi Bypass Prevention": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt"],
    "HaGeZi Anti Piracy": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt"],
    "HaGeZi DynDNS": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt"],
    "NoAI":          ["https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt"],
}

SPAM_TLD_URL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"

ADULT_KEYWORDS_EXPR = (
    'any(dns.domains[*] matches '
    '"(?i).*(blowjob|threesome|gangbang|deepthroat|bukkake|tits|fuck|onlyfans|porn|xxx|sex).*")'
)

TOP_LISTS: list[tuple[str, int, bool, str]] = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
    ("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://builtwith.com/dl/builtwith-top1m.zip", 0, False, "zip"),
]

# Build identity exclusion from env
_excluded = [e for e in (Config.SECONDARY_EMAIL, Config.TERTIARY_EMAIL) if e]
if _excluded:
    _parts = " or ".join(f'identity.email == "{e}"' for e in _excluded)
    TARGET_IDENTITY = f"not ({_parts})"
else:
    TARGET_IDENTITY = None

POLICIES: list[dict] = [
    {
        "prefix": "L_Relaxed",
        "policy_name": "Block: Relaxed Profile",
        "action": "block",
        "identity_condition": None,
        "category_condition": (
            "any(dns.security_category[*] in {178 80 187 83 176 175 117 131 134 153})"
            " or any(dns.content_category[*] in {133})"
        ),
        "include": ["HaGeZi Normal", "Hagezi NSFW", "HaGeZi Fake", "HaGeZi No SafeSearch", "HaGeZi TIF Full"],
        "exclude": [],
        "use_spam_tld": False,
    },
    {
        "prefix": "L_Restrictive",
        "policy_name": "Block: Restrictive Profile",
        "action": "block",
        "identity_condition": TARGET_IDENTITY,
        "category_condition": (
            "any(dns.security_category[*] in {151 191 188 68})"
            " or any(dns.content_category[*] in {67 125})"
        ),
        "include": ["HaGeZi Pro", "HaGeZi Bypass Prevention", "HaGeZi Social",
                     "HaGeZi Anti Piracy", "HaGeZi DynDNS", "NoAI"],  # ← comma fixed
        "exclude": ["HaGeZi Normal"],
        "use_spam_tld": False,
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# Cloudflare API
# ──────────────────────────────────────────────────────────────────────────────

class CF:
    def __init__(self) -> None:
        self.base = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.hdrs = {"Authorization": f"Bearer {Config.API_TOKEN}", "Content-Type": "application/json"}
        self.sess = requests.Session()
        retry = Retry(total=Config.MAX_RETRIES, backoff_factor=2,
                      status_forcelist=(500, 502, 503, 504, 429))
        ad = HTTPAdapter(pool_connections=Config.MAX_WORKERS, pool_maxsize=Config.MAX_WORKERS + 2, max_retries=retry)
        self.sess.mount("https://", ad)
        self.sess.mount("http://", ad)

    def _req(self, method: str, path: str, **kw) -> dict:
        url = f"{self.base}/{path}"
        for attempt in range(Config.MAX_RETRIES):
            try:
                r = self.sess.request(method, url, headers=self.hdrs, timeout=Config.REQUEST_TIMEOUT, **kw)
                if r.status_code in (429, 500, 502, 503, 504) and attempt < Config.MAX_RETRIES - 1:
                    wait = 2 ** attempt
                    log.warning("HTTP %s → retry in %ds (%d left)", r.status_code, wait, Config.MAX_RETRIES - attempt - 1)
                    time.sleep(wait)
                    continue
                r.raise_for_status()
                time.sleep(Config.API_DELAY_S)
                return r.json()
            except requests.exceptions.RequestException as e:
                if attempt == Config.MAX_RETRIES - 1:
                    raise
                wait = 2 ** attempt
                log.warning("Net err on %s: %s → retry in %ds", path, e, wait)
                time.sleep(wait)
        raise RuntimeError("unreachable")

    def _paged(self, endpoint: str) -> list[dict]:
        out, page = [], 1
        while True:
            data = self._req("GET", f"{endpoint}?page={page}&per_page=100")
            out.extend(data.get("result") or [])
            info = data.get("result_info") or {}
            if page >= info.get("total_pages", 1):
                break
            page += 1
        return out

    # convenience wrappers
    def lists(self) -> list[dict]:      return self._paged("lists")
    def rules(self) -> list[dict]:      return self._paged("rules")
    def del_list(self, lid: str):       return self._req("DELETE", f"lists/{lid}")
    def del_rule(self, rid: str):       return self._req("DELETE", f"rules/{rid}")
    def mk_list(self, name, items, desc=""): return self._req("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items, "description": desc})
    def up_list(self, lid, name, items, desc=""): return self._req("PUT", f"lists/{lid}", json={"name": name, "items": items, "description": desc})
    def mk_rule(self, payload: dict):   return self._req("POST", "rules", json={**payload, "rule_settings": {"block_page_enabled": False}})
    def up_rule(self, rid, payload: dict): return self._req("PUT", f"rules/{rid}", json={**payload, "rule_settings": {"block_page_enabled": False}})

# ──────────────────────────────────────────────────────────────────────────────
# Domain helpers
# ──────────────────────────────────────────────────────────────────────────────

def clean_domain(raw: str) -> str | None:
    d = raw.strip().strip(".").lower()
    if not d or "." not in d or IP_RE.match(d):
        return None
    if any(c in d for c in "*/[]"):
        return None
    return d

def is_subdomain_of(domain: str, parents: set[str]) -> bool:
    """True if *domain* is a subdomain of any entry in *parents*."""
    parts = domain.split(".")
    for i in range(1, len(parts)):
        if ".".join(parts[i:]) in parents:
            return True
    return False

def optimize_domains(domains: set[str]) -> list[str]:
    """Remove subdomains whose parent is also present. Returns sorted list."""
    if not domains:
        return []
    # Shortest (fewest labels) first so parents are seen before children
    ordered = sorted(domains, key=lambda d: (d.count("."), d))
    kept: set[str] = set()
    result: list[str] = []
    for d in ordered:
        if not is_subdomain_of(d, kept):
            kept.add(d)
            result.append(d)
    return result

# ──────────────────────────────────────────────────────────────────────────────
# Relevance filter
# ──────────────────────────────────────────────────────────────────────────────

def _parse_csv(lines, col: int, skip_hdr: bool) -> set[str]:
    out: set[str] = set()
    for i, line in enumerate(lines):
        if skip_hdr and i == 0:
            continue
        parts = line.split(",")
        if len(parts) > col:
            dom = parts[col].strip().strip('"').lower()
            if dom and "." in dom:
                out.add(dom)
    return out

def _fetch_top_list(url: str, col: int, skip: bool, comp: str, sess: requests.Session) -> set[str]:
    r = sess.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=90)
    r.raise_for_status()
    if comp == "zip":
        with zipfile.ZipFile(BytesIO(r.content)) as zf:
            with TextIOWrapper(zf.open(zf.namelist()[0]), encoding="utf-8", errors="ignore") as f:
                return _parse_csv(f, col, skip)
    if comp == "gzip":
        with gzip.GzipFile(fileobj=BytesIO(r.content)) as gz:
            with TextIOWrapper(gz, encoding="utf-8", errors="ignore") as f:
                return _parse_csv(f, col, skip)
    return _parse_csv(r.text.splitlines(), col, skip)

class RelevanceFilter:
    def __init__(self, sess: requests.Session) -> None:
        self.sess = sess
        self.master: set[str] = set()
        self._build()

    def _build(self) -> None:
        log.info("Building relevance dataset (%d threads)…", Config.MAX_WORKERS)
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            futs = {pool.submit(_fetch_top_list, *args, self.sess): args[0] for args in TOP_LISTS}
            errors = 0
            for f in concurrent.futures.as_completed(futs):
                try:
                    self.master |= f.result()
                except Exception as e:
                    errors += 1
                    log.warning("Top-list source failed (%s): %s", futs[f], e)
        if not self.master:
            raise RuntimeError("All top-list sources failed — cannot build relevance filter")
        if errors:
            log.warning("Built with %d/%d sources (partial).", len(TOP_LISTS) - errors, len(TOP_LISTS))
        log.info("Relevance set: %s unique domains", f"{len(self.master):,}")

    def keep(self, domain: str) -> bool:
        d = domain.lower().removeprefix("www.")
        return is_subdomain_of(d, self.master) or d in self.master

# ──────────────────────────────────────────────────────────────────────────────
# Fetching blocklists
# ──────────────────────────────────────────────────────────────────────────────

def fetch_blocklist(name: str, urls: list[str], sess: requests.Session,
                    filt: RelevanceFilter | None) -> tuple[str, set[str], int]:
    kept: set[str] = set()
    pruned = 0
    failures = 0

    for url in urls:
        try:
            r = sess.get(url, timeout=Config.REQUEST_TIMEOUT)
            r.raise_for_status()
        except Exception as e:
            failures += 1
            log.error("  %s ← fetch failed: %s", url, e)
            continue  # keep whatever we got from other URLs

        for line in r.text.splitlines():
            line = line.strip()
            if not line or line[0] in "#!/":
                continue
            dom = clean_domain(line.split()[-1])
            if not dom:
                continue
            if filt and not filt.keep(dom):
                pruned += 1
            else:
                kept.add(dom)

    if failures and not kept:
        raise RuntimeError(f"All {len(urls)} source(s) for '{name}' failed")
    if failures:
        log.warning("  %s: %d/%d sources failed (partial data)", name, failures, len(urls))

    log.info("  %-28s %s kept (pruned %s)", name, f"{len(kept):,}", f"{pruned:,}")
    return name, kept, pruned

def fetch_spam_tlds(sess: requests.Session) -> list[str]:
    try:
        r = sess.get(SPAM_TLD_URL, timeout=Config.REQUEST_TIMEOUT)
        r.raise_for_status()
        tlds = set()
        for line in r.text.splitlines():
            t = line.strip().lower().split()[-1].strip(".")
            if t and "." not in t and "*" not in t:
                tlds.add(t)
        log.info("Spam TLDs: %d", len(tlds))
        return sorted(tlds)
    except Exception as e:
        log.error("Failed to fetch spam-TLD list: %s — TLD blocking will be SKIPPED", e)
        return []

def build_tld_expr(tlds: list[str]) -> str:
    """Build CF regex. Chunk to stay under expression-length limits."""
    if not tlds:
        return ""
    MAX_PER_EXPR = 80
    chunks = [tlds[i:i + MAX_PER_EXPR] for i in range(0, len(tlds), MAX_PER_EXPR)]
    exprs = [f'any(dns.domains[*] matches "(?i)\\.({"|".join(c)})$")' for c in chunks]
    return " or ".join(f"({e})" for e in exprs)

# ──────────────────────────────────────────────────────────────────────────────
# Policy compilation
# ──────────────────────────────────────────────────────────────────────────────

def compile_policies(policies: list[dict], fetched: dict[str, set[str]]) -> list[tuple[dict, list[str]]]:
    base = fetched.get("HaGeZi Normal", set())
    out: list[tuple[dict, list[str]]] = []
    for pol in policies:
        s: set[str] = set()
        for inc in pol["include"]:
            s |= fetched.get(inc, set())
        for exc in pol["exclude"]:
            s -= fetched.get(exc, set())

        # Subtract base list if it wasn't explicitly included/excluded
        if "HaGeZi Normal" not in pol["include"] and "HaGeZi Normal" not in pol["exclude"] and base:
            s = {d for d in s if not is_subdomain_of(d, base)}

        out.append((pol, optimize_domains(s)))
    return out

# ──────────────────────────────────────────────────────────────────────────────
# Cloudflare sync
# ──────────────────────────────────────────────────────────────────────────────

def _rule_payload(pol: dict, list_ids: list[str], tld_expr: str, identity: str | None) -> dict:
    clauses = [f"any(dns.domains[*] in ${lid})" for lid in list_ids]
    if tld_expr:
        clauses.append(tld_expr)
    if pol["prefix"] == "L_Restrictive":
        clauses.append(ADULT_KEYWORDS_EXPR)
    if pol.get("category_condition"):
        clauses.append(f"({pol['category_condition']})")

    traffic = " or ".join(clauses)

    payload: dict = {
        "name": pol["policy_name"],
        "action": pol.get("action", "block"),
        "enabled": True,  # set by caller
        "filters": ["dns"],
        "traffic": traffic,
    }
    if identity and "dns." not in identity:
        payload["identity"] = identity
    return payload

def sync_policy(cf: CF, pol: dict, domains: list[str],
                all_lists: list[dict], all_rules: list[dict],
                tld_expr: str) -> tuple[list[str], str]:
    identity = pol.get("identity_condition")
    rule_name = pol["policy_name"]

    # ── lists ──
    list_ids: list[str] = []
    if domains:
        sorted_d = sorted(domains)
        chunks = [sorted_d[i:i + Config.MAX_LIST_SIZE] for i in range(0, len(sorted_d), Config.MAX_LIST_SIZE)]
        existing = sorted(
            (l for l in all_lists if l["name"].startswith(pol["prefix"] + " ")),
            key=lambda x: x["name"],
        )

        def do_chunk(idx: int, chunk: list[str]) -> str:
            name = f"{pol['prefix']} {idx + 1:03d}"
            h = hashlib.sha256(",".join(chunk).encode()).hexdigest()
            items = [{"value": d} for d in chunk]
            if idx < len(existing):
                ex = existing[idx]
                if ex.get("description") == h:
                    return ex["id"]
                cf.up_list(ex["id"], name, items, h)
                log.info("  Updated list %s (%s)", name, f"{len(chunk):,}")
                return ex["id"]
            else:
                res = cf.mk_list(name, items, h)
                log.info("  Created list %s (%s)", name, f"{len(chunk):,}")
                return res["result"]["id"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
            futs = [pool.submit(do_chunk, i, c) for i, c in enumerate(chunks)]
            list_ids = [f.result() for f in futs]

    # ── rule ──
    payload = _rule_payload(pol, list_ids, tld_expr if pol.get("use_spam_tld") else "", identity)
    existing_rule = next((r for r in all_rules if r["name"] == rule_name), None)
    payload["enabled"] = existing_rule["enabled"] if existing_rule else True

    if existing_rule:
        if existing_rule.get("traffic") == payload["traffic"] and existing_rule.get("identity") == payload.get("identity"):
            log.info("  Rule '%s' unchanged", rule_name)
        else:
            cf.up_rule(existing_rule["id"], payload)
            log.info("  Rule '%s' updated", rule_name)
    else:
        cf.mk_rule(payload)
        log.info("  Rule '%s' created", rule_name)

    return list_ids, rule_name

# ──────────────────────────────────────────────────────────────────────────────
# Cleanup
# ──────────────────────────────────────────────────────────────────────────────

def _is_protected(name: str) -> bool:
    return any(kw in name for kw in Config.PROTECTED_KEYWORDS)

def _matches_scrub(name: str) -> bool:
    return any(t in name for t in Config.SCRUB_TARGETS)

def cleanup(cf: CF, active_list_ids: set[str], active_rule_names: set[str]) -> None:
    log.info("Cleaning up orphans…")
    lists = cf.lists()
    rules = cf.rules()

    for r in rules:
        if _is_protected(r["name"]) or r["name"] in active_rule_names:
            continue
        if _matches_scrub(r["name"]):
            try:
                cf.del_rule(r["id"])
                log.info("  Del rule: %s", r["name"])
            except Exception as e:
                log.error("  Could not del rule %s: %s", r["name"], e)

    for l in lists:
        if _is_protected(l["name"]) or l["id"] in active_list_ids:
            continue
        if _matches_scrub(l["name"]):
            try:
                cf.del_list(l["id"])
                log.info("  Del list: %s", l["name"])
            except Exception as e:
                log.error("  Could not del list %s: %s", l["name"], e)

# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main() -> None:
    t0 = time.perf_counter()
    Config.validate()
    cf = CF()

    # ── download session ──
    dl = requests.Session()
    dl_retry = Retry(total=3, backoff_factor=1, status_forcelist=(500, 502, 503, 504))
    ad = HTTPAdapter(pool_connections=8, pool_maxsize=12, max_retries=dl_retry)
    dl.mount("https://", ad)
    dl.mount("http://", ad)

    # ── relevance filter ──
    filt: RelevanceFilter | None = None
    if Config.ENABLE_RELEVANCE_FILTER:
        filt = RelevanceFilter(dl)
    else:
        log.info("Relevance filter disabled")

    # ── spam TLDs ──
    tlds = fetch_spam_tlds(dl)
    tld_expr = build_tld_expr(tlds)

    # ── fetch all blocklists ──
    fetched: dict[str, set[str]] = {}
    total_pruned = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futs = {pool.submit(fetch_blocklist, name, urls, dl, filt): name
                for name, urls in BLOCKLIST_URLS.items()}
        for f in concurrent.futures.as_completed(futs):
            name = futs[f]
            try:
                _, kept, pruned = f.result()
                fetched[name] = kept
                total_pruned += pruned
            except Exception as e:
                if name == "HaGeZi Normal":
                    log.critical("Fatal: primary baseline '%s' unavailable: %s", name, e)
                    sys.exit(1)
                log.warning("Non-critical source '%s' failed: %s", name, e)

    # ── compile ──
    compiled = compile_policies(POLICIES, fetched)
    total = sum(len(d) for _, d in compiled)
    log.info("Pruned: %s │ Total to sync: %s", f"{total_pruned:,}", f"{total:,}")

    if total > Config.TOTAL_QUOTA:
        log.error("Quota exceeded (%s > %s). Aborting.", f"{total:,}", f"{Config.TOTAL_QUOTA:,}")
        sys.exit(1)

    # ── existing state ──
    all_lists = cf.lists()
    all_rules = cf.rules()

    # ── detach rules so we can modify lists ──
    log.info("Detaching rules to free list references…")
    for pol in POLICIES:
        r = next((x for x in all_rules if x["name"] == pol["policy_name"]), None)
        if not r:
            continue
        fallback = pol.get("category_condition", '')
        if pol["prefix"] == "L_Restrictive":
            fallback = f"({fallback} or {ADULT_KEYWORDS_EXPR})" if fallback else ADULT_KEYWORDS_EXPR
        if not fallback:
            fallback = 'dns.domains == "detached.placeholder"'
        payload: dict = {"name": pol["policy_name"], "action": pol.get("action", "block"),
                         "enabled": r["enabled"], "filters": ["dns"], "traffic": fallback}
        idn = pol.get("identity_condition")
        if idn and "dns." not in idn:
            payload["identity"] = idn
        try:
            cf.up_rule(r["id"], payload)
        except Exception as e:
            log.error("Detach failed for %s: %s", pol["policy_name"], e)

    # ── purge stale rules ──
    valid_names = {p["policy_name"] for p in POLICIES}
    for r in all_rules[:]:
        if _is_protected(r["name"]) or r["name"] in valid_names:
            continue
        if _matches_scrub(r["name"]):
            try:
                cf.del_rule(r["id"])
                log.info("  Purged stale rule: %s", r["name"])
            except Exception as e:
                log.error("  Purge failed %s: %s", r["name"], e)

    # ── purge stale lists (excess chunks) ──
    expected: dict[str, int] = {}
    for pol, doms in compiled:
        expected[pol["prefix"]] = max(1, -(-len(doms) // Config.MAX_LIST_SIZE)) if doms else 0

    for lst in all_lists[:]:
        if _is_protected(lst["name"]):
            continue
        matched = None
        for pfx in expected:
            if lst["name"].startswith(pfx + " "):
                matched = pfx
                break
        if matched is None and _matches_scrub(lst["name"]):
            try:
                cf.del_list(lst["id"])
                log.info("  Purged orphan list: %s", lst["name"])
            except Exception as e:
                log.error("  Purge failed %s: %s", lst["name"], e)
            continue
        if matched is not None:
            try:
                idx = int(lst["name"].split()[-1])
                if idx > expected[matched]:
                    cf.del_list(lst["id"])
                    log.info("  Purged excess list: %s", lst["name"])
            except (ValueError, IndexError):
                if _matches_scrub(lst["name"]):
                    try:
                        cf.del_list(lst["id"])
                    except Exception:
                        pass

    # ── sync new state ──
    active_ids: set[str] = set()
    active_names: set[str] = set()
    for pol, doms in compiled:
        log.info("Syncing policy: %s", pol["policy_name"])
        ids, rname = sync_policy(cf, pol, doms, all_lists, all_rules, tld_expr)
        active_ids |= set(ids)
        active_names.add(rname)

    # ── final cleanup (catch anything missed) ──
    cleanup(cf, active_ids, active_names)

    # ── local dump ──
    agg: set[str] = set()
    for _, d in compiled:
        agg |= set(d)
    try:
        with open("aggregate_blocklist.txt", "w") as f:
            for d in sorted(agg):
                f.write(d + "\n")
        log.info("Wrote aggregate_blocklist.txt (%s entries)", f"{len(agg):,}")
    except OSError as e:
        log.error("Local dump failed: %s", e)

    log.info("Done in %.1fs", time.perf_counter() - t0)

if __name__ == "__main__":
    main()
