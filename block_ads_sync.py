import concurrent.futures
import csv
import gzip
import hashlib
import io
import logging
import os
import re
import sys
import time
import zipfile

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


# ============================================================
# CONFIG
# ============================================================

class Config:
    API_TOKEN = os.getenv("API_TOKEN", "")
    ACCOUNT_ID = os.getenv("ACCOUNT_ID", "")
    PRIMARY_EMAIL = os.getenv("PRIMARY_EMAIL", "")
    SECONDARY_EMAIL = os.getenv("SECONDARY_EMAIL", "")
    TERTIARY_EMAIL = os.getenv("TERTIARY_EMAIL", "")

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
    MANAGED_RULE_NAMES = set(PRECEDENCE)

    @classmethod
    def validate(cls):
        missing = [x for x in ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL")
                   if not getattr(cls, x)]
        if missing:
            raise EnvironmentError(
                f"Missing mandatory environment variables: {', '.join(missing)}"
            )


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ============================================================
# DOMAIN PARSING
# ============================================================

IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)$|"
    r"^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|"
    r"^(?:[A-Fa-f0-9]{1,4}:)*:"
    r"[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*$"
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]"
    r"(?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def valid_domain(value):
    value = value.strip().lower()

    if value.startswith("*."):
        value = value[2:]

    if value.startswith("||"):
        value = value[2:]
        value = re.split(r"[\^\$]", value, 1)[0]

    value = value.strip(' \t\r\n"\'. ,;')

    if (
        not value
        or "." not in value
        or IP_RE.fullmatch(value)
        or any(x in value for x in ("/", "[", "]", "*", "|", "^", "$",
                                    "(", ")", "=", "?", "\\"))
    ):
        return None

    try:
        value = value.encode("idna").decode()
    except UnicodeError:
        return None

    return value if DOMAIN_RE.fullmatch(value) else None


def parse_line(line):
    line = line.strip()
    if not line or line.startswith(("#", "!", "/")):
        return None

    parts = line.split()
    if len(parts) > 1 and IP_RE.fullmatch(parts[0]):
        return valid_domain(parts[1])

    return valid_domain(parts[0])


def suffix_match(host, lookup):
    host = host.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]

    if host in lookup:
        return True

    parts = host.split(".")
    return any(".".join(parts[i:]) in lookup for i in range(1, len(parts)))


# ============================================================
# SOURCES
# ============================================================

BLOCKLIST_SOURCES = [
    {
        "name": "HaGeZi Normal",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "HaGeZi Pro",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "Hagezi NSFW",
        "url": [
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
            "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
        ],
        "relevance": True,
    },
    {
        "name": "HaGeZi Badware",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "HaGeZi Fake",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "HaGeZi TIF Full",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "Cyber Threat Intel",
        "url": "https://raw.githubusercontent.com/DNSBunker/CTI/refs/heads/main/domains.txt",
        "relevance": False,
    },
    {
        "name": "HaGeZi Social",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "HaGeZi No SafeSearch",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "HaGeZi Bypass Prevention",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "HaGeZi Anti Piracy",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "HaGeZi DynDNS",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
        "relevance": True,
    },
    {
        "name": "NoAI",
        "url": "https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt",
        "relevance": True,
    },
]

SPAM_ALLOW_SOURCE = {
    "name": "HaGeZi Spam Allow",
    "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-allow-onlydomains.txt",
    "relevance": False,
}

SPAM_TLD_URL = (
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/"
    "wildcard/spam-tlds-onlydomains.txt"
)

TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
    ("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://builtwith.com/dl/builtwith-top1m.zip", 0, False, "zip"),
]


# ============================================================
# POLICIES
# ============================================================

excluded = [
    e.strip().lower()
    for e in (Config.SECONDARY_EMAIL, Config.TERTIARY_EMAIL)
    if e.strip()
]

TARGET_IDENTITY = (
    f'not(identity.email in {{{" ".join(map(repr, excluded))}}})'
    if excluded else None
)

def policies():
    result = [
        {
            "prefix": "L_Relaxed",
            "name": "Block: Relaxed Profile",
            "action": "block",
            "identity": None,
            "category": (
                "any(dns.security_category[*] in "
                "{178 80 187 83 176 175 117 131 134 153}) "
                "or any(dns.content_category[*] in {133})"
            ),
            "include": [
                "HaGeZi Normal",
                "Hagezi NSFW",
                "HaGeZi Badware",
                "HaGeZi Fake",
                "HaGeZi No SafeSearch",
                "HaGeZi TIF Full",
                "Cyber Threat Intel",
                "HaGeZi DynDNS",
                "HaGeZi Anti Piracy",
            ],
            "exclude": [],
            "spam_tld": True,
        },
        {
            "prefix": "L_Restrictive",
            "name": "Block: Restrictive Profile",
            "action": "block",
            "identity": TARGET_IDENTITY,
            "category": (
                "any(dns.security_category[*] in {151 191 188 68}) or "
                "any(dns.content_category[*] in {67 125}) or "
                "any(app.ids[*] in "
                "{534 541 572 600 604 618 628 633 1110 1122 1130 1135 "
                "1138 1853 2678 2680 2826 2831 2844 2845 2848 2852 "
                "3097 3098}) or "
                'any(dns.domains[*] in '
                '{"web.archive.org" "steamcommunity.com" '
                '"linkvertise.com" "vercel.com"})'
            ),
            "include": [
                "HaGeZi Pro",
                "HaGeZi Bypass Prevention",
                "HaGeZi Social",
                "NoAI",
            ],
            "exclude": ["HaGeZi Normal"],
            "spam_tld": False,
        },
    ]

    if any(p["spam_tld"] for p in result):
        result.append({
            "prefix": "L_AllowSpam",
            "name": "Allow: Spam Exceptions",
            "action": "allow",
            "identity": None,
            "category": None,
            "include": ["HaGeZi Spam Allow"],
            "exclude": [],
            "spam_tld": False,
        })

    return result


# ============================================================
# HTTP
# ============================================================

def make_session(download=False):
    s = requests.Session()

    retry = Retry(
        total=3 if download else 0,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET"]),
        respect_retry_after_header=True,
    )

    s.mount(
        "https://",
        HTTPAdapter(
            pool_connections=Config.MAX_WORKERS,
            pool_maxsize=Config.MAX_WORKERS + 2,
            max_retries=retry,
        ),
    )
    return s


class CloudflareAPI:
    def __init__(self):
        self.base = (
            f"https://api.cloudflare.com/client/v4/accounts/"
            f"{Config.ACCOUNT_ID}/gateway"
        )
        self.headers = {
            "Authorization": f"Bearer {Config.API_TOKEN}",
            "Content-Type": "application/json",
        }
        self.session = make_session()

    def request(self, method, endpoint, **kwargs):
        retries, delay = Config.MAX_RETRIES, 2
        url = f"{self.base}/{endpoint.lstrip('/')}"

        while True:
            try:
                r = self.session.request(
                    method,
                    url,
                    headers=self.headers,
                    timeout=Config.REQUEST_TIMEOUT,
                    **kwargs,
                )
            except requests.RequestException as e:
                if retries <= 0:
                    raise
                log.warning("Network error: %s; retrying in %ss", e, delay)
            else:
                if r.ok:
                    return r.json()

                if r.status_code not in (429, 500, 502, 503, 504):
                    log.error("Cloudflare %s: %s", r.status_code, r.text)
                    r.raise_for_status()

                if retries <= 0:
                    r.raise_for_status()

                retry_after = r.headers.get("Retry-After")
                try:
                    delay = max(1, int(float(retry_after))) if retry_after else delay
                except ValueError:
                    pass

                log.warning(
                    "Transient API error %s; retrying in %ss",
                    r.status_code,
                    delay,
                )

            retries -= 1
            time.sleep(delay)
            delay = min(delay * 2, 60)

    def get_all(self, endpoint):
        out, page = [], 1
        while True:
            r = self.request("GET", f"{endpoint}?page={page}&per_page=100")
            out.extend(r.get("result") or [])
            info = r.get("result_info") or {}
            if page >= info.get("total_pages", 1):
                return out
            page += 1

    def lists(self): return self.get_all("lists")
    def rules(self): return self.get_all("rules")

    def delete_list(self, lid):
        return self.request("DELETE", f"lists/{lid}")

    def delete_rule(self, rid):
        return self.request("DELETE", f"rules/{rid}")

    def list_write(self, method, lid, name, items, desc):
        payload = {
            "name": name,
            "items": items,
            "description": desc,
        }
        if method == "POST":
            payload["type"] = "DOMAIN"
            return self.request("POST", "lists", json=payload)
        return self.request("PUT", f"lists/{lid}", json=payload)

    def create_list(self, name, items, desc=""):
        return self.list_write("POST", None, name, items, desc)

    def update_list(self, lid, name, items, desc=""):
        return self.list_write("PUT", lid, name, items, desc)

    def rule_write(self, method, rid, data):
        payload = {
            **data,
            "rule_settings": {"block_page_enabled": False},
        }
        return self.request(
            method,
            "rules" if method == "POST" else f"rules/{rid}",
            json=payload,
        )

    def create_rule(self, data):
        return self.rule_write("POST", None, data)

    def update_rule(self, rid, data):
        return self.rule_write("PUT", rid, data)


# ============================================================
# RELEVANCE
# ============================================================

def parse_csv(iterable, col, skip):
    out = set()
    for i, line in enumerate(iterable):
        if skip and i == 0:
            continue
        try:
            parts = next(csv.reader([line]))
            if len(parts) > col:
                d = valid_domain(parts[col].strip())
                if d:
                    out.add(d)
        except Exception:
            pass
    return out


def fetch_top(spec, session):
    url, col, skip, compression = spec
    try:
        r = session.get(url, headers={"User-Agent": "Mozilla/5.0"},
                        timeout=Config.DOWNLOAD_TIMEOUT)
        r.raise_for_status()

        if compression == "zip":
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                files = [x for x in z.namelist() if not x.endswith("/")]
                if not files:
                    raise ValueError("ZIP archive contained no files")
                with io.TextIOWrapper(
                    z.open(files[0]), encoding="utf-8", errors="ignore"
                ) as f:
                    data = parse_csv(f, col, skip)

        elif compression == "gzip":
            with gzip.GzipFile(fileobj=io.BytesIO(r.content)) as gz:
                with io.TextIOWrapper(
                    gz, encoding="utf-8", errors="ignore"
                ) as f:
                    data = parse_csv(f, col, skip)
        else:
            data = parse_csv(r.text.splitlines(), col, skip)

        return data

    except Exception as e:
        log.warning("Top-list failure: %s", e)
        return set()


class RelevanceChecker:
    def __init__(self, session):
        self.session = session
        self.allowlist = set()

    def build(self):
        with concurrent.futures.ThreadPoolExecutor(Config.MAX_WORKERS) as pool:
            for data in pool.map(lambda x: fetch_top(x, self.session), TOP_LISTS):
                self.allowlist.update(data)

        log.info("Relevance dataset: %,d domains", len(self.allowlist))

    def relevant(self, domain):
        return suffix_match(domain, self.allowlist)


# ============================================================
# SOURCE FETCHING
# ============================================================

def fetch_source(source, session, checker=None):
    domains = set()
    pruned = 0

    urls = source["url"] if isinstance(source["url"], list) else [source["url"]]

    for url in urls:
        r = session.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=Config.DOWNLOAD_TIMEOUT,
        )
        r.raise_for_status()

        for line in r.text.splitlines():
            d = parse_line(line)
            if not d:
                continue
            if checker and not checker.relevant(d):
                pruned += 1
                continue
            domains.add(d)

    log.info(
        "Fetched %-24s | kept: %8s | relevance pruned: %8s",
        source["name"],
        f"{len(domains):,}",
        f"{pruned:,}",
    )
    return source["name"], domains, pruned


def fetch_spam_tlds(session):
    r = session.get(
        SPAM_TLD_URL,
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=Config.DOWNLOAD_TIMEOUT,
    )
    r.raise_for_status()

    out = set()

    for line in r.text.splitlines():
        x = line.strip().lower()
        if not x or x.startswith(("#", "!", "/")):
            continue
        x = x.removeprefix("||")
        x = re.split(r"[\^\$]", x, 1)[0].strip(" .")
        if "." not in x and "*" not in x and re.fullmatch(r"[a-z0-9-]{2,63}", x):
            out.add(x)

    if not out:
        raise RuntimeError("Spam TLD source returned zero usable TLDs")

    return sorted(out)


def tld_expression(tlds):
    if not tlds:
        return ""
    return (
        r'any(dns.domains[*] matches "(?i)\.('
        + "|".join(re.escape(x) for x in tlds)
        + r')$")'
    )


# ============================================================
# POLICY COMPILATION
# ============================================================

def optimize_domains(domains):
    ordered = sorted(domains, key=lambda d: d.split(".")[::-1])
    result = []

    for d in ordered:
        if result and d.endswith("." + result[-1]):
            continue
        result.append(d)

    return result


def build_policy_sets(configs, fetched, spam_tlds):
    normal = fetched.get("HaGeZi Normal", set())
    spam = set(spam_tlds)
    blocked = set().union(
        *(v for k, v in fetched.items() if k != "HaGeZi Spam Allow")
    )

    result = []
    total_pruned = 0

    for p in configs:
        domains = set().union(
            *(fetched.get(x, set()) for x in p["include"])
        )

        for x in p["exclude"]:
            domains.difference_update(fetched.get(x, set()))

        if p["action"] == "allow":
            domains.difference_update(blocked)

        elif (
            p["prefix"] != "L_Normal"
            and "HaGeZi Normal" not in p["include"]
            and "HaGeZi Normal" not in p["exclude"]
            and normal
        ):
            domains = {
                d for d in domains
                if not suffix_match(d, normal)
            }

        if p["action"] == "block" and spam:
            before = len(domains)
            domains = {
                d for d in domains
                if d.rsplit(".", 1)[-1] not in spam
            }
            removed = before - len(domains)
            total_pruned += removed
            log.info("[%s] Spam-TLD domains removed: %,d", p["name"], removed)

        domains = optimize_domains(domains)
        log.info("[%s] Final optimized list entries: %,d", p["name"], len(domains))
        result.append((p, domains))

    log.info("TOTAL Spam-TLD domains removed: %,d", total_pruned)
    return result


# ============================================================
# CLOUDFLARE SYNC
# ============================================================

def sync_policy(cf, existing_lists, existing_rules, domains, policy, raw_tld=""):
    managed = sorted(
        [
            x for x in existing_lists
            if x.get("name", "").startswith(policy["prefix"] + " ")
        ],
        key=lambda x: x["name"],
    )

    chunks = [
        domains[i:i + Config.MAX_LIST_SIZE]
        for i in range(0, len(domains), Config.MAX_LIST_SIZE)
    ]

    def write_chunk(item):
        idx, chunk = item
        name = f"{policy['prefix']} {idx + 1:03d}"
        digest = hashlib.sha256(",".join(chunk).encode()).hexdigest()
        payload = [{"value": d} for d in chunk]

        if idx < len(managed):
            old = managed[idx]
            if old.get("description") == digest:
                return old["id"]

            cf.update_list(
                old["id"], name, payload, desc=digest
            )
            return old["id"]

        return cf.create_list(
            name, payload, desc=digest
        )["result"]["id"]

    if chunks:
        with concurrent.futures.ThreadPoolExecutor(Config.MAX_WORKERS) as pool:
            used_ids = list(pool.map(write_chunk, enumerate(chunks)))
    else:
        used_ids = []

    expressions = [
        f"any(dns.domains[*] in ${lid})"
        for lid in used_ids
    ]

    if raw_tld and policy["spam_tld"]:
        expressions.append(f"({raw_tld})")

    if policy["category"]:
        expressions.append(policy["category"])

    identity = policy["identity"]
    traffic = " or ".join(expressions)

    if identity and "dns." in identity:
        traffic = " or ".join(
            f"({identity} and {x})" for x in expressions
        )
        identity_expr = ""
    else:
        identity_expr = identity or ""

    name = policy["name"]
    desired = {
        "name": name,
        "action": policy["action"],
        "enabled": True,
        "filters": ["dns"],
        "traffic": traffic,
        "precedence": Config.PRECEDENCE[name],
    }

    if identity_expr:
        desired["identity"] = identity_expr

    existing = next(
        (r for r in existing_rules if r.get("name") == name),
        None,
    )

    if existing:
        current = {
            "name": existing.get("name"),
            "action": existing.get("action"),
            "enabled": existing.get("enabled", True),
            "filters": existing.get("filters"),
            "traffic": existing.get("traffic"),
            "precedence": existing.get("precedence"),
            "identity": existing.get("identity", ""),
        }
        desired_compare = desired | {"identity": desired.get("identity", "")}

        if current == desired_compare:
            log.info("Gateway rule unchanged: %s", name)
        else:
            cf.update_rule(existing["id"], desired)
            log.info("Gateway rule updated: %s", name)
    else:
        cf.create_rule(desired)
        log.info("Gateway rule created: %s", name)

    return used_ids, [name]


# ============================================================
# SAFE RULE DETACH / RESTORE
# ============================================================

def detach_rules(cf, existing_rules, active):
    snapshots = []

    for p in active:
        old = next(
            (r for r in existing_rules if r.get("name") == p["name"]),
            None,
        )
        if not old:
            continue

        snapshot = {
            k: old.get(k)
            for k in (
                "id", "name", "action", "enabled", "filters",
                "traffic", "precedence", "identity"
            )
        }
        snapshot["action"] = snapshot["action"] or "block"
        snapshot["enabled"] = snapshot["enabled"] is not False
        snapshot["filters"] = snapshot["filters"] or ["dns"]
        snapshot["traffic"] = snapshot["traffic"] or ""

        fallback = (
            f"({p['category']})"
            if p["category"]
            else 'any(dns.domains[*] == "detached.placeholder")'
        )

        payload = {
            "name": p["name"],
            "action": snapshot["action"],
            "enabled": snapshot["enabled"],
            "filters": snapshot["filters"],
            "traffic": fallback,
            "precedence": Config.PRECEDENCE[p["name"]],
        }

        if p["identity"] and "dns." not in p["identity"]:
            payload["identity"] = p["identity"]

        cf.update_rule(old["id"], payload)
        snapshots.append(snapshot)

    return snapshots


def restore_rules(cf, snapshots):
    for s in snapshots:
        payload = {
            "name": s["name"],
            "action": s["action"],
            "enabled": s["enabled"],
            "filters": s["filters"],
            "traffic": s["traffic"],
            "precedence": s["precedence"],
        }
        if s.get("identity"):
            payload["identity"] = s["identity"]

        try:
            cf.update_rule(s["id"], payload)
        except Exception as e:
            log.critical("Failed restoring rule %s: %s", s["name"], e)


# ============================================================
# CLEANUP
# ============================================================

def cleanup(cf, lists, rules, active_ids, active_names):
    for rule in rules:
        if (
            rule.get("name") in Config.MANAGED_RULE_NAMES
            and rule.get("name") not in active_names
        ):
            try:
                cf.delete_rule(rule["id"])
            except Exception as e:
                log.error("Could not delete rule %s: %s",
                          rule.get("name"), e)

    for lst in lists:
        name = lst.get("name", "")
        if (
            any(name.startswith(p) for p in Config.MANAGED_LIST_PREFIXES)
            and lst.get("id") not in active_ids
        ):
            try:
                cf.delete_list(lst["id"])
            except Exception as e:
                log.error("Could not delete list %s: %s", name, e)


# ============================================================
# MAIN
# ============================================================

def main():
    start = time.perf_counter()

    try:
        Config.validate()

        cf = CloudflareAPI()
        active = policies()

        sources = BLOCKLIST_SOURCES.copy()

        if any("HaGeZi Spam Allow" in p["include"] for p in active):
            sources.append(SPAM_ALLOW_SOURCE)

        session = make_session(download=True)

        # Relevance dataset
        checker = None
        if any(s.get("relevance") for s in sources):
            checker = RelevanceChecker(session)
            checker.build()

            if not checker.allowlist:
                log.warning("Relevance dataset empty; disabling filtering")
                checker = None

        # Spam TLD data
        spam_tlds = fetch_spam_tlds(session)
        spam_expr = tld_expression(spam_tlds)

        # Fetch sources
        fetched = {}
        total_relevance_pruned = 0

        with concurrent.futures.ThreadPoolExecutor(Config.MAX_WORKERS) as pool:
            jobs = {
                pool.submit(
                    fetch_source,
                    src,
                    session,
                    checker if checker and src.get("relevance") else None,
                ): src
                for src in sources
            }

            for future in concurrent.futures.as_completed(jobs):
                src = jobs[future]

                try:
                    name, domains, pruned = future.result()
                    fetched[name] = domains
                    total_relevance_pruned += pruned

                except Exception as e:
                    if src["name"] == "HaGeZi Normal":
                        log.critical(
                            "HaGeZi Normal failed; aborting before Cloudflare changes: %s",
                            e,
                        )
                        return 1

                    log.warning(
                        "Non-critical source failed: %s: %s",
                        src["name"],
                        e,
                    )

        compiled = build_policy_sets(active, fetched, spam_tlds)

        total_domains = sum(len(x) for _, x in compiled)

        log.info(
            "Domains pruned via relevance filter: %,d",
            total_relevance_pruned,
        )
        log.info(
            "Target payload footprint: %,d / %,d",
            total_domains,
            Config.TOTAL_QUOTA,
        )

        if total_domains > Config.TOTAL_QUOTA:
            log.critical("Compiled payload exceeds configured quota")
            return 1

        # Existing state
        existing_lists = cf.lists()
        existing_rules = cf.rules()

        snapshots = []

        try:
            snapshots = detach_rules(cf, existing_rules, active)

            active_ids = []
            active_names = []

            for policy, domains in compiled:
                ids, names = sync_policy(
                    cf,
                    existing_lists,
                    existing_rules,
                    domains,
                    policy,
                    spam_expr if policy["spam_tld"] else "",
                )
                active_ids.extend(ids)
                active_names.extend(names)

            # Verification
            verified = cf.rules()

            for policy in active:
                rule = next(
                    (r for r in verified if r.get("name") == policy["name"]),
                    None,
                )

                if not rule:
                    raise RuntimeError(
                        f"Post-sync verification failed: missing '{policy['name']}'"
                    )

                expected = Config.PRECEDENCE[policy["name"]]
                if rule.get("precedence") != expected:
                    raise RuntimeError(
                        f"Post-sync verification failed: "
                        f"{policy['name']} precedence "
                        f"{rule.get('precedence')} != {expected}"
                    )

            cleanup(
                cf,
                existing_lists,
                existing_rules,
                active_ids,
                active_names,
            )

        except Exception as e:
            log.critical("Synchronization failed: %s", e)
            restore_rules(cf, snapshots)
            return 1

        log.info("=" * 50)
        log.info("SYNC COMPLETE")
        log.info("Final managed payload: %,d domains", total_domains)
        log.info("Runtime: %.2f seconds", time.perf_counter() - start)
        log.info("=" * 50)

        return 0

    except KeyboardInterrupt:
        log.warning("Interrupted by user")
        return 130

    except Exception as e:
        log.exception("Fatal error: %s", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
