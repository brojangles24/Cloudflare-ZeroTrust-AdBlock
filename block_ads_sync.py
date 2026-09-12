import concurrent.futures
import csv
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import sys
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


class Config:
    API_TOKEN = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
    PRIMARY_EMAIL = os.environ.get("PRIMARY_EMAIL", "")
    SECONDARY_EMAIL = os.environ.get("SECONDARY_EMAIL", "")
    TERTIARY_EMAIL = os.environ.get("TERTIARY_EMAIL", "")
    ACTIVE_TIER = os.environ.get("ACTIVE_TIER", "")

    MAX_LIST_SIZE = int(os.environ.get("MAX_LIST_SIZE", "1000"))
    TOTAL_QUOTA = int(os.environ.get("TOTAL_QUOTA", "300000"))
    MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "5"))
    API_RETRIES = int(os.environ.get("API_RETRIES", "5"))
    DOWNLOAD_RETRIES = int(os.environ.get("DOWNLOAD_RETRIES", "3"))
    REQUEST_TIMEOUT = (5, 30)
    DOWNLOAD_TIMEOUT = (10, 90)

    REQUIRE_ALL_ACTIVE_SOURCES = True
    MIN_SOURCE_DOMAINS = int(os.environ.get("MIN_SOURCE_DOMAINS", "25"))
    MAX_SOURCE_DROP_PCT = float(os.environ.get("MAX_SOURCE_DROP_PCT", "0.70"))

    RELEVANCE_CACHE = Path(os.environ.get("RELEVANCE_CACHE", ".cache/relevance.json"))
    RELEVANCE_CACHE_TTL = int(os.environ.get("RELEVANCE_CACHE_TTL", "86400"))

    AGGREGATE_FILE = Path("aggregate_blocklist.txt")
    APP_CONFIG_FILE = Path("config/gateway.json")
    STATE_FILE = Path("state/sync_state.json")
    SOURCE_METRICS_FILE = Path("state/source_metrics.json")

    # This prefix is deliberately narrow. The sync should never delete arbitrary
    # user-created Gateway resources merely because a name happens to contain L_.
    MANAGED_LIST_PREFIXES = ("L_Relaxed ", "L_Restrictive ", "L_AllowSpam ")
    MANAGED_RULE_NAMES = {
        "Block: Relaxed Profile",
        "Block: Restrictive Profile",
        "Allow: Spam Exceptions",
    }

    # Cloudflare Gateway expression strings should be kept comfortably below any
    # practical rule-expression limit. Refuse the deployment rather than sending
    # an oversized expression.
    MAX_TLD_EXPRESSION_CHARS = int(os.environ.get("MAX_TLD_EXPRESSION_CHARS", "7000"))

    @classmethod
    def validate(cls) -> None:
        required = ("API_TOKEN", "ACCOUNT_ID", "PRIMARY_EMAIL")
        missing = [name for name in required if not getattr(cls, name)]
        if missing:
            raise EnvironmentError(
                "Missing mandatory environment variables: " + ", ".join(missing)
            )

        if cls.MAX_LIST_SIZE <= 0 or cls.TOTAL_QUOTA <= 0:
            raise ValueError("MAX_LIST_SIZE and TOTAL_QUOTA must be positive")
        if not 0 < cls.MAX_SOURCE_DROP_PCT < 1:
            raise ValueError("MAX_SOURCE_DROP_PCT must be between 0 and 1")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
ABP_HOST_RE = re.compile(r"^\|\|([a-z0-9.-]+)(?:[/$^]|$)", re.IGNORECASE)
TLD_RE = re.compile(r"^[a-z0-9-]{2,63}$", re.IGNORECASE)

BLOCKLIST_SOURCES = [
    {
        "name": "HaGeZi Normal",
        "url": [
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
        ],
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "HageZi NSFW",
        "url": [
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
            "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
        ],
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "HaGeZi Fake",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "HaGeZi TIF Full",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt",
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "Cyber Threat Intel",
        "url": "https://raw.githubusercontent.com/DNSBunker/CTI/refs/heads/main/domains.txt",
        "enable_relevance": False,
        "required": True,
    },
    {
        "name": "HaGeZi Social",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "HaGeZi No SafeSearch",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "HaGeZi Bypass Prevention",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "HaGeZi Anti Piracy",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "HaGeZi DynDNS",
        "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
        "enable_relevance": True,
        "required": True,
    },
    {
        "name": "NoAI",
        "url": "https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt",
        "enable_relevance": True,
        "required": True,
    },
]

SPAM_ALLOW_SOURCE = {
    "name": "HaGeZi Spam Allow",
    "url": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-allow-onlydomains.txt",
    "enable_relevance": True,
    "required": True,
}

SPAM_TLD_URL = (
    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt"
)

TOP_LISTS = [
    ("https://tranco-list.eu/top-1m.csv.zip", 1, False, "zip"),
    ("https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/global/current.csv.gz", 0, True, "gzip"),
    ("https://downloads.majestic.com/majestic_million.csv", 2, True, "raw"),
    ("https://www.domcop.com/files/top/top10milliondomains.csv.zip", 1, True, "zip"),
    ("https://builtwith.com/dl/builtwith-top1m.zip", 0, False, "zip"),
]


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name, "")
    if not value:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def get_active_policies() -> list[dict]:
    excluded = [e for e in (Config.SECONDARY_EMAIL, Config.TERTIARY_EMAIL) if e]
    identity = None
    if excluded:
        formatted = " ".join(f'"{e}"' for e in excluded)
        identity = f"not(identity.email in {{{formatted}}})"

    policies = [
        {
            "prefix": "L_Relaxed",
            "tier": "relaxed",
            "policy_name": "Block: Relaxed Profile",
            "action": "block",
            "identity_condition": None,
            "category_condition": (
                "any(dns.security_category[*] in {178 80 187 83 176 175 117 131 134 153}) or "
                "any(dns.content_category[*] in {133})"
            ),
            "include": [
                "HaGeZi Normal",
                "HageZi NSFW",
                "HaGeZi Fake",
                "HaGeZi No SafeSearch",
                "HaGeZi TIF Full",
                "Cyber Threat Intel",
                "HaGeZi DynDNS",
                "HaGeZi Anti Piracy",
            ],
            "exclude": [],
            "use_spam_tld": env_bool("USE_SPAM_TLD_RELAXED", True),
        },
        {
            "prefix": "L_Restrictive",
            "tier": "restrictive",
            "policy_name": "Block: Restrictive Profile",
            "action": "block",
            "identity_condition": identity,
            "category_condition": (
                "any(dns.security_category[*] in {151 191 188 68}) or "
                "any(dns.content_category[*] in {67 125}) or "
                "any(app.ids[*] in {534 541 572 600 604 618 628 633 1110 1122 1130 1135 1138 1853 2678 2680 2826 2831 2844 2845 2848 2852 3097 3098}) or "
                'any(dns.domains[*] in {"web.archive.org" "steamcommunity.com" "linkvertise.com" "vercel.com" "rumble.com"})'
            ),
            "include": ["HaGeZi Bypass Prevention", "HaGeZi Social", "NoAI"],
            "exclude": ["HaGeZi Normal"],
            "use_spam_tld": env_bool("USE_SPAM_TLD_RESTRICTIVE", False),
        },
    ]

    tier = Config.ACTIVE_TIER.strip().lower()
    if tier in {"relaxed", "restrictive"}:
        policies = [p for p in policies if p["tier"] == tier]
    elif tier not in {"", "all"}:
        raise ValueError("ACTIVE_TIER must be empty, all, relaxed, or restrictive")

    if any(p["use_spam_tld"] for p in policies):
        policies.append(
            {
                "prefix": "L_AllowSpam",
                "tier": "system",
                "policy_name": "Allow: Spam Exceptions",
                "action": "allow",
                "identity_condition": None,
                "category_condition": None,
                "include": ["HaGeZi Spam Allow"],
                "exclude": [],
                "use_spam_tld": False,
            }
        )
    return policies


def build_session(max_retries: int, pool_size: int, user_agent: str) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=max_retries,
        connect=max_retries,
        read=max_retries,
        status=max_retries,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST", "PUT", "DELETE", "PATCH"}),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=retry,
    )
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": user_agent})
    return session


def normalize_domain(domain: str) -> str | None:
    domain = domain.strip().lower().strip(".")
    if domain.startswith("*."):
        domain = domain[2:]

    if not domain or any(ch.isspace() for ch in domain):
        return None
    if any(ch in domain for ch in ("/", "\\", "[", "]", "*", "^", "$", ":")):
        return None

    try:
        domain = domain.encode("idna").decode("ascii")
        ipaddress.ip_address(domain)
        return None
    except UnicodeError:
        return None
    except ValueError:
        pass

    if len(domain) > 253 or "." not in domain:
        return None

    labels = domain.split(".")
    if any(not DOMAIN_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return domain


def extract_domain(line: str) -> str | None:
    line = line.strip().lstrip("\ufeff")
    if not line or line.startswith(("#", "!", "[", "/")):
        return None

    match = ABP_HOST_RE.match(line)
    if match:
        return normalize_domain(match.group(1))

    fields = line.split()
    if len(fields) >= 2:
        try:
            ipaddress.ip_address(fields[0])
            return normalize_domain(fields[1])
        except ValueError:
            pass

    token = fields[0].strip('"\'')
    token = token.split("#", 1)[0].split("!", 1)[0]
    token = token.rstrip("^/$")
    return normalize_domain(token)


def has_suffix_match(host: str, lookup_set: set[str]) -> bool:
    host = host.rstrip(".").lower()
    if host in lookup_set:
        return True
    parts = host.split(".")
    return any(".".join(parts[i:]) in lookup_set for i in range(1, len(parts)))


def parse_csv_lines(iterable: Iterable[str], col_idx: int, skip_header: bool) -> set[str]:
    domains: set[str] = set()
    reader = csv.reader(iterable)
    for index, row in enumerate(reader):
        if skip_header and index == 0:
            continue
        if len(row) <= col_idx:
            continue
        domain = normalize_domain(row[col_idx])
        if domain:
            domains.add(domain)
    return domains


def fetch_top_list(url: str, col_idx: int, skip_header: bool, compression: str, session: requests.Session) -> set[str]:
    response = session.get(url, timeout=Config.DOWNLOAD_TIMEOUT)
    response.raise_for_status()

    if compression == "zip":
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            members = [name for name in archive.namelist() if not name.endswith("/")]
            if not members:
                raise RuntimeError("ZIP archive contains no files")
            with archive.open(members[0]) as raw:
                with io.TextIOWrapper(raw, encoding="utf-8", errors="ignore") as text:
                    return parse_csv_lines(text, col_idx, skip_header)

    if compression == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as raw:
            with io.TextIOWrapper(raw, encoding="utf-8", errors="ignore") as text:
                return parse_csv_lines(text, col_idx, skip_header)

    return parse_csv_lines(response.text.splitlines(), col_idx, skip_header)


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(content, encoding="utf-8")
    temp.replace(path)


class RelevanceChecker:
    def __init__(self, session: requests.Session):
        self.master_allowlist: set[str] = set()
        self.session = session

    def build_dataset(self) -> None:
        cache_file = Config.RELEVANCE_CACHE
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        now = time.time()

        if cache_file.exists():
            try:
                payload = json.loads(cache_file.read_text(encoding="utf-8"))
                timestamp = float(payload.get("timestamp", 0))
                domains = set(payload.get("domains", []))
                if domains and now - timestamp < Config.RELEVANCE_CACHE_TTL:
                    self.master_allowlist = domains
                    logger.info("Using cached relevance dataset: %,d domains", len(domains))
                    return
            except Exception as exc:
                logger.warning("Ignoring invalid relevance cache: %s", exc)

        logger.info("Building relevance dataset from top-site datasets...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = [executor.submit(fetch_top_list, *entry, self.session) for entry in TOP_LISTS]
            for future in concurrent.futures.as_completed(futures):
                try:
                    self.master_allowlist.update(future.result())
                except Exception as exc:
                    logger.warning("Top-list fetch failed: %s", exc)

        if not self.master_allowlist:
            raise RuntimeError("Relevance dataset is empty; refusing to prune sources")

        atomic_write_text(
            cache_file,
            json.dumps(
                {"timestamp": now, "domains": sorted(self.master_allowlist)},
                separators=(",", ":"),
            ),
        )
        logger.info("Relevance dataset built: %,d unique domains", len(self.master_allowlist))

    def is_relevant(self, domain: str) -> bool:
        return has_suffix_match(domain, self.master_allowlist)


@dataclass
class SourceResult:
    name: str
    parsed: int
    kept: int
    pruned: int
    domains: set[str]
    errors: list[str]


def fetch_source(session: requests.Session, source: dict, checker: RelevanceChecker | None) -> SourceResult:
    kept: set[str] = set()
    parsed_total = 0
    pruned = 0
    errors: list[str] = []
    urls = [source["url"]] if isinstance(source["url"], str) else source["url"]

    for url in urls:
        try:
            response = session.get(url, timeout=Config.DOWNLOAD_TIMEOUT)
            response.raise_for_status()
            parsed_here = 0
            for line in response.text.splitlines():
                domain = extract_domain(line)
                if not domain:
                    continue
                parsed_here += 1
                if checker and source.get("enable_relevance", False) and not checker.is_relevant(domain):
                    pruned += 1
                    continue
                kept.add(domain)
            parsed_total += parsed_here
            if parsed_here == 0:
                errors.append(f"{url}: no valid domains parsed")
        except Exception as exc:
            errors.append(f"{url}: {exc}")

    if len(kept) < Config.MIN_SOURCE_DOMAINS:
        errors.append(f"source kept only {len(kept)} domains (< {Config.MIN_SOURCE_DOMAINS})")

    return SourceResult(source["name"], parsed_total, len(kept), pruned, kept, errors)



def get_active_sources() -> list[dict]:
    return list(BLOCKLIST_SOURCES)

def fetch_spam_tlds(session: requests.Session) -> set[str]:
    response = session.get(SPAM_TLD_URL, timeout=Config.DOWNLOAD_TIMEOUT)
    response.raise_for_status()

    tlds: set[str] = set()
    for raw_line in response.text.splitlines():
        line = raw_line.strip().lower().lstrip("\ufeff")
        if not line or line.startswith(("#", "!", "/")):
            continue

        # Accept plain TLDs as well as the common hosts/wildcard forms used by
        # blocklists, while storing only the final TLD token.
        token = line.split()[0].strip().strip(".")
        if token.startswith("*."):
            token = token[2:]
        if token.startswith("||"):
            token = token[2:]
        token = token.rstrip("^/$")
        if "." in token:
            token = token.rsplit(".", 1)[-1]

        if TLD_RE.fullmatch(token):
            tlds.add(token)

    if not tlds:
        raise RuntimeError("Spam TLD source returned no usable TLDs")

    logger.info("Loaded %,d spam TLDs", len(tlds))
    return tlds


def final_tld(domain: str) -> str:
    return domain.rstrip(".").lower().rsplit(".", 1)[-1]


def remove_spam_tld_domains(domains: set[str], spam_tlds: set[str]) -> tuple[set[str], int]:
    if not spam_tlds:
        return set(domains), 0

    filtered = {domain for domain in domains if final_tld(domain) not in spam_tlds}
    return filtered, len(domains) - len(filtered)


def build_cloudflare_tld_expression(tlds: set[str]) -> str:
    if not tlds:
        return ""
    escaped = "|".join(re.escape(tld) for tld in sorted(tlds))
    expression = rf'any(dns.domains[*] matches "(?i)\.({escaped})$")'
    if len(expression) > Config.MAX_TLD_EXPRESSION_CHARS:
        raise RuntimeError(
            f"Spam TLD expression is {len(expression):,} characters, above configured "
            f"limit {Config.MAX_TLD_EXPRESSION_CHARS:,}"
        )
    return expression


def optimize_domains(domains: set[str], enable_parent_collapse: bool = True) -> list[str]:
    if not enable_parent_collapse:
        return sorted(domains)

    ordered = sorted(domains, key=lambda d: (d.count("."), d))
    kept: list[str] = []
    kept_set: set[str] = set()
    for domain in ordered:
        if not has_suffix_match(domain, kept_set):
            kept.append(domain)
            kept_set.add(domain)
    return kept


def build_policy_sets(policies: list[dict], fetched_lists: dict[str, set[str]], spam_tlds: set[str]) -> list[tuple[dict, list[str]]]:
    baseline = fetched_lists.get("HaGeZi Normal", set())
    all_blocked = set().union(
        *(domains for name, domains in fetched_lists.items() if name != "HaGeZi Spam Allow")
    )

    # Relaxed is global. When Relaxed uses the spam-TLD rule, every profile
    # must remove domains covered by that rule from its list payload, even if
    # that profile's own use_spam_tld setting is false. The profile that has
    # use_spam_tld=true still receives the actual TLD expression below.
    relaxed_spam_tld_global = any(
        p.get("tier") == "relaxed" and p.get("use_spam_tld")
        for p in policies
    )

    compiled = []
    for policy in policies:
        domain_set: set[str] = set()
        for include in policy.get("include", []):
            domain_set.update(fetched_lists.get(include, set()))
        for exclude in policy.get("exclude", []):
            domain_set.difference_update(fetched_lists.get(exclude, set()))

        domain_set.update(policy.get("custom_domains", []))

        if policy.get("action") == "allow":
            domain_set.difference_update(all_blocked)

        if (
            "HaGeZi Normal" not in policy.get("include", [])
            and baseline
            and "HaGeZi Normal" not in policy.get("exclude", [])
        ):
            domain_set = {d for d in domain_set if not has_suffix_match(d, baseline)}

        # Spam-TLD list pruning is global when the Relaxed profile enables it.
        # A profile that explicitly enables use_spam_tld also prunes itself.
        prune_spam_tlds = bool(
            policy.get("use_spam_tld")
            or relaxed_spam_tld_global
        ) and policy.get("tier") in {"relaxed", "restrictive"}

        if prune_spam_tlds:
            domain_set, removed = remove_spam_tld_domains(domain_set, spam_tlds)
            if policy.get("use_spam_tld"):
                reason = "use_spam_tld=true"
            else:
                reason = "global Relaxed spam-TLD enforcement"
            logger.info(
                "%s: %s; removed %s domains covered by spam-TLD rule",
                policy["policy_name"],
                reason,
                f"{removed:,}",
            )
        else:
            logger.info(
                "%s: spam-TLD pruning disabled; retaining matching-TLD domains",
                policy["policy_name"],
            )

        optimized = optimize_domains(domain_set, enable_parent_collapse=True)
        compiled.append((policy, optimized))
        logger.info(
            "%s: %s domains before optimization, %s after",
            policy["policy_name"], f"{len(domain_set):,}", f"{len(optimized):,}"
        )

    return compiled


class CloudflareAPI:
    def __init__(self):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{Config.ACCOUNT_ID}/gateway"
        self.session = build_session(
            Config.API_RETRIES,
            Config.MAX_WORKERS,
            "cloudflare-gateway-sync/4",
        )
        self.session.headers.update({
            "Authorization": f"Bearer {Config.API_TOKEN}",
            "Content-Type": "application/json",
        })

    def request(self, method: str, endpoint: str, **kwargs) -> dict:
        response = self.session.request(
            method,
            f"{self.base_url}/{endpoint.lstrip('/')}",
            timeout=Config.REQUEST_TIMEOUT,
            **kwargs,
        )
        if not response.ok:
            logger.error("Cloudflare API %s %s failed [%s]: %s", method, endpoint, response.status_code, response.text)
        response.raise_for_status()
        payload = response.json()
        if payload.get("success") is False:
            raise RuntimeError(f"Cloudflare API failure: {payload.get('errors', payload)}")
        return payload

    def _paginate(self, endpoint: str) -> list[dict]:
        results = []
        page = 1
        while True:
            payload = self.request("GET", f"{endpoint}?page={page}&per_page=100")
            results.extend(payload.get("result") or [])
            info = payload.get("result_info") or {}
            total_pages = int(info.get("total_pages", 1) or 1)
            if page >= total_pages:
                return results
            page += 1

    def get_lists(self) -> list[dict]:
        return self._paginate("lists")

    def get_rules(self) -> list[dict]:
        return self._paginate("rules")

    def create_list(self, name: str, items: list[dict], description: str) -> str:
        payload = self.request(
            "POST",
            "lists",
            json={"name": name, "type": "DOMAIN", "items": items, "description": description},
        )
        return payload["result"]["id"]

    def update_list(self, list_id: str, name: str, items: list[dict], description: str) -> None:
        self.request(
            "PUT",
            f"lists/{list_id}",
            json={"name": name, "items": items, "description": description},
        )

    def delete_list(self, list_id: str) -> None:
        self.request("DELETE", f"lists/{list_id}")

    def create_rule(self, payload: dict) -> str:
        result = self.request(
            "POST",
            "rules",
            json={**payload, "rule_settings": {"block_page_enabled": False}},
        )
        return result.get("result", {}).get("id", "")

    def update_rule(self, rule_id: str, payload: dict) -> None:
        self.request(
            "PUT",
            f"rules/{rule_id}",
            json={**payload, "rule_settings": {"block_page_enabled": False}},
        )

    def delete_rule(self, rule_id: str) -> None:
        self.request("DELETE", f"rules/{rule_id}")


def managed_list(name: str) -> bool:
    return name.startswith(Config.MANAGED_LIST_PREFIXES)


def managed_rule(rule: dict) -> bool:
    return rule.get("name", "") in Config.MANAGED_RULE_NAMES


def digest_domains(domains: list[str]) -> str:
    return hashlib.sha256(("\n".join(domains)).encode("utf-8")).hexdigest()


def generation_id() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H%M%S")


def build_rule_payload(policy: dict, expressions: list[str], enabled: bool = True) -> dict:
    expressions = [e for e in expressions if e]
    traffic = " or ".join(f"({expr})" for expr in expressions)
    payload = {
        "name": policy["policy_name"],
        "action": policy.get("action", "block"),
        "enabled": enabled,
        "filters": ["dns"],
        "traffic": traffic,
    }

    identity = policy.get("identity_condition")
    if identity:
        if "dns." in identity:
            payload["traffic"] = f"({identity}) and ({traffic})"
        else:
            payload["identity"] = identity
    return payload


def stage_lists(
    cf: CloudflareAPI,
    domains: list[str],
    policy: dict,
    generation: str,
) -> tuple[set[str], dict[str, str]]:
    chunks = [
        domains[i : i + Config.MAX_LIST_SIZE]
        for i in range(0, len(domains), Config.MAX_LIST_SIZE)
    ]
    used_ids: set[str] = set()
    expected_hashes: dict[str, str] = {}

    # Every generation gets fresh list IDs. The active rule is left untouched
    # until all new lists are successfully built.
    for index, chunk in enumerate(chunks, start=1):
        name = f"{policy['prefix']} {generation}-{index:03d}"
        digest = digest_domains(chunk)
        description = f"CGS|policy={policy['prefix']}|generation={generation}|sha256={digest}"
        list_id = cf.create_list(name, [{"value": d} for d in chunk], description)
        used_ids.add(list_id)
        expected_hashes[list_id] = digest
        logger.info("Staged %s: %,d domains", name, len(chunk))

    return used_ids, expected_hashes


def extract_list_ids(traffic: str) -> list[str]:
    return re.findall(r"\$([0-9a-fA-F-]{36})", traffic or "")


def list_hash_from_description(description: str) -> str | None:
    match = re.search(r"(?:sha256=)?([0-9a-f]{64})", description or "", re.IGNORECASE)
    return match.group(1).lower() if match else None


def prepare_policy(
    cf: CloudflareAPI,
    existing_lists: list[dict],
    existing_rules: list[dict],
    domains: list[str],
    policy: dict,
    tld_expression: str,
    generation: str,
) -> dict:
    if not domains and not policy.get("category_condition") and not (policy.get("use_spam_tld") and tld_expression):
        raise RuntimeError(f"{policy['policy_name']} compiled to an empty rule")

    chunks = [domains[i : i + Config.MAX_LIST_SIZE] for i in range(0, len(domains), Config.MAX_LIST_SIZE)]
    expected_hashes = [digest_domains(chunk) for chunk in chunks]
    existing_rule = next((r for r in existing_rules if r.get("name") == policy["policy_name"]), None)
    by_id = {l.get("id"): l for l in existing_lists}
    reusable_ids: list[str] = []

    if existing_rule:
        candidate_ids = extract_list_ids(existing_rule.get("traffic", ""))
        if len(candidate_ids) == len(expected_hashes):
            for list_id, expected_hash in zip(candidate_ids, expected_hashes):
                current = by_id.get(list_id)
                if not current:
                    break
                current_hash = list_hash_from_description(current.get("description", ""))
                if current_hash != expected_hash:
                    break
                reusable_ids.append(list_id)

    if len(reusable_ids) == len(expected_hashes):
        list_ids = reusable_ids
        hashes = {list_id: expected_hash for list_id, expected_hash in zip(list_ids, expected_hashes)}
        staged = False
        logger.info("%s: reusing existing verified list generation", policy["policy_name"])
    else:
        list_ids, hashes = stage_lists(cf, domains, policy, generation)
        staged = True

    expressions = [f"any(dns.domains[*] in ${lid})" for lid in sorted(list_ids)]
    if policy.get("use_spam_tld") and tld_expression:
        expressions.append(tld_expression)
    if policy.get("category_condition"):
        expressions.append(policy["category_condition"])

    enabled = existing_rule.get("enabled", True) if existing_rule else True
    payload = build_rule_payload(policy, expressions, enabled=enabled)
    rule_change_needed = not existing_rule or any(
        existing_rule.get(field) != payload.get(field)
        for field in ("name", "action", "enabled", "filters", "traffic", "identity")
    )

    return {
        "policy": policy,
        "list_ids": sorted(list_ids),
        "hashes": hashes,
        "traffic": payload["traffic"],
        "identity": payload.get("identity", ""),
        "enabled": enabled,
        "existing_rule": existing_rule,
        "staged": staged,
        "rule_change_needed": rule_change_needed,
        "tld_expression": tld_expression,
    }


def activate_staged_policies(
    cf: CloudflareAPI,
    staged: list[dict],
) -> list[dict]:
    activations: list[dict] = []
    try:
        for deployment in staged:
            policy = deployment["policy"]
            old_rule = deployment["existing_rule"]
            if not deployment["rule_change_needed"]:
                logger.info("Rule unchanged: %s", policy["policy_name"])
                deployment["created_rule"] = False
                deployment["rule_id"] = old_rule.get("id") if old_rule else None
                activations.append(deployment)
                continue

            payload = {
                "name": policy["policy_name"],
                "action": policy.get("action", "block"),
                "enabled": deployment["enabled"],
                "filters": ["dns"],
                "traffic": deployment["traffic"],
            }
            if deployment["identity"]:
                payload["identity"] = deployment["identity"]

            if old_rule:
                previous_payload = {
                    "name": old_rule.get("name"),
                    "action": old_rule.get("action", policy.get("action", "block")),
                    "enabled": old_rule.get("enabled", True),
                    "filters": old_rule.get("filters", ["dns"]),
                    "traffic": old_rule.get("traffic", ""),
                }
                if old_rule.get("identity"):
                    previous_payload["identity"] = old_rule["identity"]
                cf.update_rule(old_rule["id"], payload)
                deployment["rule_id"] = old_rule["id"]
                deployment["old_rule_payload"] = previous_payload
                deployment["created_rule"] = False
                logger.info("Activated generation for %s", policy["policy_name"])
            else:
                rule_id = cf.create_rule(payload)
                deployment["rule_id"] = rule_id
                deployment["created_rule"] = True
                logger.info("Created rule %s", policy["policy_name"])
            activations.append(deployment)
        return activations
    except Exception:
        logger.exception("Activation failed. Attempting rollback of already-switched rules.")
        for deployment in reversed(activations):
            if not deployment.get("rule_change_needed"):
                continue
            try:
                if deployment.get("created_rule"):
                    if deployment.get("rule_id"):
                        cf.delete_rule(deployment["rule_id"])
                elif deployment.get("old_rule_payload"):
                    cf.update_rule(deployment["rule_id"], deployment["old_rule_payload"])
            except Exception as rollback_exc:
                logger.critical("Rollback failed for %s: %s", deployment["policy"]["policy_name"], rollback_exc)
        raise


def verify_all_deployments(
    cf: CloudflareAPI,
    deployments: list[dict],
    retries: int = 5,
    delay: float = 2.0,
) -> tuple[list[dict], list[dict]]:
    last_error = None
    for attempt in range(1, retries + 1):
        try:
            lists = cf.get_lists()
            rules = cf.get_rules()
            by_id = {l.get("id"): l for l in lists}
            rules_by_name = {r.get("name"): r for r in rules}
            for deployment in deployments:
                name = deployment["policy"]["policy_name"]
                rule = rules_by_name.get(name)
                if not rule:
                    raise RuntimeError(f"Verification failed: rule {name} not found")
                if rule.get("traffic") != deployment["traffic"]:
                    raise RuntimeError(f"Verification failed: traffic mismatch for {name}")
                if rule.get("identity", "") != deployment["identity"]:
                    raise RuntimeError(f"Verification failed: identity mismatch for {name}")
                for list_id, expected_hash in deployment["hashes"].items():
                    current = by_id.get(list_id)
                    if not current:
                        raise RuntimeError(f"Verification failed: list {list_id} not found")
                    if f"sha256={expected_hash}" not in current.get("description", ""):
                        raise RuntimeError(f"Verification failed: list hash mismatch for {list_id}")
            return lists, rules
        except Exception as exc:
            last_error = exc
            logger.warning("Deployment verification attempt %d/%d failed: %s", attempt, retries, exc)
            if attempt < retries:
                time.sleep(delay)
    raise RuntimeError(str(last_error))


def cleanup_old_resources(
    cf: CloudflareAPI,
    lists: list[dict],
    rules: list[dict],
    active_list_ids: set[str],
    active_rule_names: set[str],
) -> None:
    # Disabled policies are removed only after the replacement deployment has
    # been fully verified. This preserves enforcement during the build/verify phases.
    for rule in rules:
        name = rule.get("name", "")
        if name in Config.MANAGED_RULE_NAMES and name not in active_rule_names:
            try:
                cf.delete_rule(rule["id"])
                logger.info("Removed disabled managed rule: %s", name)
            except Exception as exc:
                raise RuntimeError(f"Could not remove disabled managed rule {name}: {exc}") from exc

    for item in lists:
        list_id = item.get("id")
        name = item.get("name", "")
        if list_id in active_list_ids or not managed_list(name):
            continue
        desc = item.get("description", "")
        owned = desc.startswith("CGS|") or re.fullmatch(
            r"L_(Relaxed|Restrictive|AllowSpam) \d{3}", name
        )
        if not owned:
            continue
        try:
            cf.delete_list(list_id)
            logger.info("Deleted stale managed list: %s", name)
        except Exception as exc:
            logger.warning("Could not delete stale list %s: %s", name, exc)


def load_previous_metrics() -> dict:
    try:
        return json.loads(Config.SOURCE_METRICS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_json(path: Path, payload: dict) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def validate_source_metrics(results: list[SourceResult], previous: dict) -> None:
    anomalies = []
    for result in results:
        old = previous.get(result.name, {})
        old_parsed = int(old.get("parsed", 0) or 0)
        if old_parsed > 0:
            drop = (old_parsed - result.parsed) / old_parsed
            if drop > Config.MAX_SOURCE_DROP_PCT:
                anomalies.append(
                    f"{result.name}: parsed count dropped {drop:.0%} ({old_parsed:,} -> {result.parsed:,})"
                )
    if anomalies:
        raise RuntimeError("Source anomaly detected; refusing Cloudflare mutation: " + "; ".join(anomalies))


def write_aggregate_file(compiled: list[tuple[dict, list[str]]]) -> None:
    aggregate = set()
    for _, domains in compiled:
        aggregate.update(domains)
    atomic_write_text(
        Config.AGGREGATE_FILE,
        "".join(f"{domain}\n" for domain in sorted(aggregate)),
    )


# Global used only during cleanup diagnostics.
stateful_deployments: list[dict] = []


def main() -> None:
    started = time.perf_counter()
    Config.validate()
    policies = get_active_policies()
    if not policies:
        raise RuntimeError("No enabled policies are configured")
    logger.info("Active policies: %s", ", ".join(p["policy_name"] for p in policies))

    cf = CloudflareAPI()
    download_session = build_session(
        Config.DOWNLOAD_RETRIES,
        Config.MAX_WORKERS,
        "cloudflare-gateway-sync-source/4",
    )

    active_sources = get_active_sources()
    if any("HaGeZi Spam Allow" in p.get("include", []) for p in policies):
        active_sources.append(SPAM_ALLOW_SOURCE)

    checker = None
    if any(source.get("enable_relevance") for source in active_sources):
        checker = RelevanceChecker(download_session)
        checker.build_dataset()

    results: list[SourceResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = [pool.submit(fetch_source, download_session, source, checker) for source in active_sources]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    errors = {r.name: r.errors for r in results if r.errors}
    if errors and Config.REQUIRE_ALL_ACTIVE_SOURCES:
        raise RuntimeError(
            "One or more active sources failed: "
            + "; ".join(f"{name}: {', '.join(errs)}" for name, errs in sorted(errors.items()))
        )

    previous_metrics = load_previous_metrics()
    validate_source_metrics(results, previous_metrics)

    fetched_lists = {r.name: r.domains for r in results}
    spam_tlds: set[str] = set()
    tld_expression = ""
    if any(p.get("use_spam_tld") for p in policies):
        spam_tlds = fetch_spam_tlds(download_session)
        tld_expression = build_cloudflare_tld_expression(spam_tlds)

    compiled = build_policy_sets(policies, fetched_lists, spam_tlds)
    total_domains = sum(len(domains) for _, domains in compiled)
    if total_domains > Config.TOTAL_QUOTA:
        raise RuntimeError(
            f"Compiled payload {total_domains:,} exceeds configured safety quota {Config.TOTAL_QUOTA:,}"
        )

    # Validate the compilation before touching Cloudflare.
    for policy, domains in compiled:
        if not domains and not policy.get("category_condition") and not (policy.get("use_spam_tld") and tld_expression):
            raise RuntimeError(f"Policy {policy['policy_name']} compiled empty")

    existing_lists = cf.get_lists()
    existing_rules = cf.get_rules()
    generation = generation_id()
    stateful_deployments.clear()
    all_active_list_ids: set[str] = set()

    # Phase 1: prepare every policy. New lists are staged only when the existing
    # generation cannot satisfy the desired domain hashes. Active rules remain live.
    staged = []
    for policy, domains in compiled:
        deployment = prepare_policy(
            cf, existing_lists, existing_rules, domains, policy, tld_expression, generation
        )
        staged.append(deployment)
        all_active_list_ids.update(deployment["list_ids"])

    # Phase 2: switch changed rules. A rollback is attempted if activation fails.
    stateful_deployments.extend(activate_staged_policies(cf, staged))

    # Phase 3: verify the complete active state before deleting anything.
    verified_lists, verified_rules = verify_all_deployments(cf, stateful_deployments)

    # Phase 4: remove superseded managed lists only after verification succeeds.
    cleanup_old_resources(
        cf,
        verified_lists,
        verified_rules,
        all_active_list_ids,
        {d["policy"]["policy_name"] for d in stateful_deployments},
    )

    write_aggregate_file(compiled)

    source_metrics = {
        r.name: {
            "parsed": r.parsed,
            "kept": r.kept,
            "pruned": r.pruned,
            "timestamp": utc_now(),
        }
        for r in results
    }
    write_json(Config.SOURCE_METRICS_FILE, source_metrics)

    state = {
        "status": "ok",
        "timestamp": utc_now(),
        "generation": generation,
        "active_tier": Config.ACTIVE_TIER or "all",
        "policies": [
            {
                "name": policy["policy_name"],
                "prefix": policy["prefix"],
                "domain_count": len(domains),
                "use_spam_tld": bool(policy.get("use_spam_tld")),
            }
            for policy, domains in compiled
        ],
        "total_domains": total_domains,
        "spam_tld_count": len(spam_tlds),
        "spam_tld_expression_length": len(tld_expression),
        "sources": source_metrics,
        "cloudflare": {
            "managed_rules": [
                {
                    "name": d["policy"]["policy_name"],
                    "id": d.get("rule_id"),
                    "enabled": d["enabled"],
                    "list_ids": d["list_ids"],
                }
                for d in stateful_deployments
            ],
            "managed_lists": [
                {
                    "id": l.get("id"),
                    "name": l.get("name"),
                    "count": l.get("count"),
                    "description": l.get("description", ""),
                }
                for l in verified_lists
                if managed_list(l.get("name", "")) and l.get("id") in all_active_list_ids
            ],
        },
    }
    write_json(Config.STATE_FILE, state)

    elapsed = time.perf_counter() - started
    logger.info("Sync complete in %.2fs", elapsed)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        logger.exception("Sync failed before a verified deployment was completed")
        sys.exit(1)
