import os
import re
import logging
import requests
import concurrent.futures
import time
import math
from collections import Counter
from datetime import datetime
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ---------------------------------------------------------------------------
# 1. Config
# ---------------------------------------------------------------------------
class Config:
    API_TOKEN        = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID       = os.environ.get("ACCOUNT_ID", "")
    MAX_LIST_SIZE    = 1000
    MAX_RETRIES      = 3
    TOTAL_QUOTA      = 300_000
    REQUEST_TIMEOUT  = (5, 25)
    MAX_WORKERS      = 5
    TOP_KEYWORDS     = 15
    TOP_TLDS         = 10

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
    "stats_filename": "README_STATS.md",
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
        # --- ACTIVE ---
        "HaGeZi Pro++":                   "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
        "Hagezi NSFW":                    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
        "Hagezi Anti-Piracy":             "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
        "HaGeZi Fake":                    "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
        "Hagezi SafeSearch Not Supported":"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",

        # --- DISABLED / OPTIONAL ---
        # "HaGeZi Ultimate":    "..."
        # "HaGeZi Pro":         "..."
        # "1Hosts Lite":        "..."
        # "Hagezi Social Media":"..."
    },
}

# ---------------------------------------------------------------------------
# 2. Cloudflare API Client
# ---------------------------------------------------------------------------
class CloudflareAPI:
    def __init__(self):
        self.base_url = (
            f"https://api.cloudflare.com/client/v4/accounts"
            f"/{Config.ACCOUNT_ID}/gateway"
        )
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


def is_valid_domain(
    domain: str,
    kw_ex: Counter,
    tld_ex: Counter,
    other_ex: Counter,
) -> str | None:
    domain = domain.strip().strip(".")

    if not domain or _BAD_CHARS.intersection(domain):
        other_ex["Malformed/Wildcard"] += 1
        return None

    if "." not in domain or "xn--" in domain or IP_PATTERN.match(domain):
        other_ex["Invalid/IP/IDN"] += 1
        return None

    tld = domain.rsplit(".", 1)[-1]
    if tld in _BANNED_TLDS:
        tld_ex[tld] += 1
        return None

    for kw in _OFFLOAD_KW:
        if kw in domain:
            kw_ex[kw] += 1
            return None

    return domain


def fetch_url(name: str, url: str) -> tuple:
    logger.info(f"Fetching: {name}")
    kw_ex, tld_ex, other_ex = Counter(), Counter(), Counter()
    valid_domains: set[str] = set()
    raw_count = 0

    try:
        resp = requests.get(url, timeout=Config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line[0] in ("#", "!", "/"):
                continue
            raw_domain = line.split()[-1].lower()
            raw_count += 1
            cleaned = is_valid_domain(raw_domain, kw_ex, tld_ex, other_ex)
            if cleaned:
                valid_domains.add(cleaned)
        logger.info(f"Done: {name} — {len(valid_domains):,} valid")
    except Exception as exc:
        logger.error(f"Error fetching {name}: {exc}")

    return name, raw_count, valid_domains, kw_ex, tld_ex, other_ex


def optimize_domains(domains: set[str]) -> list[str]:
    """
    Tree-prune subdomains: reverse each domain so subdomain relationships
    become string-prefix relationships, sort, skip any entry whose reversed
    form starts with the last-kept reversed entry + '.'.
    """
    reversed_sorted = sorted(d[::-1] for d in domains)
    optimized: list[str] = []
    last_kept: str | None = None
    for rev in reversed_sorted:
        if last_kept and rev.startswith(last_kept + "."):
            continue
        optimized.append(rev)
        last_kept = rev
    return [d[::-1] for d in optimized]


def _domain_entropy(domain: str) -> float:
    n = len(domain)
    return -sum(
        (cnt / n) * math.log2(cnt / n)
        for cnt in Counter(domain).values()
    )

# ---------------------------------------------------------------------------
# 4. Cloudflare Sync
# ---------------------------------------------------------------------------

def sync_to_cloudflare(cf: CloudflareAPI, domains: list[str]) -> int:
    if not domains:
        logger.error("Optimised list is empty — aborting sync.")
        return 0

    if len(domains) > Config.TOTAL_QUOTA:
        logger.warning(f"Quota exceeded — slicing to {Config.TOTAL_QUOTA:,}")
        domains = domains[: Config.TOTAL_QUOTA]

    sorted_domains = sorted(domains)
    chunks = [
        sorted_domains[i : i + Config.MAX_LIST_SIZE]
        for i in range(0, len(sorted_domains), Config.MAX_LIST_SIZE)
    ]

    Path(MASTER_CONFIG["filename"]).write_text("\n".join(sorted_domains))

    existing = sorted(
        [l for l in cf.get_lists() if MASTER_CONFIG["prefix"] in l["name"]],
        key=lambda x: x["name"],
    )

    used_ids: list[str] = []

    # Step 1 — Create / update lists
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

    # Step 2 — Update firewall rule BEFORE deleting old lists
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
    else:
        cf.create_rule(payload)
    logger.info("Firewall rule updated.")

    # Step 3 — Cleanup stale lists
    for stale in existing[len(chunks):]:
        try:
            cf.delete_list(stale["id"])
            logger.info(f"Deleted stale list: {stale['name']} ({stale['id']})")
        except Exception as exc:
            logger.error(f"Failed to delete stale list {stale['id']}: {exc}")

    return len(chunks)

# ---------------------------------------------------------------------------
# 5. Report Generation
# ---------------------------------------------------------------------------

def _bar(value: float, total: float, width: int = 28) -> str:
    """Unicode block progress bar — ████████░░░░  62.3%"""
    pct    = min(value / total, 1.0) if total else 0.0
    filled = round(pct * width)
    return f"{'█' * filled}{'░' * (width - filled)}  {pct * 100:.1f}%"


def _quota_gauge(used: int, total: int) -> str:
    pct = used / total * 100 if total else 0
    if pct < 50:   status = "🟢 Healthy"
    elif pct < 80: status = "🟡 Moderate"
    elif pct < 95: status = "🟠 High"
    else:          status = "🔴 Critical"
    return f"{_bar(used, total, 40)}  {used:,} / {total:,}  [{status}]"


def _sparkline(values: list[int], width: int = 20) -> str:
    """Mini sparkline using unicode block chars."""
    blocks = " ▁▂▃▄▅▆▇█"
    if not values or max(values) == 0:
        return blocks[0] * width
    hi = max(values)
    return "".join(blocks[min(round(v / hi * 8), 8)] for v in values)


def generate_markdown_report(stats: dict) -> None:
    now       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_raw = stats["total_raw"] or 1

    kept_pct  = round(stats["final_size"]  / total_raw * 100, 2)
    kw_pct    = round(stats["kw_total"]    / total_raw * 100, 2)
    tld_pct   = round(stats["tld_total"]   / total_raw * 100, 2)
    dup_pct   = round((stats["duplicates"] + stats["tree_removed"]) / total_raw * 100, 2)
    quota_pct = round(stats["final_size"]  / Config.TOTAL_QUOTA * 100, 2)

    # ── Source bar chart ─────────────────────────────────────────────────────
    src_names  = [f'"{n[:22]}"' for n in stats["sources"].keys()]
    src_valid  = [d["valid"]    for d in stats["sources"].values()]
    src_unique = [d["unique_to_source"] for d in stats["sources"].values()]

    src_bar_chart = f"""```mermaid
xychart-beta horizontal
    title "Source — Valid Domains Ingested"
    x-axis {src_names}
    y-axis "Domains"
    bar {src_valid}
    line {src_unique}
```"""

    # ── Keyword bar chart ────────────────────────────────────────────────────
    top_kw    = stats["kw_ex"].most_common(10)
    kw_labels = [f'"{k[:14]}"' for k, _ in top_kw]
    kw_counts = [c for _, c in top_kw]

    kw_bar_chart = f"""```mermaid
xychart-beta
    title "Top 10 Offloaded Keyword Hits"
    x-axis {kw_labels}
    y-axis "Blocked Domains"
    bar {kw_counts}
```"""

    # ── TLD bar chart ────────────────────────────────────────────────────────
    top_tlds   = stats["tld_ex"].most_common(Config.TOP_TLDS)
    tld_labels = [f'".{t[:10]}"' for t, _ in top_tlds]
    tld_counts = [c for _, c in top_tlds]

    tld_bar_chart = f"""```mermaid
xychart-beta
    title "Top Banned TLD Hits"
    x-axis {tld_labels}
    y-axis "Blocked Domains"
    bar {tld_counts}
```"""

    # ── Pipeline funnel pie ──────────────────────────────────────────────────
    funnel_chart = f"""```mermaid
pie showData title DNS Blocklist Pipeline Breakdown
    "Active Rules"     : {stats['final_size']}
    "Keyword Filtered" : {stats['kw_total']}
    "Banned TLD"       : {stats['tld_total']}
    "Deduplication"    : {stats['duplicates']}
    "Tree Pruned"      : {stats['tree_removed']}
```"""

    # ── Source quality quadrant ──────────────────────────────────────────────
    quad_points = "\n".join(
        f"        {name[:20]}({round(d['unique_to_source']/d['valid']*100 if d['valid'] else 0, 0)}, "
        f"{round(sum(len(x) for x in d['set'])/len(d['set']) if d['set'] else 0, 0)})"
        for name, d in stats["sources"].items()
    )
    quadrant_chart = f"""```mermaid
quadrantChart
    title Source Quality Matrix (Uniqueness vs Avg Domain Length)
    x-axis "Low Uniqueness" --> "High Uniqueness"
    y-axis "Short Domains" --> "Long Domains"
    quadrant-1 High Signal
    quadrant-2 Deep Coverage
    quadrant-3 Redundant
    quadrant-4 Short & Unique
{quad_points}
```"""

    # ── Execution timeline ───────────────────────────────────────────────────
    timeline_chart = f"""```mermaid
timeline
    title Sync Pipeline Execution
    section Ingest
        Concurrent Fetch   : {len(stats['sources'])} sources
                           : {stats['total_raw']:,} raw domains
    section Filter
        Keyword Offload    : -{stats['kw_total']:,} domains
        TLD Blocklist      : -{stats['tld_total']:,} domains
        Deduplication      : -{stats['duplicates']:,} duplicates
    section Optimise
        Subdomain Tree Prune : -{stats['tree_removed']:,} subdomains
        Final Domain Pool    : {stats['final_size']:,} unique rules
    section Deploy
        Cloudflare Sync    : {stats['chunks']} list chunks
                           : 1 gateway firewall rule
```"""

    # ── Source uniqueness table ──────────────────────────────────────────────
    source_rows = "\n".join(
        f"| {name} "
        f"| {d['raw']:>10,} "
        f"| {d['valid']:>10,} "
        f"| {d['unique_to_source']:>9,} "
        f"| `{_bar(d['unique_to_source'], d['valid'], 16)}` "
        f"| {'🥇' if i == 0 else '🥈' if i == 1 else '🥉' if i == 2 else '·'} |"
        for i, (name, d) in enumerate(
            sorted(stats["sources"].items(), key=lambda x: x[1]["unique_to_source"], reverse=True)
        )
    )

    # ── Keyword table ────────────────────────────────────────────────────────
    kw_max = kw_counts[0] if kw_counts else 1
    kw_table_rows = "\n".join(
        f"| `{kw:<20}` | {count:>8,} | `{_bar(count, kw_max, 22)}` |"
        for kw, count in stats["kw_ex"].most_common(Config.TOP_KEYWORDS)
    )

    # ── TLD table ────────────────────────────────────────────────────────────
    tld_max = tld_counts[0] if tld_counts else 1
    tld_table_rows = "\n".join(
        f"| `.{tld:<12}` | {count:>8,} | `{_bar(count, tld_max, 22)}` |"
        for tld, count in stats["tld_ex"].most_common(Config.TOP_TLDS)
    )

    # ── Entropy sparkline across sample ─────────────────────────────────────
    buckets = [0] * 10
    for d in (stats.get("sample_domains") or []):
        e   = _domain_entropy(d)
        idx = min(int(e / 4.0 * 10), 9)
        buckets[idx] += 1
    spark = _sparkline(buckets)

    # ── Badge colour for quota ───────────────────────────────────────────────
    badge_colour = "brightgreen" if quota_pct < 50 else "yellow" if quota_pct < 80 else "critical"
    ts_badge     = now.replace(" ", "_").replace(":", "-")

    # ────────────────────────────────────────────────────────────────────────
    # Full report
    # ────────────────────────────────────────────────────────────────────────
    md = f"""<!--
  Auto-generated by sync_blocklist.py — do not edit manually.
  Changes will be overwritten on next sync.
-->

<div align="center">

# 🛡️ DNS Intelligence Report

**Cloudflare Gateway · Ads, Tracker, Telemetry & Malware Blocklist**

![Last Sync](https://img.shields.io/badge/Last_Sync-{ts_badge}-blue?style=for-the-badge&logo=cloudflare&logoColor=white)
![Active Rules](https://img.shields.io/badge/Active_Rules-{stats['final_size']:,}-success?style=for-the-badge&logo=shield&logoColor=white)
![Quota](https://img.shields.io/badge/Quota-{quota_pct}%25-{badge_colour}?style=for-the-badge)
![Runtime](https://img.shields.io/badge/Runtime-{stats['runtime']}s-lightgrey?style=for-the-badge&logo=lightning&logoColor=white)
![Sources](https://img.shields.io/badge/Sources-{len(stats['sources'])}_Active-informational?style=for-the-badge)

</div>

---

## ⚡ At a Glance

| | Metric | Value | |
|:---:|:---|---:|:---|
| 🌐 | **Sources Active** | `{len(stats['sources'])}` | feeds ingested this sync |
| 📥 | **Raw Domains Fetched** | `{stats['total_raw']:,}` | before any filtering |
| ✅ | **Active Block Rules** | `{stats['final_size']:,}` | pushed to Cloudflare |
| 🧹 | **Total Filtered Out** | `{stats['total_raw'] - stats['final_size']:,}` | noise removed |
| 🔁 | **Duplicates Removed** | `{stats['duplicates']:,}` | cross-source overlap |
| 🌳 | **Subdomains Tree-Pruned** | `{stats['tree_removed']:,}` | covered by parent rule |
| ⏱️ | **Sync Runtime** | `{stats['runtime']}s` | wall clock |
| 📦 | **Cloudflare List Chunks** | `{stats['chunks']}` | × {Config.MAX_LIST_SIZE:,} domains each |

---

## 📊 Pipeline Funnel

> From **{stats['total_raw']:,} raw domains** down to **{stats['final_size']:,} precision block rules** — a {round((1 - stats['final_size']/total_raw)*100, 1)}% reduction in noise.

{funnel_chart}

---

## 🗺️ Execution Timeline

{timeline_chart}

---

## 📉 Cloudflare Quota Consumption

```
Gateway Rule Limit: {Config.TOTAL_QUOTA:,}
{_quota_gauge(stats['final_size'], Config.TOTAL_QUOTA)}
```

### Filter Stage Breakdown

| Stage | Domains | Share of Raw | Visual |
| :--- | ---: | ---: | :--- |
| 🔴 Keyword Filtered  | {stats['kw_total']:,}  | {kw_pct}%  | `{_bar(stats['kw_total'], total_raw)}` |
| 🟠 Banned TLD        | {stats['tld_total']:,} | {tld_pct}% | `{_bar(stats['tld_total'], total_raw)}` |
| 🟡 Dedup + Tree Prune | {stats['duplicates'] + stats['tree_removed']:,} | {dup_pct}% | `{_bar(stats['duplicates'] + stats['tree_removed'], total_raw)}` |
| 🟢 **Active Rules**  | **{stats['final_size']:,}** | **{kept_pct}%** | `{_bar(stats['final_size'], total_raw)}` |

---

## 🛰️ Source Intelligence

{src_bar_chart}

### Uniqueness Ranking

> The **line** in the chart above shows unique-only contribution per source.
> A source with high valid count but low uniqueness is largely redundant.

| Source | Raw Ingest | Valid | Unique Only | Uniqueness Bar | Rank |
| :--- | ---: | ---: | ---: | :--- | :---: |
{source_rows}

### Source Quality Matrix

> **X-axis:** what % of a source's domains are unique (not in any other source).
> **Y-axis:** average domain length — longer domains tend to be more specific / less spammy.

{quadrant_chart}

---

## 🚫 Keyword Filter Intelligence

{kw_bar_chart}

### Full Keyword Hit Table (Top {Config.TOP_KEYWORDS})

| Keyword | Blocked | Distribution |
| :--- | ---: | :--- |
{kw_table_rows}

---

## 🌍 Banned TLD Intelligence

{tld_bar_chart}

### Top Offending TLDs

| TLD | Blocked | Distribution |
| :--- | ---: | :--- |
{tld_table_rows}

---

## 🔬 Domain Health & Entropy

| Metric | Value | Interpretation |
| :--- | :--- | :--- |
| **Avg Shannon Entropy** | `{stats['avg_entropy']} bits` | {'🟢 Normal — human-readable domains' if stats['avg_entropy'] < 3.5 else '🟡 Elevated — some algorithmic domains' if stats['avg_entropy'] < 4.2 else '🔴 High — possible DGA/random domain activity'} |
| **Max Domain Length** | `{stats['max_len']} chars` | longest domain in the active ruleset |
| **Entropy Distribution** | `{spark}` | low entropy → high entropy (across 5k sample) |

> **Shannon Entropy** measures character randomness per domain string.
> Scores above `4.0` may indicate algorithmically-generated domains (DGA malware).
> Human-readable ad/tracker domains typically score between `2.5` and `3.5`.

---

## ⚙️ Configuration Reference

| Parameter | Value | Description |
| :--- | :--- | :--- |
| `TOTAL_QUOTA` | `{Config.TOTAL_QUOTA:,}` | Cloudflare Gateway rule limit |
| `MAX_LIST_SIZE` | `{Config.MAX_LIST_SIZE:,}` | Domains per list chunk |
| `MAX_WORKERS` | `{Config.MAX_WORKERS}` | Concurrent fetch threads |
| `MAX_RETRIES` | `{Config.MAX_RETRIES}` | Per-request retry attempts |
| `TOP_KEYWORDS` | `{Config.TOP_KEYWORDS}` | Rows shown in keyword table |
| `TOP_TLDS` | `{Config.TOP_TLDS}` | Rows shown in TLD table |

---

<div align="center">

*Auto-generated · `{now}` · [sync_blocklist.py](./sync_blocklist.py)*

</div>
"""

    Path(MASTER_CONFIG["stats_filename"]).write_text(md)
    logger.info(f"Report written → {MASTER_CONFIG['stats_filename']}")

# ---------------------------------------------------------------------------
# 6. Main
# ---------------------------------------------------------------------------

def main() -> None:
    start = time.perf_counter()

    Config.validate()
    cf = CloudflareAPI()

    all_source_data: dict[str, dict] = {}
    global_domain_set: set[str]      = set()
    global_kw_ex    = Counter()
    global_tld_ex   = Counter()
    global_other_ex = Counter()
    total_raw_fetched = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as pool:
        futures = {
            pool.submit(fetch_url, name, url): name
            for name, url in MASTER_CONFIG["urls"].items()
        }
        for future in concurrent.futures.as_completed(futures):
            name, raw_fetched, valid_set, kw_ex, tld_ex, other_ex = future.result()
            all_source_data[name] = {
                "raw":   raw_fetched,
                "valid": len(valid_set),
                "set":   valid_set,
            }
            total_raw_fetched += raw_fetched
            global_domain_set |= valid_set
            global_kw_ex.update(kw_ex)
            global_tld_ex.update(tld_ex)
            global_other_ex.update(other_ex)

    total_valid_count = sum(d["valid"] for d in all_source_data.values())
    duplicates        = total_valid_count - len(global_domain_set)

    for name, data in all_source_data.items():
        others = global_domain_set - data["set"]
        data["unique_to_source"] = len(data["set"] - others)

    optimized    = optimize_domains(global_domain_set)
    tree_removed = len(global_domain_set) - len(optimized)

    num_chunks = sync_to_cloudflare(cf, optimized)

    # Single-pass stats over optimised list
    total_entropy = 0.0
    max_len       = 0
    for d in optimized:
        total_entropy += _domain_entropy(d)
        if len(d) > max_len:
            max_len = len(d)
    avg_entropy = round(total_entropy / len(optimized), 3) if optimized else 0.0

    generate_markdown_report({
        "total_raw":      total_raw_fetched,
        "kw_total":       sum(global_kw_ex.values()),
        "tld_total":      sum(global_tld_ex.values()),
        "duplicates":     duplicates,
        "tree_removed":   tree_removed,
        "final_size":     len(optimized),
        "kw_ex":          global_kw_ex,
        "tld_ex":         global_tld_ex,
        "sources":        all_source_data,
        "avg_entropy":    avg_entropy,
        "max_len":        max_len,
        "chunks":         num_chunks,
        "runtime":        round(time.perf_counter() - start, 2),
        "sample_domains": optimized[:5_000],   # for entropy sparkline
    })

    logger.info("Done. Intelligence report generated.")


if __name__ == "__main__":
    main()
