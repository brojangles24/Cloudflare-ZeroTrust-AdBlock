import os
import sys
import tempfile
import shutil
import re
import concurrent.futures
import json
import logging
import argparse
import time
import math
from datetime import datetime
from pathlib import Path
from subprocess import run, CalledProcessError
from itertools import islice
from collections import Counter
import requests

# --- 1. Logging Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- 2. Configuration Class ---
class Config:
    API_TOKEN: str = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID: str = os.environ.get("ACCOUNT_ID", "")
    
    MAX_LIST_SIZE: int = 1000
    MAX_LISTS: int = 300 
    MAX_RETRIES: int = 5
    
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main" 
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

# --- DEFINITION OF FEEDS ---
FEED_CONFIGS = [
    {
        "name": "Ad Block Feed",
        "prefix": "Block ads",
        "policy_name": "Block Ads, Trackers and Telemetry",
        "filename": "HaGeZi_Pro.txt",
        "urls": [
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt", # Hagezi Normal
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt", # Hagezi Fake
            "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt" # Hagezi Badware Hoster
        ]
    },
    {
        "name": "Threat Intel Feed",
        "prefix": "TIF Mini",
        "policy_name": "Threat Intelligence Feed",
        "filename": "TIF_Mini.txt",
        "urls": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"]
    }
]

# --- 3. Helper Functions ---
INVALID_CHARS_PATTERN = re.compile(r'[<>&;\"\'/=\s]')
# Your provided TLD exclusion regex
EXCLUDED_TLD_PATTERN = re.compile('''r'\.(?:bid|cf|click|download|ga|gdn|gq|icu|loan|men|ml|monster|ooo|party|pw|stream|su|tk|top|win|zip)$', re.IGNORECASE''')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1', 'broadcasthost'}

def validate_config():
    if not Config.API_TOKEN:
        raise RuntimeError("API_TOKEN environment variable is not set.")
    if not Config.ACCOUNT_ID:
        raise RuntimeError("ACCOUNT_ID environment variable is not set.")

def domains_to_cf_items(domains):
    return [{"value": domain} for domain in domains if domain]

def chunked_iterable(iterable, size):
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk: break
        yield chunk

def run_command(command):
    try:
        result = run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        return result.stdout
    except CalledProcessError as e:
        raise RuntimeError(f"Command failed: {' '.join(command)}\n{e.stderr}")

def download_list(url, file_path):
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    file_path.write_bytes(response.content)

def get_nerd_metrics(domains):
    stats = {
        "longest_domain": "",
        "max_entropy_domain": "",
        "max_entropy": 0.0,
        "keyword_counts": Counter()
    }
    
    token_pattern = re.compile(r'[a-z]{4,}') 
    
    for d in domains:
        if len(d) > len(stats['longest_domain']):
            stats['longest_domain'] = d
            
        prob = [float(d.count(c)) / len(d) for c in dict.fromkeys(list(d))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        
        if entropy > stats['max_entropy']:
            stats['max_entropy'] = entropy
            stats['max_entropy_domain'] = d

        stats['keyword_counts'].update(token_pattern.findall(d))

    return stats

# --- 4. Cloudflare API Client ---
class CloudflareAPI:
    def __init__(self, account_id, api_token, max_retries):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
        self.max_retries = max_retries
        self.session = None

    def __enter__(self):
        self.session = requests.Session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.session: self.session.close()

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}/{endpoint}"
        for i in range(self.max_retries + 1):
            try:
                resp = self.session.request(method, url, headers=self.headers, **kwargs)
                if resp.status_code == 429 or resp.status_code >= 500:
                    time.sleep((i + 1) * 2)
                    continue
                resp.raise_for_status()
                return resp.json()
            except Exception as e:
                if i == self.max_retries: raise e
        return None

    def get_lists(self): return self._request("GET", "lists")
    def get_list_items(self, lid, limit): return self._request("GET", f"lists/{lid}/items?limit={limit}")
    def update_list(self, lid, append, remove): return self._request("PATCH", f"lists/{lid}", json={"append": append, "remove": remove})
    def create_list(self, name, items): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items})
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def get_rules(self): return self._request("GET", "rules")
    def create_rule(self, data): return self._request("POST", "rules", json=data)
    def update_rule(self, rid, data): return self._request("PUT", f"rules/{rid}", json=data)
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")

# --- 5. Workflow Functions ---
def fetch_domains(feed_config):
    start_time = time.time()
    logger.info(f"--- Fetching: {feed_config['name']} ---")
    temp_dir = Path(tempfile.mkdtemp())
    unique_domains = set()
    tld_counter = Counter()
    
    stats = {
        "raw_lines": 0, "valid_domains": 0, "excluded_tld": 0,
        "dedup_count": 0, "time_taken": 0.0, "tlds": Counter()
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as exec:
        {exec.submit(download_list, url, temp_dir/f"l_{i}.txt"): url for i, url in enumerate(feed_config['urls'])}

    for fpath in temp_dir.glob("l_*.txt"):
        with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(('#', '!', '//')): continue
                
                stats["raw_lines"] += 1
                parts = line.split()
                if not parts: continue
                candidate = parts[-1].lower()
                
                if '.' in candidate and not INVALID_CHARS_PATTERN.search(candidate):
                    if candidate not in COMMON_JUNK_DOMAINS:
                        if EXCLUDED_TLD_PATTERN.search(candidate):
                            stats["excluded_tld"] += 1
                            continue
                            
                        tld = candidate.split('.')[-1]
                        unique_domains.add(candidate)
                        tld_counter[tld] += 1
                        
    shutil.rmtree(temp_dir)
    stats["valid_domains"] = len(unique_domains)
    stats["time_taken"] = time.time() - start_time
    stats["tlds"] = tld_counter
    return unique_domains, stats

def save_and_sync(cf, feed, domains, force=False):
    out = Path(feed['filename'])
    new_data = '\n'.join(sorted(domains)) + '\n'
    
    if out.exists() and not force and out.read_text(encoding='utf-8') == new_data:
        return False

    out.write_text(new_data, encoding='utf-8')
    if not domains: return True

    all_lists = cf.get_lists().get('result') or []
    prefix = feed['prefix']
    existing = [l for l in all_lists if prefix in l.get('name', '')]
    used_ids = []
    excess = [l['id'] for l in existing]

    for i, chunk in enumerate(chunked_iterable(sorted(domains), Config.MAX_LIST_SIZE)):
        items = domains_to_cf_items(chunk)
        if excess:
            lid = excess.pop(0)
            old = cf.get_list_items(lid, Config.MAX_LIST_SIZE).get('result') or []
            rem = [item['value'] for item in old if item.get('value')]
            cf.update_list(lid, items, rem)
            used_ids.append(lid)
        else:
            res = cf.create_list(f"{prefix} - {i+1:03d}", items)
            used_ids.append(res['result']['id'])

    rules = cf.get_rules().get('result') or []
    rid = next((r['id'] for r in rules if r.get('name') == feed['policy_name']), None)
    clauses = [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in used_ids]
    expr = {"or": clauses} if len(clauses) > 1 else clauses[0]
    payload = {"name": feed['policy_name'], "conditions": [{"type": "traffic", "expression": expr}], "action": "block", "enabled": True, "filters": ["dns"]}
    
    if rid: cf.update_rule(rid, payload)
    else: cf.create_rule(payload)
    
    for lid in excess: cf.delete_list(lid)
    return True

def git_push(files):
    run_command(["git", "config", "--global", "user.email", f"{Config.GITHUB_ACTOR_ID}+{Config.GITHUB_ACTOR}@users.noreply.github.com"])
    run_command(["git", "config", "--global", "user.name", f"{Config.GITHUB_ACTOR}[bot]"])
    changed = []
    for f in files:
        try: 
            run_command(["git", "diff", "--exit-code", f])
        except:
            run_command(["git", "add", f])
            changed.append(f)
    if changed:
        run_command(["git", "commit", "-m", f"Update blocklists & stats: {', '.join(changed)}"])
        run_command(["git", "push", "origin", Config.TARGET_BRANCH])

def write_markdown_stats(feed_stats, filename="STATS.md"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_raw = sum(d['raw_lines'] for d in feed_stats.values())
    total_excluded = sum(d['excluded_tld'] for d in feed_stats.values())
    total_dedup = sum(d['dedup_count'] for d in feed_stats.values())
    total_final = sum(d['valid_domains'] for d in feed_stats.values())
    
    md_lines = [
        f"# 🛡️ Blocklist Sync Statistics",
        f"*Last updated: {now}*",
        "",
        "| Feed Name | Raw Lines | TLD Excluded | Overlap (TIF) | Final Count | Time (s) |",
        "|:---|---:|---:|---:|---:|---:|",
    ]
    
    for name, data in feed_stats.items():
        excl_pct = (data['excluded_tld'] / data['raw_lines'] * 100) if data['raw_lines'] > 0 else 0.0
        md_lines.append(
            f"| **{name}** | {data['raw_lines']:,} | {data['excluded_tld']:,} ({excl_pct:.1f}%) | {data['dedup_count']:,} | {data['valid_domains']:,} | {data['time_taken']:.2f} |"
        )
        
    md_lines.append(f"| **TOTALS** | **{total_raw:,}** | **{total_excluded:,}** | **{total_dedup:,}** | **{total_final:,}** | |")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(md_lines))
    return filename

def print_console_summary(feed_stats, datasets):
    RST, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    CYAN, GREEN, YELLOW, RED, MAGENTA, BLUE = "\033[36m", "\033[32m", "\033[33m", "\033[31m", "\033[35m", "\033[34m"

    t_raw = sum(d['raw_lines'] for d in feed_stats.values())
    t_final = sum(d['valid_domains'] for d in feed_stats.values())
    t_time = sum(d['time_taken'] for d in feed_stats.values())
    
    global_tlds = Counter()
    for d in feed_stats.values():
        global_tlds.update(d.get('tlds', Counter()))
    top_tlds = global_tlds.most_common(5)

    velocity = int(t_raw / t_time) if t_time > 0 else 0
    junk_ratio = ((t_raw - t_final) / t_raw * 100) if t_raw > 0 else 0
    
    all_domains = set().union(*datasets.values())
    nerd_stats = get_nerd_metrics(all_domains)

    w = {"name": 22, "raw": 10, "excl": 16, "ovrl": 12, "final": 10, "time": 8}
    def border(c, l, r, i): return f"{DIM}{l}{i.join([c * w[k] for k in w])}{r}{RST}"

    print("\n" + border("═", "╔", "╗", "╦"))
    headers = [f"{'FEED SOURCE':<{w['name']}}", f"{'RAW':>{w['raw']}}", f"{'TLD EXCL':>{w['excl']}}", 
               f"{'OVERLAP':>{w['ovrl']}}", f"{'FINAL':>{w['final']}}", f"{'TIME':>{w['time']}}"]
    print(f"{BOLD}║ {CYAN}{f'{RST}{BOLD}║{CYAN} '.join(headers)}{RST}{BOLD} ║{RST}")
    print(border("═", "╠", "╣", "╬"))

    for name, data in feed_stats.items():
        excl_pct = (data['excluded_tld'] / data['raw_lines'] * 100) if data['raw_lines'] > 0 else 0.0
        row = [
            f"{name:<{w['name']}}", f"{data['raw_lines']:>{w['raw']},}",
            f"{YELLOW}{data['excluded_tld']:>{w['excl']-8},} ({excl_pct:02.0f}%){RST}",
            f"{RED}{data['dedup_count']:>{w['ovrl']},}{RST}",
            f"{GREEN}{data['valid_domains']:>{w['final']},}{RST}", f"{data['time_taken']:>{w['time']-1}.2f}s"
        ]
        print(f"{BOLD}║{RST} {f' {DIM}│{RST} '.join(row)} {BOLD}║{RST}")
    print(border("═", "╚", "╝", "╩"))

    print(f"\n{BOLD}🔍 NETWORK INTELLIGENCE:{RST}")
    print(f"   {CYAN}Top Blocked TLDs:{RST}")
    max_tld_len = max(len(t[0]) for t in top_tlds) if top_tlds else 0
    for tld, count in top_tlds:
        bar_len = int((count / (top_tlds[0][1] if top_tlds else 1)) * 20)
        bar = "█" * bar_len
        print(f"   • {tld:<{max_tld_len}} : {MAGENTA}{bar:<20}{RST} {count:,}")

    print(f"\n   {CYAN}Performance Metrics:{RST}")
    print(f"   • {BOLD}Processing Speed :{RST} {velocity:,} domains/sec")
    print(f"   • {BOLD}Junk Ratio         :{RST} {junk_ratio:.1f}% (Waste removed)")
    print(f"   • {BOLD}Total Efficiency :{RST} {GREEN}100%{RST} (Ready for Cloudflare)")

    print(f"\n   {BOLD}🤓 NERD CORNER:{RST}")
    ent_val = nerd_stats['max_entropy']
    ent_color = RED if ent_val > 4.5 else GREEN
    print(f"   • {BOLD}Highest Entropy :{RST} {ent_color}{nerd_stats['max_entropy_domain']}{RST}")
    print(f"     └─ Score: {ent_val:.2f} bits (Likely a botnet/DGA)")

    long_dom = nerd_stats['longest_domain']
    display_dom = (long_dom[:50] + '...') if len(long_dom) > 50 else long_dom
    print(f"   • {BOLD}Longest Domain  :{RST} {BLUE}{display_dom}{RST}")
    print(f"     └─ Length: {len(long_dom)} chars")

    print(f"   • {BOLD}The Vibe Check  :{RST} (Most frequent tokens)")
    top_kwd = nerd_stats['keyword_counts'].most_common(3)
    for word, count in top_kwd:
        print(f"     [{YELLOW}{word}{RST}] found {count:,} times")

    print("\n" + "="*95 + "\n")

# --- 6. Main Execution ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        validate_config()
        feed_stats = {} 

        with CloudflareAPI(Config.ACCOUNT_ID, Config.API_TOKEN, Config.MAX_RETRIES) as cf:
            if args.delete:
                logger.warning("🗑️ Deleting all lists and rules...")
                rules = cf.get_rules().get('result') or []
                lists = cf.get_lists().get('result') or []
                for f in FEED_CONFIGS:
                    rid = next((r['id'] for r in rules if r['name'] == f['policy_name']), None)
                    if rid: cf.delete_rule(rid)
                    for l in [ls for ls in lists if f['prefix'] in ls['name']]: cf.delete_list(l['id'])
                return

            datasets = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as exec:
                future_to_name = {exec.submit(fetch_domains, f): f['name'] for f in FEED_CONFIGS}
                for future in concurrent.futures.as_completed(future_to_name):
                    name = future_to_name[future]
                    domains, stats = future.result()
                    datasets[name] = domains
                    feed_stats[name] = stats
            
            logger.info("--- 🧠 Starting Deduplication ---")
            tif_name = "Threat Intel Feed"
            if tif_name in datasets:
                for name, domains in datasets.items():
                    if name != tif_name:
                        before_count = len(domains)
                        datasets[name] -= datasets[tif_name]
                        after_count = len(domains)
                        feed_stats[name]['dedup_count'] = before_count - after_count
                        feed_stats[name]['valid_domains'] = after_count

            logger.info("--- ☁️ Starting Cloudflare Sync ---")
            changed_files = []
            for f in FEED_CONFIGS:
                logger.info(f"⚡ Processing {f['name']}...")
                if save_and_sync(cf, f, datasets[f['name']], args.force):
                    changed_files.append(f['filename'])

            stats_file = write_markdown_stats(feed_stats)
            changed_files.append(stats_file)

            if Path(".git").exists() and changed_files:
                git_push(changed_files)
        
        print_console_summary(feed_stats, datasets)
        logger.info("✅ Execution complete!")

    except Exception as e:
        logger.critical(f"Fatal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
