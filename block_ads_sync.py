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
from pathlib import Path
from subprocess import run, CalledProcessError
from itertools import islice

import requests
import toml

# --- 1. Configuration & Setup ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- FEED URL DEFINITIONS (Constants) ---
HAGEZI_ULTIMATE = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/ultimate-onlydomains.txt"
HAGEZI_PRO = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt"
HAGEZI_NORMAL = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/normal-onlydomains.txt"
HAGEZI_LIGHT = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/light-onlydomains.txt"
HAGEZI_BADWARE = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/badware-onlydomains.txt"
HAGEZI_FAKE = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt"
HAGEZI_TIF_MINI = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"
HAGEZI_TIF_MEDIUM = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt"
HAGEZI_SPAM_TLDS_IDNS = "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt" 

# --- TLD DEFINITIONS ---
TOP_15_TLDS_TUPLE = (
    "zip", "mov", "xyz", "top", "gdn", "win", "loan", "bid",
    "stream", "tk", "ml", "ga", "cf", "gq", "cn",
)
AGGR_TLDS_IDNS = HAGEZI_SPAM_TLDS_IDNS

class Config:
    API_TOKEN: str = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID: str = os.environ.get("ACCOUNT_ID", "")
    
    MAX_LIST_SIZE: int = 1000
    MAX_LISTS: int = 300 
    MAX_RETRIES: int = 5
    
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main" 
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

    CURRENT_LEVEL: str = "0"
    LAST_DEPLOYED_LEVEL: str = "0"
    SHOULD_WIPE: bool = False
    
    BLOCKED_TLDS_SET: set = set()
    TLD_SOURCE: str | tuple = () 
    FEED_CONFIGS: list = []
    POLICY_CONFIG: dict = {}

    PROFILE_LEVELS = {
        "1": {
            "name": "Minimal",
            "tlds_source": (),
            "feeds": [
                {"name": "Ads Light", "prefix": "Block 1A", "policy_name": "Level 1: Minimal Ads/Trackers", "filename": "L1_Light.txt", "urls": [HAGEZI_LIGHT]},
                {"name": "Security Mini", "prefix": "Block 1S", "policy_name": "Level 1: Minimal Security", "filename": "L1_Security.txt", "urls": [HAGEZI_TIF_MINI, HAGEZI_BADWARE, HAGEZI_FAKE]}
            ],
            "policies": {"block_malware": True, "block_scam": False, "block_tor": False, "block_countries": [], "block_bypass": False}
        },
        "2": {
            "name": "Normal",
            "tlds_source": TOP_15_TLDS_TUPLE,
            "feeds": [
                {"name": "Ads Normal", "prefix": "Block 2A", "policy_name": "Level 2: Normal Ads/Trackers", "filename": "L2_Normal.txt", "urls": [HAGEZI_NORMAL]},
                {"name": "Security Mini", "prefix": "Block 2S", "policy_name": "Level 2: Normal Security", "filename": "L2_Security.txt", "urls": [HAGEZI_TIF_MINI, HAGEZI_BADWARE, HAGEZI_FAKE]}
            ],
            "policies": {"block_malware": True, "block_scam": True, "block_tor": True, "block_countries": ["CN", "RU", "KP", "IR"], "block_bypass": False}
        },
        "3": {
            "name": "Aggressive",
            "tlds_source": AGGR_TLDS_IDNS,
            "feeds": [
                {"name": "Ads Pro", "prefix": "Block 3A", "policy_name": "Level 3: Aggressive Ads/Trackers", "filename": "L3_Pro.txt", "urls": [HAGEZI_PRO]},
                {"name": "Threat Intel Mini", "prefix": "Block 3S", "policy_name": "Level 3: Strong Security", "filename": "L3_Security.txt", "urls": [HAGEZI_TIF_MINI]}
            ],
            "policies": {"block_malware": True, "block_scam": True, "block_tor": True, "block_countries": ["CN", "RU", "KP", "IR", "SY", "BY", "AF"], "block_bypass": True}
        },
        "4": {
            "name": "Extreme",
            "tlds_source": AGGR_TLDS_IDNS,
            "feeds": [
                {"name": "Ads Ultimate", "prefix": "Block 4A", "policy_name": "Level 4: Ultimate Scorched Earth", "filename": "L4_Ultimate.txt", "urls": [HAGEZI_ULTIMATE]},
                {"name": "Threat Intel Medium", "prefix": "Block 4S", "policy_name": "Level 4: Extreme Security", "filename": "L4_Security.txt", "urls": [HAGEZI_TIF_MEDIUM]}
            ],
            "policies": {"block_malware": True, "block_scam": True, "block_tor": True, "block_countries": ["CN", "RU", "KP", "IR", "SY", "BY", "AF", "IQ", "LY", "SO", "VN"], "block_bypass": True}
        },
    }

    @classmethod
    def load_config_data(cls):
        config_path = Path("config.toml")
        if not config_path.exists(): raise ScriptExit("config.toml not found.", critical=True)
        try:
            config_data = toml.loads(config_path.read_text())
            level_str = str(config_data.get('security_level', 1))
            if level_str not in cls.PROFILE_LEVELS: raise ValueError(f"Invalid level '{level_str}'")
        except Exception as e: raise ScriptExit(f"Error reading config.toml: {e}", critical=True)

        cache_path = Path(".last_deployed_profile")
        last_level = cache_path.read_text().strip() if cache_path.exists() else "0"
        
        cls.CURRENT_LEVEL = level_str
        cls.LAST_DEPLOYED_LEVEL = last_level
        cls.SHOULD_WIPE = (cls.CURRENT_LEVEL != cls.LAST_DEPLOYED_LEVEL)
        
        if cls.SHOULD_WIPE: logger.warning(f"PROFILE CHANGE: {last_level} -> {cls.CURRENT_LEVEL}. Wiping resources.")
        else: logger.info(f"Profile {cls.CURRENT_LEVEL} consistent.")

        profile = cls.PROFILE_LEVELS[level_str]
        cls.TLD_SOURCE = profile["tlds_source"]
        cls.FEED_CONFIGS = profile["feeds"]
        cls.POLICY_CONFIG = profile.get("policies", {})
        
        if isinstance(cls.TLD_SOURCE, tuple) and cls.TLD_SOURCE:
            cls.BLOCKED_TLDS_SET = set(cls.TLD_SOURCE)
        elif isinstance(cls.TLD_SOURCE, str) and cls.TLD_SOURCE:
            logger.info("Downloading external TLD list for internal filtering...")
            temp_file = Path(tempfile.gettempdir()) / "external_tlds.txt"
            try:
                download_list(cls.TLD_SOURCE, temp_file)
                with open(temp_file, 'r', encoding='utf-8') as f:
                    tlds = [line.strip().lstrip('.').lower() for line in f if line.strip() and not line.startswith('#')]
                cls.BLOCKED_TLDS_SET = set(tlds)
                os.remove(temp_file)
            except Exception as e:
                logger.error(f"Failed to load external TLD list: {e}")
                cls.BLOCKED_TLDS_SET = set()
        
        if cls.TLD_SOURCE:
            tld_feed = {
                "name": "Junk TLDs and IDNs",
                "prefix": "Block TLD",
                "policy_name": f"Level {level_str}: Junk TLD/IDN Blocking",
                "filename": f"L{level_str}_TLDs.txt",
                "urls": [cls.TLD_SOURCE] if isinstance(cls.TLD_SOURCE, str) else []
            }
            cls.FEED_CONFIGS.append(tld_feed)

    @classmethod
    def validate(cls):
        if not cls.API_TOKEN or not cls.ACCOUNT_ID: raise ScriptExit("Missing API_TOKEN or ACCOUNT_ID.", critical=True)

CFG = Config()

# --- 2. Helper Functions ---
INVALID_CHARS_PATTERN = re.compile(r'[<>&;\"\'/=\s]')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1', 'broadcasthost'}

class ScriptExit(Exception):
    def __init__(self, message, silent=False, critical=False):
        super().__init__(message)
        self.silent = silent; self.critical = critical

def domains_to_cf_items(domains): return [{"value": domain} for domain in domains if domain]
def chunked_iterable(iterable, size):
    it = iter(iterable); 
    while True: 
        chunk = list(islice(it, size)); 
        if not chunk: break; 
        yield chunk

def run_command(command):
    try: return run(command, check=True, capture_output=True, text=True, encoding='utf-8').stdout
    except CalledProcessError as e: raise RuntimeError(f"Command failed: {e.stderr}")

def download_list(url, file_path):
    r = requests.get(url, timeout=30); r.raise_for_status(); file_path.write_bytes(r.content)

# --- 3. Cloudflare API Client (REAL) ---
class CloudflareAPI:
    def __init__(self, account_id, api_token, max_retries):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
        self.max_retries = max_retries
        self.session = requests.Session()
    def __enter__(self): 
        self.session = requests.Session()
        self.session.mount('https://', requests.adapters.HTTPAdapter(max_retries=self.max_retries))
        return self
    def __exit__(self, exc_type, exc_value, traceback): self.session.close()
    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}/{endpoint}"
        retries = 0
        while retries <= self.max_retries:
            try:
                resp = self.session.request(method, url, headers=self.headers, **kwargs)
                if resp.status_code >= 500 or resp.status_code == 429: resp.raise_for_status()
                data = resp.json()
                if not data.get('success'):
                    msgs = [e.get('message', 'Unknown') for e in data.get('errors', [])]
                    # Handle deletion 404 gracefully
                    if method == "DELETE" and any("not found" in m.lower() for m in msgs): return {'success': True}
                    raise requests.exceptions.HTTPError(f"API Error: {msgs}", response=resp)
                return data
            except Exception as e:
                retries += 1
                if retries > self.max_retries: raise RuntimeError(f"API failed: {e}")
                time.sleep(retries * 2)
    def get_lists(self): return self._request("GET", "lists")
    def get_list_items(self, lid, lim): return self._request("GET", f"lists/{lid}/items?limit={lim}")
    def update_list(self, lid, app, rem): return self._request("PATCH", f"lists/{lid}", json={"append": app, "remove": rem})
    def create_list(self, name, items): return self._request("POST", "lists", json={"name": name, "type": "DOMAIN", "items": items})
    def delete_list(self, lid): return self._request("DELETE", f"lists/{lid}")
    def get_rules(self): return self._request("GET", "rules")
    def create_rule(self, pl): return self._request("POST", "rules", json=pl)
    def update_rule(self, rid, pl): return self._request("PUT", f"rules/{rid}", json=pl)
    def delete_rule(self, rid): return self._request("DELETE", f"rules/{rid}")

# --- 4. Logic Functions ---

def create_tld_regex(content):
    tlds = [l.strip().lstrip('.').lower() for l in content.splitlines() if l.strip() and not l.startswith('#')]
    if not tlds: return ""
    return f"(?i)\\.({'|'.join(sorted(set(tlds)))})$"

def create_tld_policy(cf, file, level):
    name = f"Level {level}: Junk TLD/IDN Blocking"
    if not file.exists(): return
    regex = create_tld_regex(file.read_text(encoding='utf-8'))
    if not regex: return
    
    payload = {
        "name": name, "description": "Managed by script.", "enabled": True, "action": "block", "filters": ["dns"],
        "traffic": f"dns.fqdn matches regex \"{regex}\"", "rule_settings": {"block_page_enabled": False}
    }
    rules = cf.get_rules().get('result') or []
    pid = next((p['id'] for p in rules if p.get('name') == name), None)
    if pid: cf.update_rule(pid, payload)
    else: cf.create_rule(payload)

def deploy_category_policies(cf, level):
    logger.info(f"--- Deploying Category Policies for Level {level} ---")
    config = CFG.POLICY_CONFIG
    
    sec_cats = []
    if config.get("block_malware"): sec_cats.extend(["Malware", "Phishing", "Command and Control"])
    if config.get("block_scam"): sec_cats.extend(["Spam", "Spyware", "Botnet"])
    
    if sec_cats:
        p_name = f"Level {level}: Block Malware"
        expr = f"any(dns.security_category[*] in {{{' '.join([f'\"{c}\"' for c in sec_cats])}}})"
        _deploy_policy(cf, p_name, {"name": p_name, "enabled": True, "action": "block", "filters": ["dns"], "traffic": expr, "rule_settings": {"block_page_enabled": False}})

    if config.get("block_tor"):
        p_name = f"Level {level}: Block Tor DNS"
        _deploy_policy(cf, p_name, {"name": p_name, "enabled": True, "action": "block", "filters": ["dns"], "traffic": "dns.fqdn matches regex \"(?i)\\.onion$\"", "rule_settings": {"block_page_enabled": False}})

    if config.get("block_countries"):
        p_name = f"Level {level}: Block Countries"
        c_regex = "|".join([c.lower() for c in config["block_countries"]])
        _deploy_policy(cf, p_name, {"name": p_name, "enabled": True, "action": "block", "filters": ["dns"], "traffic": f"dns.fqdn matches regex \"(?i)\\.({c_regex})$\"", "rule_settings": {"block_page_enabled": False}})

    if config.get("block_bypass"):
        p_name = f"Level {level}: Block Apple and Cox DNS"
        _deploy_policy(cf, p_name, {"name": p_name, "enabled": True, "action": "block", "filters": ["dns"], "traffic": "dns.fqdn in {\"mask.icloud.com\" \"mask-h2.icloud.com\" \"mask-api.icloud.com\"}", "rule_settings": {"block_page_enabled": False}})

def _deploy_policy(cf, name, payload):
    rules = cf.get_rules().get('result') or []
    pid = next((p['id'] for p in rules if p.get('name') == name), None)
    if pid: 
        logger.info(f"Updating Policy: {name}")
        cf.update_rule(pid, payload)
    else: 
        logger.info(f"Creating Policy: {name}")
        cf.create_rule(payload)

def fetch_domains(cfg):
    logger.info(f"Fetching: {cfg['name']}")
    if cfg['name'] == "Junk TLDs and IDNs" and isinstance(CFG.TLD_SOURCE, tuple):
        out = Path(cfg['filename'])
        out.write_text('\n'.join(sorted(CFG.TLD_SOURCE)) + '\n', encoding='utf-8')
        return set(f"d.{t}" for t in CFG.TLD_SOURCE)
    
    t_dir = Path(tempfile.mkdtemp()); 
    with concurrent.futures.ThreadPoolExecutor(5) as ex:
        ex.map(lambda u: download_list(u[1], t_dir/f"{u[0]}.txt"), enumerate(cfg['urls']))
    
    u_doms = set()
    for f in t_dir.glob("*.txt"):
        for l in f.read_text(encoding='utf-8', errors='ignore').splitlines():
            p = l.strip().split()
            if not p or l.startswith('#'): continue
            d = p[-1].lower()
            if CFG.BLOCKED_TLDS_SET and '.' in d and d.split('.')[-1] in CFG.BLOCKED_TLDS_SET: continue
            if '.' in d and not INVALID_CHARS_PATTERN.search(d) and d not in COMMON_JUNK_DOMAINS: u_doms.add(d)
    shutil.rmtree(t_dir)
    return u_doms

def save_and_sync(cf, cfg, d_set, force=False):
    out = Path(cfg['filename'])
    if cfg['name'] == "Junk TLDs and IDNs" and isinstance(CFG.TLD_SOURCE, str):
        out.write_text('\n'.join(sorted(d_set)) + '\n', encoding='utf-8')
        return True 
    
    content = '\n'.join(sorted(d_set)) + '\n'
    if out.exists() and out.read_text(encoding='utf-8') == content and not force: return True
    out.write_text(content, encoding='utf-8')
    
    p_name = cfg['policy_name']; prefix = cfg['prefix']
    if not d_set: return False
    
    lists = cf.get_lists().get('result') or []
    curr_l = [l for l in lists if prefix in l.get('name', '')]
    
    used_ids = []
    ids_to_del = [l['id'] for l in curr_l]
    
    for i, chunk in enumerate(chunked_iterable(sorted(d_set), CFG.MAX_LIST_SIZE)):
        name = f"{prefix} - {i+1:03d}"
        items = domains_to_cf_items(chunk)
        if ids_to_del:
            lid = ids_to_del.pop(0)
            logger.info(f"Updating List: {name}")
            old = cf.get_list_items(lid, CFG.MAX_LIST_SIZE).get('result') or []
            cf.update_list(lid, items, [x['value'] for x in old])
            used_ids.append(lid)
        else:
            logger.info(f"Creating List: {name}")
            used_ids.append(cf.create_list(name, items)['result']['id'])
            
    or_c = [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in used_ids]
    expr = {"or": or_c} if len(or_c) > 1 else or_c[0]
    pl = {"name": p_name, "enabled": True, "action": "block", "filters": ["dns"], 
          "conditions": [{"type": "traffic", "expression": expr}], "rule_settings": {"block_page_enabled": False}}
    
    _deploy_policy(cf, p_name, pl)
    
    for lid in ids_to_del:
        logger.info(f"Deleting unused list: {lid}")
        cf.delete_list(lid)
    return True

# --- REVISED CLEANUP: Ruthless Edition ---
def cleanup_resources(cf):
    logger.info("--- ⚠️ CLEANUP MODE: DELETING RESOURCES ⚠️ ---")
    rules = cf.get_rules().get('result') or []
    lists = cf.get_lists().get('result') or []
    
    # 1. Identify ALL Lists to delete (Nuke everything)
    # This solves the "TIF Mini" issue by deleting ANY list present.
    # If you have critical manual lists, you must exclude them here.
    # Currently configured to delete ALL lists to ensure clean state.
    lists_to_delete = lists
    list_ids_to_delete = {l['id'] for l in lists_to_delete}
    
    logger.info(f"Found {len(lists_to_delete)} lists to delete.")

    # 2. Identify Policies to delete
    # Delete ANY policy that uses a list we are deleting.
    # AND delete any policy that matches our known script keywords.
    policies_to_delete = []
    keywords = ["Level", "Block", "Ads", "Security", "TIF", "Junk", "Malware", "Tor", "Country"]
    
    for p in rules:
        # Check 1: Does it depend on a list we are wiping?
        if any(lid in str(p) for lid in list_ids_to_delete):
            policies_to_delete.append(p)
            continue
        
        # Check 2: Does it look like one of our managed policies?
        if any(k in p.get('name', '') for k in keywords):
            policies_to_delete.append(p)
            continue

    # 3. Delete Policies First
    if policies_to_delete:
        logger.info(f"Deleting {len(policies_to_delete)} conflicting policies...")
        for p in policies_to_delete:
            logger.info(f"Deleting Policy: {p['name']} ({p['id']})...")
            try: cf.delete_rule(p['id'])
            except Exception as e: logger.error(f"Err: {e}")
        
        logger.info("Waiting 15s for policy deletion to propagate...")
        time.sleep(15) # Essential for Cloudflare consistency
    else:
        logger.info("No conflicting policies found.")

    # 4. Delete Lists
    for l in lists_to_delete:
        logger.info(f"Deleting List: {l['name']} ({l['id']})...")
        try: cf.delete_list(l['id'])
        except Exception as e: logger.error(f"Err: {e}")
        
    Path(".last_deployed_profile").write_text(CFG.CURRENT_LEVEL)
    logger.info("--- Cleanup Complete. ---")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        logger.info("--- 0. Initializing ---")
        CFG.load_config_data(); CFG.validate()
        
        with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf:
            if args.delete or CFG.SHOULD_WIPE:
                cleanup_resources(cf)
                if args.delete: return

            # Git setup (Assuming git repo exists)
            is_git = Path(".git").exists()
            if is_git:
                try: 
                    run_command(["git", "config", "--global", "user.email", f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"])
                    run_command(["git", "config", "--global", "user.name", f"{CFG.GITHUB_ACTOR}[bot]"])
                except Exception as e: logger.warning(f"Git init: {e}")

            feed_data = {}
            for f in CFG.FEED_CONFIGS: feed_data[f['name']] = fetch_domains(f)
            
            # Deduplication
            ad = next((f['name'] for f in CFG.FEED_CONFIGS if 'Ads ' in f['name']), None)
            sec = next((f['name'] for f in CFG.FEED_CONFIGS if 'Security' in f['name']), None)
            tif = next((f['name'] for f in CFG.FEED_CONFIGS if 'Threat' in f['name']), None)
            
            if ad and sec and ad in feed_data and sec in feed_data:
                 overlap = feed_data[ad].intersection(feed_data[sec])
                 if overlap: logger.info(f"Dedupe Ads/Sec: {len(overlap)}"); feed_data[sec] -= overlap
            if ad and tif and ad in feed_data and tif in feed_data:
                 overlap = feed_data[ad].intersection(feed_data[tif])
                 if overlap: logger.info(f"Dedupe Ads/TIF: {len(overlap)}"); feed_data[tif] -= overlap
            if sec and tif and sec in feed_data and tif in feed_data:
                 overlap = feed_data[sec].intersection(feed_data[tif])
                 if overlap: logger.info(f"Dedupe Sec/TIF: {len(overlap)}"); feed_data[tif] -= overlap

            changed = []
            sync_ok = True
            for f in CFG.FEED_CONFIGS:
                if not save_and_sync(cf, f, feed_data[f['name']], args.force): sync_ok = False
                else: changed.append(f['filename'])
                
            if sync_ok:
                tld_f = next((f for f in CFG.FEED_CONFIGS if f['name'] == 'Junk TLDs and IDNs'), None)
                if tld_f: create_tld_policy(cf, Path(tld_f['filename']), CFG.CURRENT_LEVEL)
                
                deploy_category_policies(cf, CFG.CURRENT_LEVEL)
                
                Path(".last_deployed_profile").write_text(CFG.CURRENT_LEVEL)
                logger.info("✅ Deployment Complete.")
                
                if is_git and changed:
                    for f in changed:
                        try: run_command(["git", "add", f])
                        except: pass
                    try:
                        run_command(["git", "commit", "-m", "Update blocklists"])
                        run_command(["git", "push"])
                    except: pass
            else:
                logger.error("Sync failed.")

    except Exception as e:
        logger.critical(f"Fatal: {e}", exc_info=True); sys.exit(1)

if __name__ == "__main__":
    main()
