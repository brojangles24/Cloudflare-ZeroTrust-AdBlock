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

# --- 1. Configuration & Setup ---

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

class Config:
    API_TOKEN: str = os.environ.get("API_TOKEN", "")
    ACCOUNT_ID: str = os.environ.get("ACCOUNT_ID", "")
    
    # Global Limits
    MAX_LIST_SIZE: int = 1000
    MAX_LISTS: int = 300 
    MAX_RETRIES: int = 5
    
    # Git Configuration
    TARGET_BRANCH: str = os.environ.get("GITHUB_REF_NAME") or os.environ.get("TARGET_BRANCH") or "main" 
    GITHUB_ACTOR: str = os.environ.get("GITHUB_ACTOR", "github-actions[bot]")
    GITHUB_ACTOR_ID: str = os.environ.get("GITHUB_ACTOR_ID", "41898282")

    # --- JUNK TLD FILTER ---
    BLOCKED_TLDS = (
    # --- High Threat / Malware Vectors ---
    ".zip",      # Phishing: confusion with file extensions
    ".mov",      # Phishing: confusion with file extensions
    ".xyz",      # #1 Malware/Burner domain (Whitelist legitimate dev sites manually)
    ".top",      # #2 Malware/C2 host
    ".gdn",      # "Global Domain Name" - Pure spam
    ".win",      # Scam landing pages
    ".loan",     # Predatory financial scams
    ".bid",      # Auction scams
    ".stream",   # Illegal streaming/malvertising
    ".tk",       # Tokelau - Legacy abuse
    ".ml",       # Mali - Legacy abuse
    ".ga",       # Gabon - Legacy abuse
    ".cf",       # CAR - Legacy abuse
    ".gq",       # Eq. Guinea - Legacy abuse
    ".cn",       # China - High attack volume
    ".ru",       # Russia - High malware volume
    ".sbs",      # "Side by Side" - #1 SMS Phishing (Smishing) vector in 2025
    ".cfd",      # "Clothing/Design" - 99% fake shops/scams
    ".bond",     # Crypto/Investment scams
    ".es",       # Spain - High phishing volume in 2025
    ".xn--11b4c3d",     # IDN Spam / Phishing
    ".xn--1ck2e1b",     # IDN Spam / Phishing
    ".xn--1qqw23a",     # IDN Spam (Chinese)
    ".xn--2scrj9c",     # IDN Spam (Indian)
    ".xn--30rr7y",      # IDN Spam (Chinese)
    ".xn--3bst00m",     # IDN Spam / Phishing
    ".xn--3ds443g",     # .online (Chinese - High Abuse)
    ".xn--3e0b707e",    # IDN Spam (Korean)
    ".xn--3hcrj9c",     # IDN Spam / Phishing
    ".xn--3oq18vl8pn36a", # IDN Spam (Chinese)
    ".xn--3pxu8k",      # .dot (Chinese)
    ".xn--42c2d9a",     # IDN Spam (Thai)
    ".xn--45br5cyl",    # IDN Spam (Indian)
    ".xn--45brj9c",     # IDN Spam (Indian)
    ".xn--45q11c",      # IDN Spam / Phishing
    ".xn--4gbrim",      # .site (Arabic - High Abuse)
    ".xn--54b7fta0cc",  # IDN Spam (Bengali)
    ".xn--55qw42g",     # .public (Chinese)
    ".xn--55qx5d",      # .company (Chinese - High Abuse)
    ".xn--5su34j936bgsg", # .health (Chinese)
    ".xn--5tzm5g",      # .website (Chinese)
    ".xn--6frz82g",     # .mobile (Chinese)
    ".xn--6qq986b3xl",  # .pharmacy (High Phishing)
    ".xn--80adxhks",    # .moscow (Russia - High Risk)
    ".xn--80ao21a",     # .kz (Kazakhstan)
    ".xn--80aqecdr1a",  # .pharmacy (Russian)
    ".xn--80asehdb",    # .online (Russia - High Abuse)
    ".xn--80aswg",      # .site (Russia - High Abuse)
    ".xn--8y0a063a",    # IDN Spam (Chinese)
    ".xn--90a3ac",      # .srb (Serbia)
    ".xn--90ae",        # .bg (Bulgaria)
    ".xn--90ais",       # .by (Belarus - Cyber Threat)
    ".xn--9dbq2a",      # IDN Spam (Hebrew)
    ".xn--9et52u",      # IDN Spam (Chinese)
    ".xn--9krt00a",     # IDN Spam / Phishing
    ".xn--b4w605ferd",  # .fashion (Chinese)
    ".xn--bck1b9a5dre4c", # .shopping (Japanese)
    ".xn--c1avg",       # .org (Russia - High Abuse)
    ".xn--c2br7g",      # IDN Spam (Indian)
    ".xn--cck2b3b",     # IDN Spam (Korean)
    ".xn--cckwcxetd",   # .amazon (Phishing Vector)
    ".xn--cg4bki",      # .samsung (Phishing Vector)
    ".xn--clchc0ea0b2g2a9gcd", # IDN Spam
    ".xn--czr694b",     # .trademark (Spam)
    ".xn--czrs0t",      # .store (Chinese)
    ".xn--czru2d",      # .mall (Chinese)
    ".xn--d1acj3b",     # .kids (Russia)
    ".xn--d1alf",       # .mk (Macedonia)
    ".xn--e1a4c",       # .eu (Cyrillic - Phishing)
    ".xn--eckvdtc9d",   # .sale (Chinese)
    ".xn--efvy88h",     # .help (Chinese)
    ".xn--fct429k",     # .family (Chinese)
    ".xn--fhbei",       # .shabaka (Arabic)
    ".xn--fiq228c5hs",  # .mobile (Chinese)
    ".xn--fiq64b",      # .link (Chinese)
    ".xn--fiqs8s",      # .china (High Scanning/Attacks)
    ".xn--fiqz9s",      # .cisco (Phishing Vector)
    ".xn--fjq720a",     # .entertainment (Chinese)
    ".xn--flw351e",     # .google (Phishing Vector)
    ".xn--fpcrj9c3d",   # IDN Spam (Indian)
    ".xn--fzc2c9e2c",   # .shopping (Sri Lanka)
    ".xn--fzys8d69uvgm", # .vip (Chinese)
    ".xn--g2xx48c",     # .photos (Chinese)
    ".xn--gckr3f0f",    # .download (Chinese)
    ".xn--gecrj9c",     # IDN Spam (Indian)
    ".xn--gk3at1e",     # .brasil (Phishing)
    ".xn--h2breg3eve",  # IDN Spam (Indian)
    ".xn--h2brj9c",     # .bharat (India - Spam)
    ".xn--h2brj9c8c",   # IDN Spam (Indian)
    ".xn--hxt814e",     # .web (Chinese)
    ".xn--i1b6b1a6a2e", # .organization (Hindi)
    ".xn--imr513n",     # .restaurant (Chinese)
    ".xn--io0a7i",      # .network (Chinese - High Abuse)
    ".xn--j1aef",       # .com (Cyrillic - Phishing)
    ".xn--j1amh",       # .uk (Cyrillic - Phishing)
    ".xn--j6w193g",     # .hk (Hong Kong)
    ".xn--jlq480n2rg",  # .amazon (Chinese Phishing)
    ".xn--jlq61u9w7b",  # .nokia (Chinese Phishing)
    ".xn--jvr189m",     # .live (Chinese)
    ".xn--kcrx77d1x4a", # .website (Thai)
    ".xn--kprw13d",     # .kp (Taiwan)
    ".xn--kpry57d",     # .tw (Taiwan)
    ".xn--kput3i",      # .pt (Mobile Spam)
    ".xn--l1acc",       # .mn (Mongolia)
    ".xn--lgbbat1ad8j", # .algeria (Arabic)
    ".xn--mgb9awbf",    # .oman (Arabic)
    ".xn--mgba3a3ejt",  # .armenia (Arabic)
    ".xn--mgba3a4f16a", # .iran (Arabic - Sanctioned)
    ".xn--mgba7c0bbn0a", # .mauritania (Arabic)
    ".xn--mgbaakc7dvf", # .tunisia (Arabic)
    ".xn--mgbaam7a8h",  # .uae (Arabic - Spam)
    ".xn--mgbab2bd",    # .bazar (Marketplace Scams)
    ".xn--mgbah1a3hjkrd", # .mauritania (Arabic)
    ".xn--mgbai9azgqp6j", # .pakistan (Arabic)
    ".xn--mgbayh7gpa",  # .jordan (Arabic)
    ".xn--mgbbh1a",     # .sudan (Arabic)
    ".xn--mgbbh1a71e",  # .india (Arabic)
    ".xn--mgbc0a9azcg", # .morocco (Arabic)
    ".xn--mgbca7dzdo",  # .abudhabi (Arabic)
    ".xn--mgbcpq6gpa1a", # .bahrain (Arabic)
    ".xn--mgberp4a5d4ar", # .saudiarabia (Arabic)
    ".xn--mgbgu82a",    # .com (Arabic - Phishing)
    ".xn--mgbi4ecexp",  # .catholic (Arabic)
    ".xn--mgbpl2fh",    # .net (Arabic)
    ".xn--mgbt3dhd",    # .kirghizstan (Arabic)
    ".xn--mgbtx2b",     # .iraq (Arabic - High Risk)
    ".xn--mgbx4cd0ab",  # .malaysia (Arabic)
    ".xn--mix891f",     # .macau (Chinese)
    ".xn--mk1bu44c",    # .com (Arabic)
    ".xn--mxtq1m",      # .govt (Chinese - Fake Gov)
    ".xn--ngbc5azd",    # .shabaka (Arabic Web Spam)
    ".xn--ngbe9e0a",    # .kuwait (Arabic)
    ".xn--ngbrx",       # .arab (Arabic)
    ".xn--node",        # .ge (Georgia)
    ".xn--nqv7f",       # .organization (Spam)
    ".xn--nqv7fs00ema", # .organization (Chinese)
    ".xn--nyqy26a",     # .health (Chinese)
    ".xn--o3cw4h",      # .th (Thailand)
    ".xn--ogbpf8fl",    # .syria (Arabic - Sanctioned)
    ".xn--otu796d",     # .job (Chinese)
    ".xn--p1acf",       # .rus (Russian Spam)
    ".xn--p1ai",        # .rf (Russia - #1 Malware Source)
    ".xn--pgbs0dh",     # .tunisia
    ".xn--pssy2u",      # .club (Chinese Spam)
    ".xn--q7ce6a",      # .lao (Laos)
    ".xn--q9jyb4c",     # .google (Homograph Phishing)
    ".xn--qcka1pmc",    # .google (Homograph Phishing)
    ".xn--qxa6a",       # .eu (Greek)
    ".xn--qxam",        # .gr (Greece)
    ".xn--rhqv96g",     # .world (Chinese Spam)
    ".xn--rovu88b",     # .intel (Phishing)
    ".xn--rvc1e0am3e",  # .norway (Chinese)
    ".xn--s9brj9c",     # IDN Spam (Indian)
    ".xn--ses554g",     # .site (Chinese - High Abuse)
    ".xn--t60b56a",     # .dot (Chinese)
    ".xn--tckwe",       # .com (Japanese)
    ".xn--tiq49xqyj",   # .cloud (Chinese)
    ".xn--unup4y",      # .game (Chinese)
    ".xn--vhquv",       # .art (Chinese)
    ".xn--vuq861b",     # .com (Chinese - High Phishing)
    ".xn--w4r85el8fhu5dnra", # .japanese (Japanese)
    ".xn--w4rs40l",     # .fly (Chinese)
    ".xn--wgbh1c",      # .market (Arabic Spam)
    ".xn--wgbl6a",      # .qatar (Arabic)
    ".xn--xhq521b",     # .guangdong (Chinese)
    ".xn--xkc2al3hye2a", # .srilanka (Tamil)
    ".xn--xkc2dl3a5ee0h", # .tamilnadu (Tamil)
    ".xn--y9a3aq",      # .am (Armenia - Spam)
    ".xn--yfro4i67o",   # .singapore (Chinese)
    ".xn--ygbi2ammx",   # .palestine (Arabic)
    ".xn--zfr164b",     # .gov (Arabic - Fake Gov)
    )

    # --- DEFINITION OF FEEDS ---
    FEED_CONFIGS = [
        {
            "name": "Ad Block Feed",
            "prefix": "Block ads", # Kept prefix same to avoid re-uploading all lists
            "policy_name": "Block Ads, Trackers and Telemetry", # <--- UPDATED NAME
            "filename": "HaGeZi_Normal.txt",
            "urls": [
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt",
                #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt",
            ]
        },
        {
            "name": "Security Feed",
            "prefix": "Block Security",
            "policy_name": "Block Security Risks",
            "filename": "HaGeZi_Security.txt",
            "urls": [
                #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/hoster-onlydomains.txt",
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
            ]
        },
        {
            "name": "Threat Intel Feed",
            "prefix": "TIF Mini",
            "policy_name": "Threat Intelligence Feed",
            "filename": "TIF_Mini.txt",
            "urls": [
                "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt",
                #"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt",
            ]
        }
    ]

    @classmethod
    def validate(cls):
        if not cls.API_TOKEN:
            raise ScriptExit("API_TOKEN environment variable is not set.", critical=True)
        if not cls.ACCOUNT_ID:
            raise ScriptExit("ACCOUNT_ID environment variable is not set.", critical=True)

CFG = Config()

# --- 2. Helper Functions & Exceptions ---

INVALID_CHARS_PATTERN = re.compile(r'[<>&;\"\'/=\s]')
COMMON_JUNK_DOMAINS = {'localhost', '127.0.0.1', '0.0.0.0', '::1', 'broadcasthost'}

class ScriptExit(Exception):
    def __init__(self, message, silent=False, critical=False):
        super().__init__(message)
        self.silent = silent
        self.critical = critical

def domains_to_cf_items(domains):
    return [{"value": domain} for domain in domains if domain]

def chunked_iterable(iterable, size):
    """Yield successive chunks from iterable."""
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk

def run_command(command):
    """Run a shell command. Raises RuntimeError with the actual error output if it fails."""
    command_str = ' '.join(command)
    logger.debug(f"Running command: {command_str}")
    try:
        result = run(command, check=True, capture_output=True, text=True, encoding='utf-8')
        return result.stdout
    except CalledProcessError as e:
        error_msg = f"Command failed: {command_str}\nSTDERR: {e.stderr}\nSTDOUT: {e.stdout}"
        logger.debug(error_msg)
        raise RuntimeError(error_msg)

def download_list(url, file_path):
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    file_path.write_bytes(response.content)

# --- 3. Cloudflare API Client ---

class CloudflareAPI:
    def __init__(self, account_id, api_token, max_retries):
        self.base_url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/gateway"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }
        self.max_retries = max_retries
        self.session = None

    def __enter__(self):
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=self.max_retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.session:
            self.session.close()

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.base_url}/{endpoint}"
        retries = 0
        while retries <= self.max_retries:
            try:
                response = self.session.request(method, url, headers=self.headers, **kwargs)
                if response.status_code < 500:
                    response.raise_for_status()
                    return response.json()
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                status_code = e.response.status_code if e.response is not None else 0
                if status_code >= 500 or status_code == 429:
                    retries += 1
                    sleep_time = retries * 2
                    logger.warning(f"Cloudflare API Error ({status_code}). Retrying {retries}/{self.max_retries} in {sleep_time}s...")
                    time.sleep(sleep_time)
                    if retries > self.max_retries:
                        logger.error(f"Max retries exceeded for {method} {url}")
                        raise RuntimeError(f"Cloudflare API failed after retries: {e}")
                else:
                    if status_code == 400:
                         raise e
                    logger.error(f"Cloudflare Client Error: {e}")
                    raise RuntimeError(f"Cloudflare API failed: {e}")

    def get_lists(self): return self._request("GET", "lists")
    def get_list_items(self, list_id, limit): return self._request("GET", f"lists/{list_id}/items?limit={limit}")
    def update_list(self, list_id, append_items, remove_items):
        data = {"append": append_items, "remove": remove_items}
        return self._request("PATCH", f"lists/{list_id}", json=data)
    def create_list(self, name, items):
        data = {"name": name, "type": "DOMAIN", "items": items}
        return self._request("POST", "lists", json=data)
    def delete_list(self, list_id): return self._request("DELETE", f"lists/{list_id}")
    def get_rules(self): return self._request("GET", "rules")
    def create_rule(self, payload): return self._request("POST", "rules", json=payload)
    def update_rule(self, rule_id, payload): return self._request("PUT", f"rules/{rule_id}", json=payload)
    def delete_rule(self, rule_id): return self._request("DELETE", f"rules/{rule_id}")


# --- 4. Workflow Functions ---

def fetch_domains(feed_config):
    logger.info(f"--- Fetching: {feed_config['name']} ---")
    list_urls = feed_config['urls']
    temp_dir = Path(tempfile.mkdtemp())
    unique_domains = set()
    tld_filtered_count = 0

    logger.info(f"Downloading {len(list_urls)} lists...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_url = {
            executor.submit(download_list, url, temp_dir / f"list_{i}.txt"): url
            for i, url in enumerate(list_urls)
        }
        concurrent.futures.wait(future_to_url)

    for file_path in temp_dir.glob("list_*.txt"):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'): continue
                    parts = line.split()
                    if not parts: continue
                    candidate = parts[-1].lower() 
                    
                    if candidate.endswith(CFG.BLOCKED_TLDS):
                        tld_filtered_count += 1
                        continue 
                    
                    if '.' in candidate and not INVALID_CHARS_PATTERN.search(candidate):
                         if candidate not in COMMON_JUNK_DOMAINS:
                             unique_domains.add(candidate)
        except Exception as e:
            logger.warning(f"Error processing file {file_path}: {e}")

    shutil.rmtree(temp_dir)
    logger.info(f"   [TLD Filter] Removed {tld_filtered_count} junk domains.")
    logger.info(f"   [Net Result] Fetched {len(unique_domains)} unique domains.")
    return unique_domains

def save_and_sync(cf_client, feed_config, domain_set, force_update=False):
    output_path = Path(feed_config['filename'])
    
    new_content = '\n'.join(sorted(domain_set)) + '\n'
    
    if output_path.exists() and not force_update:
        current_content = output_path.read_text(encoding='utf-8')
        if current_content == new_content:
            logger.info(f"✅ [No Changes] {feed_config['name']} matches local file. Skipping Cloudflare sync.")
            return True 

    logger.info(f"💾 Saving {len(domain_set)} domains to {output_path}...")
    output_path.write_text(new_content, encoding='utf-8')
    
    prefix = feed_config['prefix']
    policy_name = feed_config['policy_name']
    total_lines = len(domain_set)

    if total_lines == 0:
        logger.warning(f"Feed {feed_config['name']} is empty. Skipping Sync.")
        return False

    total_lists_needed = (total_lines + CFG.MAX_LIST_SIZE - 1) // CFG.MAX_LIST_SIZE
    
    all_current_lists = cf_client.get_lists().get('result') or []
    current_policies = cf_client.get_rules().get('result') or []

    current_lists_with_prefix = [l for l in all_current_lists if prefix in l.get('name', '')]
    other_lists_count = len(all_current_lists) - len(current_lists_with_prefix)
    
    if total_lists_needed > CFG.MAX_LISTS - other_lists_count:
        logger.error(f"Not enough capacity! Needed: {total_lists_needed}, Available: {CFG.MAX_LISTS - other_lists_count}")
        return False

    used_list_ids = []
    excess_list_ids = [l['id'] for l in current_lists_with_prefix]

    sorted_domains = sorted(domain_set)
    for i, domains_chunk in enumerate(chunked_iterable(sorted_domains, CFG.MAX_LIST_SIZE)):
        list_name = f"{prefix} - {i + 1:03d}"
        items_json = domains_to_cf_items(domains_chunk)
        
        if excess_list_ids:
            list_id = excess_list_ids.pop(0)
            logger.info(f"Updating list {list_id} ({list_name})...")
            old_items = cf_client.get_list_items(list_id, CFG.MAX_LIST_SIZE).get('result') or []
            remove_items = [item['value'] for item in old_items if item.get('value')]
            cf_client.update_list(list_id, append_items=items_json, remove_items=remove_items)
            used_list_ids.append(list_id)
        else:
            logger.info(f"Creating new list: {list_name}...")
            result = cf_client.create_list(list_name, items_json)
            used_list_ids.append(result['result']['id'])
    
    policy_id = next((p['id'] for p in current_policies if p.get('name') == policy_name), None)
    
    or_clauses = [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in used_list_ids]
    expression_json = {"or": or_clauses} if len(or_clauses) > 1 else (or_clauses[0] if or_clauses else {"not": {"eq": {"lhs": "dns.domains", "rhs": "null"}}})

    policy_payload = {
        "name": policy_name,
        "conditions": [{"type": "traffic", "expression": expression_json}],
        "action": "block",
        "enabled": True,
        "description": f"Managed by script: {feed_config['name']}",
        "rule_settings": {"block_page_enabled": False},
        "filters": ["dns"]
    }
    
    if policy_id:
        existing_policy = next((p for p in current_policies if p.get('id') == policy_id), {})
        existing_conditions = existing_policy.get('conditions') or []
        
        needs_update = bool(excess_list_ids)
        if not needs_update and existing_conditions:
             if existing_conditions[0].get('expression') != expression_json:
                 needs_update = True

        if needs_update:
            logger.info(f"Updating policy '{policy_name}'...")
            cf_client.update_rule(policy_id, policy_payload)
        else:
            logger.info(f"Policy '{policy_name}' up to date.")
    else:
        logger.info(f"Creating policy '{policy_name}'...")
        cf_client.create_rule(policy_payload)
        
    for list_id in excess_list_ids:
        logger.info(f"Deleting excess list {list_id}...")
        try:
            cf_client.delete_list(list_id)
        except Exception as e:
            err_str = str(e)
            if "400" in err_str or "7003" in err_str or "7000" in err_str:
                logger.warning(f"Skipping delete for {list_id}: List appears to be already deleted or in use.")
            else:
                logger.warning(f"Failed to delete {list_id}: {e}")

    return True

def cleanup_resources(cf_client):
    logger.info("--- ⚠️ CLEANUP MODE: DELETING RESOURCES ⚠️ ---")
    current_policies = cf_client.get_rules().get('result') or []
    all_current_lists = cf_client.get_lists().get('result') or []

    for feed in CFG.FEED_CONFIGS:
        logger.info(f"Cleaning up resources for: {feed['name']}")
        prefix = feed['prefix']
        policy_name = feed['policy_name']

        policy_id = next((p['id'] for p in current_policies if p.get('name') == policy_name), None)
        if policy_id:
            logger.info(f"Deleting Policy: {policy_name} ({policy_id})...")
            try:
                cf_client.delete_rule(policy_id)
            except Exception as e:
                logger.error(f"Failed to delete policy {policy_id}: {e}")

        lists_to_delete = [l for l in all_current_lists if prefix in l.get('name', '')]
        for lst in lists_to_delete:
            logger.info(f"Deleting List: {lst['name']} ({lst['id']})...")
            try:
                cf_client.delete_list(lst['id'])
            except Exception as e:
                logger.error(f"Failed to delete list {lst['id']}: {e}")
    logger.info("--- Cleanup Complete ---")

def git_configure():
    git_user_name = f"{CFG.GITHUB_ACTOR}[bot]"
    git_user_email = f"{CFG.GITHUB_ACTOR_ID}+{CFG.GITHUB_ACTOR}@users.noreply.github.com"
    run_command(["git", "config", "--global", "user.email", git_user_email])
    run_command(["git", "config", "--global", "user.name", git_user_name])

def discard_local_changes(file_path):
    logger.info(f"Discarding local changes to {file_path}...")
    try:
        run_command(["git", "checkout", "--", str(file_path)])
    except RuntimeError:
        try:
            os.remove(file_path)
        except OSError:
            pass

def git_commit_and_push(changed_files):
    logger.info("--- Git Commit & Push ---")
    if not changed_files: return
    
    files_to_commit = []
    for f in changed_files:
        try:
            run_command(["git", "diff", "--exit-code", f])
            logger.info(f"File {f} matches repo. Skipping add.")
        except RuntimeError:
            logger.info(f"File {f} has changes. Staging.")
            run_command(["git", "add", f])
            files_to_commit.append(f)

    if not files_to_commit:
        logger.info("No files actually changed. Skipping commit.")
        return

    try:
        run_command(["git", "commit", "-m", f"Update blocklists: {', '.join(files_to_commit)}"])
    except RuntimeError as e:
        if "nothing to commit" in str(e) or "no changes added to commit" in str(e):
            logger.info("Git reported nothing to commit.")
            return
        logger.error(f"Git commit failed with: {e}")
        raise
    
    if run(["git", "remote", "get-url", "origin"], check=False, capture_output=True).returncode == 0:
        logger.info(f"Pushing to {CFG.TARGET_BRANCH}...")
        run_command(["git", "push", "origin", CFG.TARGET_BRANCH])

# --- 5. Main Execution ---
def main():
    parser = argparse.ArgumentParser(description="Cloudflare Gateway Blocklist Manager")
    parser.add_argument("--delete", action="store_true", help="Delete all lists and policies defined in config")
    parser.add_argument("--force", action="store_true", help="Force update even if files haven't changed")
    args = parser.parse_args()

    try:
        logger.info("--- 0. Initializing ---")
        CFG.validate()
        
        with CloudflareAPI(CFG.ACCOUNT_ID, CFG.API_TOKEN, CFG.MAX_RETRIES) as cf_client:
            
            if args.delete:
                cleanup_resources(cf_client)
                return

            is_git_repo = Path(".git").exists()
            if is_git_repo:
                try:
                    run_command(["git", "fetch", "origin", CFG.TARGET_BRANCH])
                    run_command(["git", "checkout", CFG.TARGET_BRANCH])
                    run_command(["git", "reset", "--hard", f"origin/{CFG.TARGET_BRANCH}"])
                    git_configure()
                except Exception as e:
                    logger.warning(f"Git init warning: {e}")

            feed_datasets = {}
            for feed in CFG.FEED_CONFIGS:
                feed_datasets[feed['name']] = fetch_domains(feed)

            # --- SMART DEDUPLICATION ---
            ad_name = "Ad Block Feed"
            security_name = "Security Feed"
            tif_name = "Threat Intel Feed"

            if ad_name in feed_datasets and security_name in feed_datasets:
                overlap = feed_datasets[ad_name].intersection(feed_datasets[security_name])
                if overlap:
                    logger.info(f"🔍 Found {len(overlap)} overlaps between Ads & Security.")
                    feed_datasets[security_name] -= overlap

            if ad_name in feed_datasets and tif_name in feed_datasets:
                overlap = feed_datasets[ad_name].intersection(feed_datasets[tif_name])
                if overlap:
                    logger.info(f"🔍 Found {len(overlap)} overlaps between Ads & TIF.")
                    feed_datasets[tif_name] -= overlap

            if security_name in feed_datasets and tif_name in feed_datasets:
                overlap = feed_datasets[security_name].intersection(feed_datasets[tif_name])
                if overlap:
                    logger.info(f"🔍 Found {len(overlap)} overlaps between Security & TIF.")
                    feed_datasets[tif_name] -= overlap

            changed_files_list = []
            for feed in CFG.FEED_CONFIGS:
                try:
                    dataset = feed_datasets[feed['name']]
                    sync_success = save_and_sync(cf_client, feed, dataset, force_update=args.force)
                    if sync_success:
                        changed_files_list.append(feed['filename'])
                except Exception as e:
                    logger.error(f"Failed to process feed '{feed['name']}': {e}", exc_info=True)
                    if is_git_repo:
                        discard_local_changes(feed['filename'])

            if is_git_repo and changed_files_list:
                git_commit_and_push(changed_files_list)

        logger.info("✅ Execution complete!")

    except ScriptExit as e:
        if e.silent: sys.exit(0)
        logger.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
