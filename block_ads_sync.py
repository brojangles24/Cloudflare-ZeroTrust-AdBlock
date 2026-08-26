import os
import re
import requests
import json
import time

# ------------------------------------------------------------------------------
# 1. Configuration & Authentication
# ------------------------------------------------------------------------------
CF_ACCOUNT_ID = os.environ.get("CF_ACCOUNT_ID", "YOUR_ACCOUNT_ID")
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "YOUR_API_TOKEN")

API_BASE = f"https://api.cloudflare.com/client/v4/accounts/{CF_ACCOUNT_ID}/gateway"
HEADERS = {
    "Authorization": f"Bearer {CF_API_TOKEN}",
    "Content-Type": "application/json",
}

BLOCKLIST_URLS = {
    "HaGeZi Normal": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi-onlydomains.txt"],
    "HaGeZi Pro": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt",
    "Hagezi NSFW": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nsfw-onlydomains.txt",
        "https://raw.githubusercontent.com/sjhgvr/oisd/refs/heads/main/abp_nsfw.txt",
    ],
    "HaGeZi Fake": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt",
    "HaGeZi TIF Full": ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt"],
    "HaGeZi Social": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/social-onlydomains.txt",
    "HaGeZi No SafeSearch": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/nosafesearch-onlydomains.txt",
    "HaGeZi Bypass Prevention": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "HaGeZi Anti Piracy": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/anti.piracy-onlydomains.txt",
    "HaGeZi DynDNS": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/dyndns-onlydomains.txt",
    "HaGeZi DNS Rebind": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adguard/dns-rebind-protection.txt",
    "NoAI": "https://raw.githubusercontent.com/laylavish/uBlockOrigin-HUGE-AI-Blocklist/refs/heads/main/noai_hosts.txt",
}

POLICIES = [
    {
        "prefix": "L_Relaxed",
        "policy_name": "Block: Relaxed Profile",
        "action": "block",
        "include": ["HaGeZi Normal", "Hagezi NSFW", "HaGeZi Fake", "HaGeZi No SafeSearch", "HaGeZi TIF Full", "HaGeZi DNS Rebind"],
        "exclude": [],
    },
    {
        "prefix": "L_Restrictive",
        "policy_name": "Block: Restrictive Profile",
        "action": "block",
        "include": ["HaGeZi Pro", "Hagezi NSFW", "HaGeZi Fake", "HaGeZi No SafeSearch", "HaGeZi TIF Full", "HaGeZi Social", "HaGeZi Bypass Prevention", "HaGeZi Anti Piracy", "HaGeZi DynDNS", "HaGeZi DNS Rebind", "NoAI"],
        "exclude": [],
    },
]

# ------------------------------------------------------------------------------
# 2. Parsing Logic
# ------------------------------------------------------------------------------
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
ADGUARD_BLOCK_REGEX = re.compile(r"^\|\|([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\^")
ADGUARD_ALLOW_REGEX = re.compile(r"^@@\|\|([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\^")
REGEX_RULE_REGEX = re.compile(r"^/(.*)/$")

def fetch_and_parse_source(url: str) -> dict:
    parsed = {"domains": set(), "allows": set(), "regexes": set()}
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
    except Exception as err:
        print(f"[-] Error fetching {url}: {err}")
        return parsed

    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith(("!", "#")): continue

        if line.startswith("@@||"):
            if match := ADGUARD_ALLOW_REGEX.match(line): parsed["allows"].add(match.group(1).lower())
            continue
        if line.startswith("||"):
            if match := ADGUARD_BLOCK_REGEX.match(line): parsed["domains"].add(match.group(1).lower())
            continue
        if line.startswith("/") and line.endswith("/"):
            if match := REGEX_RULE_REGEX.match(line): parsed["regexes"].add(match.group(1))
            continue
            
        cleaned_domain = line.replace("0.0.0.0", "").replace("127.0.0.1", "").strip().lower()
        if DOMAIN_REGEX.match(cleaned_domain):
            parsed["domains"].add(cleaned_domain)

    return parsed

def optimize_domains(domains: set) -> list:
    sorted_domains = sorted(domains, key=len)
    optimized = set()
    for domain in sorted_domains:
        parts = domain.split(".")
        if not any(".".join(parts[i:]) in optimized for i in range(1, len(parts))):
            optimized.add(domain)
    return sorted(list(optimized))

# ------------------------------------------------------------------------------
# 3. Cloudflare API Logic
# ------------------------------------------------------------------------------
def create_cf_list(name: str, domains: list) -> str:
    """Uploads a chunk of domains as a Cloudflare List and returns the List ID."""
    items = [{"value": d} for d in domains]
    payload = {"name": name, "type": "DOMAIN", "items": items}
    resp = requests.post(f"{API_BASE}/lists", headers=HEADERS, json=payload)
    resp.raise_for_status()
    return resp.json()["result"]["id"]

def push_policy_to_cloudflare(policy_name: str, list_ids: list, regexes: set, action: str):
    """Creates a Gateway Firewall Rule linking the Domain Lists and Regex patterns."""
    expressions = []
    
    # 1. Attach domain lists
    if list_ids:
        list_checks = " or ".join([f"any(dns.domains[*] in ${lid})" for lid in list_ids])
        expressions.append(f"({list_checks})")
        
    # 2. Attach regex rules (typically matching returned IP for rebind protection)
    if regexes:
        regex_checks = " or ".join([f'any(dns.resolved_ip[*] matches "{rx}")' for rx in regexes])
        expressions.append(f"({regex_checks})")
        
    if not expressions:
        return

    full_expression = " or ".join(expressions)
    
    payload = {
        "name": policy_name,
        "description": "Automated DNS Policy",
        "action": action,
        "traffic": full_expression,
        "enabled": True
    }
    
    resp = requests.post(f"{API_BASE}/rules", headers=HEADERS, json=payload)
    if resp.status_code != 200:
        print(f"[-] Failed to create rule {policy_name}: {resp.text}")
    else:
        print(f"[+] Successfully created Cloudflare Gateway Rule: {policy_name}")

# ------------------------------------------------------------------------------
# 4. Main Execution
# ------------------------------------------------------------------------------
def main():
    cache = {}
    print("[+] Downloading and parsing domain/regex sources...")
    for key, sources in BLOCKLIST_URLS.items():
        if isinstance(sources, str): sources = [sources]
        source_data = {"domains": set(), "allows": set(), "regexes": set()}
        for src in sources:
            res = fetch_and_parse_source(src)
            source_data["domains"].update(res["domains"])
            source_data["allows"].update(res["allows"])
            source_data["regexes"].update(res["regexes"])
        cache[key] = source_data

    print("\n[+] Compiling and uploading profiles...")
    for policy in POLICIES:
        policy_domains, policy_allows, policy_regexes = set(), set(), set()
        
        for source_key in policy["include"]:
            if source_key in cache:
                policy_domains.update(cache[source_key]["domains"])
                policy_allows.update(cache[source_key]["allows"])
                policy_regexes.update(cache[source_key]["regexes"])
                
        for source_key in policy["exclude"]:
            if source_key in cache:
                policy_domains.difference_update(cache[source_key]["domains"])

        policy_domains.difference_update(policy_allows)
        optimized_domains = optimize_domains(policy_domains)
        
        print(f"\n---> Uploading Profile: {policy['prefix']} ({len(optimized_domains)} domains, {len(policy_regexes)} regexes)")
        
        # Chunk into Cloudflare 1000-item lists
        chunk_size = 1000
        list_ids = []
        for i in range(0, len(optimized_domains), chunk_size):
            chunk = optimized_domains[i:i + chunk_size]
            list_name = f"{policy['prefix']}_chunk_{i//chunk_size + 1}_{int(time.time())}"
            try:
                lid = create_cf_list(list_name, chunk)
                list_ids.append(lid)
                print(f"     - Uploaded list chunk {i//chunk_size + 1}")
            except Exception as e:
                print(f"     [-] Failed to upload list chunk {i//chunk_size + 1}: {e}")

        # Push to Gateway Rules
        push_policy_to_cloudflare(policy["policy_name"], list_ids, policy_regexes, policy["action"])

if __name__ == "__main__":
    if CF_ACCOUNT_ID == "YOUR_ACCOUNT_ID" or CF_API_TOKEN == "YOUR_API_TOKEN":
        print("[-] Please set CF_ACCOUNT_ID and CF_API_TOKEN environment variables.")
    else:
        main()
