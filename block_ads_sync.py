import os, sys, time, requests, argparse
from pathlib import Path
from subprocess import run

# --- Minimal Config ---
API_TOKEN = os.environ.get("API_TOKEN")
ACCT_ID = os.environ.get("ACCOUNT_ID")
T_BR = os.environ.get("GITHUB_REF_NAME", "main")

BAD_TLDS = {".zip", ".su", ".kp", ".pw", ".stream", ".tk", ".ml", ".ga", ".cf", ".gq", 
            ".top", ".icu", ".monster", ".ooo", ".gdn", ".xin", ".sbs", ".bid", ".loan", ".win", ".download", ".click"}

FEEDS = [
    {"p": "Ads", "pol": "Block Ads", "f": "Ads.txt", "u": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/multi.light-onlydomains.txt"},
    {"p": "Sec", "pol": "Block Sec", "f": "Sec.txt", "u": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/fake-onlydomains.txt"},
    {"p": "TIF", "pol": "Block TIF", "f": "TIF.txt", "u": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.mini-onlydomains.txt"}
]

class CFClient:
    def __init__(self):
        self.url = f"https://api.cloudflare.com/client/v4/accounts/{ACCT_ID}/gateway"
        self.h = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
        self.s = requests.Session()

    def req(self, m, e, **k):
        for i in range(3):
            r = self.s.request(m, f"{self.url}/{e}", headers=self.h, **k)
            if r.status_code != 429: return r.json().get('result', [])
            time.sleep(2**i)

def fetch(u):
    try:
        r = requests.get(u, timeout=20)
        return {l.split()[-1].lower() for l in r.text.splitlines() if l.strip() and l[0] not in ('#', '!', '/') 
                and "." + l.split()[-1].rsplit('.', 1)[-1] not in BAD_TLDS}
    except: return set()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delete", action="store_true")
    args = parser.parse_args()

    if not API_TOKEN or not ACCT_ID: return
    cf = CFClient()

    if args.delete:
        rules, lists = cf.req("GET", "rules"), cf.req("GET", "lists")
        for f in FEEDS:
            rid = next((r['id'] for r in rules if r['name'] == f['pol']), None)
            if rid: cf.req("DELETE", f"rules/{rid}")
            for l in [ls for ls in lists if f['p'] in ls['name']]: cf.req("DELETE", f"lists/{l['id']}")
        return

    ds = {f['p']: fetch(f['u']) for f in FEEDS}
    # Deduplicate: TIF > Sec > Ads
    ds["Sec"] -= ds["Ads"]
    ds["TIF"] -= (ds["Ads"] | ds["Sec"])

    changed = []
    rules, lists = cf.req("GET", "rules"), cf.req("GET", "lists")
    
    for f in FEEDS:
        path, domains = Path(f['f']), sorted(ds[f['p']])
        out = '\n'.join(domains) + '\n'
        if path.exists() and path.read_text() == out: continue
        path.write_text(out)
        
        cur_l = [l['id'] for l in lists if f['p'] in l['name']]
        u_ids = []
        for i, chunk in enumerate([domains[x:x+1000] for x in range(0, len(domains), 1000)]):
            itms = [{"value": v} for v in chunk]
            if cur_l:
                lid = cur_l.pop(0)
                old = cf.req("GET", f"lists/{lid}/items?limit=1000")
                cf.req("PATCH", f"lists/{lid}", json={"append": itms, "remove": [o['value'] for o in old if 'value' in o]})
                u_ids.append(lid)
            else:
                u_ids.append(cf.req("POST", "lists", json={"name": f"{f['p']}-{i}", "type": "DOMAIN", "items": itms})['id'])
        
        rid = next((r['id'] for r in rules if r['name'] == f['pol']), None)
        expr = {"or": [{"any": {"in": {"lhs": {"splat": "dns.domains"}, "rhs": f"${lid}"}}} for lid in u_ids]}
        pay = {"name": f['pol'], "conditions": [{"type": "traffic", "expression": expr}], "action": "block", "enabled": True, "filters": ["dns"]}
        cf.req("PUT", f"rules/{rid}", json=pay) if rid else cf.req("POST", "rules", json=pay)
        for lid in cur_l: cf.req("DELETE", f"lists/{lid}")
        changed.append(f['f'])

    if changed and Path(".git").exists():
        for cmd in [["git", "add"] + changed, ["git", "commit", "-m", "upd"], ["git", "push", "origin", T_BR]]: run(cmd)

if __name__ == "__main__": main()
