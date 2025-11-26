Cloudflare Gateway ZeroTrust Ad Block

Forked from jacobgelling/cloudflare-gateway-block-ads.
This version uses the HaGeZi Ultimate blocklist by default. It will automatically download the blocklist, split it into chunks, upload the chunks as Cloudflare Domains lists, and apply a Gateway policy to block them.

If you want a different blocklist, just change the blocklist URL in the script. No other modification is required.

Cloudflare currently enforces 300 lists and 300k total domains. If your chosen blocklist exceeds those limits, trim or switch to something below 300K domains (OISD Big/Small, 1Hosts Lite, HaGeZi Normal/Pro/Pro++, etc.)

How It Works

The script retrieves the HaGeZi Pro++, OISD small, and 1Hosts Lite lists every hour, deduplicates, checks for changes, and updates the Cloudflare lists only if the source list has changed. This avoids pointless API calls. (Blocklist URLs can easily be changed in the script) 

Note: If you choose to use the priority 300k list, it assumes you have a regex setup to block the most abused TLDs, as classified by Hagezi in his list of most abused TLDs. The priority list automatically filters out any domain ending in one of those TLDs. (https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/spam-tlds-onlydomains.txt)                  

Setup
Cloudflare

You need a Cloudflare Zero Trust account. The free tier works.
Create an API Token with Account.Zero Trust permissions.
Locate your Account ID from the Cloudflare dashboard URL.
Keep the token and ID ready for GitHub secrets.

GitHub

Fork this repository.
Add two repository secrets:

API_TOKEN set to your Cloudflare API token

ACCOUNT_ID set to your Cloudflare Account ID

Enable GitHub Actions with read and write workflow permissions.
