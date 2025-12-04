Cloudflare Gateway ZeroTrust Ad Block

Forked from jacobgelling/cloudflare-gateway-block-ads.
This version includes various other blocklists that can be used. It will automatically download the blocklist, split it into chunks, upload the chunks as Cloudflare Domains lists, and apply a Gateway policy to block them.

If you want a different blocklist, just change the blocklist URL in the script. No other modification is required.

Cloudflare currently enforces 300 lists, each with 1000 entries, meaning there is a 300,000-capacity limit. If your chosen blocklist (or combination of blocklists, as the script auto-deduplicates) exceeds these limits, trim or switch to something with fewer than 300K domains (OISD Big/Small, 1Hosts Lite, HaGeZi Normal/Pro/Pro++, etc.).

How It Works

The script retrieves the HaGeZi Pro++, OISD small, and 1Hosts Lite lists every hour, deduplicates them, checks for changes, and updates the Cloudflare lists only if the source list has been modified. This avoids pointless API calls. (Blocklist URLs can easily be changed in the script) 

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
