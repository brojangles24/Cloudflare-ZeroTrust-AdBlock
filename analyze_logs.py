import os
import json
import sys
import logging
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from openai import OpenAI, APIError
from typing import Set, List, Dict, Any, Tuple, Optional

# --- Configuration ---

CHUNK_SIZE = 200
REPORT_THRESHOLD = 7  # Domains rated 7+ are potential false positives
API_MODEL = "gpt-4o"
CLOUDFLARE_API_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql"

# New: Define report filenames
ALLOW_LIST_FILE = Path("allow_list.md")
REVIEW_LIST_FILE = Path("review_list.md")

SYSTEM_PROMPT = """
You are a DNS analysis expert. You specialize in identifying false positives in
ad/tracker/malware blocklists. The user will provide a JSON list of domain
names that were blocked by their filter.

Analyze each domain and respond with *only* a valid JSON object.

The JSON object should be a dictionary where each key is the domain name from
the input. The value for each domain should be a dictionary containing:

1. "rating": An integer from 1 to 10.
   * 1 = Absolutely an ad, tracker, or malicious domain.
   * 10 = Absolutely a false positive (a safe, legitimate domain).
2. "reason": A brief one-sentence justification for the rating.
"""

# --- Setup Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

def fetch_blocked_domains_from_api(
    account_id: str, api_token: str
) -> List[str]:
    """
    Fetches unique blocked domains from the last 24 hours
    from the Cloudflare GraphQL API.
    """
    blocked_domains: Set[str] = set()

    # Calculate 24 hours ago in RFC3339 format
    start_time = (datetime.now(timezone.utc) - timedelta(hours=24))
    start_time_str = start_time.isoformat()

    query = """
    query GetBlockedDns($accountTag: string, $filter: GatewayDnsAnalyticsFilter_InputObject) {
      viewer {
        accounts(filter: {accountTag: $accountTag}) {
          gatewayDnsAnalytics(
            limit: 10000
            orderBy: [datetime_DESC]
            filter: $filter
          ) {
            dimensions {
              queryName
            }
          }
        }
      }
    }
    """
    
    variables = {
        "accountTag": account_id,
        "filter": {
            "action": "block",
            "datetime_geq": start_time_str  # "datetime greater than or equal to"
        }
    }

    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(
            CLOUDFLARE_API_ENDPOINT,
            headers=headers,
            json={"query": query, "variables": variables}
        )
        response.raise_for_status()
        data = response.json()
        
        if "errors" in data:
            logging.error(f"Cloudflare API Error: {data['errors']}")
            return []

        results = data.get("data", {}).get("viewer", {}).get("accounts", [])
        if not results:
            logging.error("No 'accounts' data returned from Cloudflare API.")
            return []

        analytics = results[0].get("gatewayDnsAnalytics", [])
        for item in analytics:
            domain = item.get("dimensions", {}).get("queryName")
            if domain:
                blocked_domains.add(domain)

    except requests.exceptions.RequestException as e:
        logging.error(f"Error calling Cloudflare API: {e}")
        return []

    logging.info(f"Found {len(blocked_domains)} unique blocked domains from the last 24 hours.")
    return list(blocked_domains)


def analyze_domains(
    domain_list: List[str], client: OpenAI, model: str
) -> Dict[str, Dict[str, Any]]:
    """Analyzes a list of domains using the OpenAI API and returns a results dictionary."""
    if not domain_list:
        return {}

    user_prompt = json.dumps(domain_list)
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0,
            response_format={"type": "json_object"}
        )
        text = response.choices[0].message.content
        if not text:
            logging.error("Received empty response from API.")
            return {}
        return json.loads(text)
    except APIError as e:
        logging.error(f"Error calling OpenAI API: {e}")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON response from API: {e}\nResponse text: {text}")
        return {}
    except Exception as e:
        logging.error(f"An unexpected error occurred during API call: {e}")
        return {}


def generate_report(all_results: Dict[str, Dict[str, Any]], threshold: int):
    """Sorts results and writes them to markdown files."""
    allow_list: List[Tuple[str, Dict]] = []
    review_list: List[Tuple[str, Dict]] = []

    for domain, data in all_results.items():
        rating = data.get("rating", 1)
        if rating >= threshold:
            allow_list.append((domain, data))
        else:
            review_list.append((domain, data))

    # --- Generate Allow List ---
    allow_list.sort(key=lambda x: x[1].get("rating", 1), reverse=True)
    with ALLOW_LIST_FILE.open("w") as f:
        f.write(f"# 🟢 Potential Allow List ({len(allow_list)} Domains)\n\n")
        f.write(f"_Updated: {datetime.now(timezone.utc).isoformat()}_\n\n")
        if not allow_list:
            f.write("No potential false positives found.\n")
        else:
            for domain, data in allow_list:
                f.write(f"### {domain}\n")
                f.write(f"* **Rating:** {data.get('rating', 'N/A')}/10\n")
                f.write(f"* **Reason:** {data.get('reason', 'No reason provided.')}\n\n")
    logging.info(f"Wrote {len(allow_list)} domains to {ALLOW_LIST_FILE}")

    # --- Generate Review List ---
    review_list.sort(key=lambda x: x[1].get("rating", 1))
    with REVIEW_LIST_FILE.open("w") as f:
        f.write(f"# 🔴 Review / Blocked List ({len(review_list)} Domains)\n\n")
        f.write(f"_Updated: {datetime.now(timezone.utc).isoformat()}_\n\n")
        if not review_list:
            f.write("No domains to review.\n")
        else:
            f.write("| Rating | Domain |\n")
            f.write("|:---|:---|\n")
            for domain, data in review_list:
                rating = data.get('rating', 1)
                f.write(f"| {rating}/10 | `{domain}` |\n")
    logging.info(f"Wrote {len(review_list)} domains to {REVIEW_LIST_FILE}")


def main():
    print("--- Cloudflare Gateway Log Analysis (with OpenAI API) ---")

    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        logging.error("Error: OPENAI_API_KEY environment variable not set.")
        sys.exit(1)
    
    try:
        client = OpenAI(api_key=openai_api_key)
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}")
        sys.exit(1)

    account_id = os.environ.get("ACCOUNT_ID")
    api_token = os.environ.get("API_TOKEN")

    if not account_id or not api_token:
        logging.error("Error: ACCOUNT_ID or API_TOKEN env variables not set.")
        sys.exit(1)

    logging.info("Fetching latest blocked domains from Cloudflare API...")
    domains_to_analyze = fetch_blocked_domains_from_api(account_id, api_token)
    
    if not domains_to_analyze:
        logging.info("No blocked domains found or error fetching from API. Exiting.")
        sys.exit(0)

    all_results: Dict[str, Dict[str, Any]] = {}
    total_batches = (len(domains_to_analyze) + CHUNK_SIZE - 1) // CHUNK_SIZE

    for i in range(0, len(domains_to_analyze), CHUNK_SIZE):
        chunk = domains_to_analyze[i:i + CHUNK_SIZE]
        logging.info(f"Analyzing batch {i//CHUNK_SIZE + 1} of {total_batches} ({len(chunk)} domains)...")
        chunk_results = analyze_domains(chunk, client, model=API_MODEL)
        if chunk_results:
            all_results.update(chunk_results)
        else:
            logging.warning(f"Batch {i//CHUNK_SIZE + 1} failed or returned no results.")

    if not all_results:
        logging.error("Analysis complete, but no results were gathered. Exiting.")
        sys.exit(1)

    logging.info("Analysis complete. Generating report files...")
    generate_report(all_results, REPORT_THRESHOLD)


if __name__ == "__main__":
    main()
