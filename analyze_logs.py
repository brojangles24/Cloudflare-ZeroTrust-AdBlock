import os
import json
import sys
import logging
import requests  # We need the 'requests' library now
from pathlib import Path
from openai import OpenAI, APIError
from typing import Set, List, Dict, Any, Tuple, Optional

# --- Configuration ---

CHUNK_SIZE = 200
REPORT_THRESHOLD = 7  # Domains rated 7+ are potential false positives
API_MODEL = "gpt-4o"
CLOUDFLARE_API_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql"

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
    Fetches the last 1000 unique blocked domains directly from 
    the Cloudflare GraphQL API.
    """
    blocked_domains: Set[str] = set()

    # This GraphQL query asks for the 1000 most recent DNS events
    # that were blocked, and only returns the domain name.
    query = """
    query GetBlockedDns($accountTag: string, $filter: GatewayDnsAnalyticsFilter_InputObject) {
      viewer {
        accounts(filter: {accountTag: $accountTag}) {
          gatewayDnsAnalytics(
            limit: 1000
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
            "action": "block"
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
        response.raise_for_status()  # Raise an error for bad responses (4xx, 5xx)
        
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
    except Exception as e:
        logging.error(f"An unexpected error occurred during API fetch: {e}")
        return []

    logging.info(f"Found {len(blocked_domains)} unique blocked domains from API.")
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
            response_format={"type": "json_object"}  # Enable JSON mode
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
    """Sorts results and prints a formatted report to the console."""
    allow_list: List[Tuple[str, Dict]] = []
    review_list: List[Tuple[str, Dict]] = []

    for domain, data in all_results.items():
        rating = data.get("rating", 1)
        if rating >= threshold:
            allow_list.append((domain, data))
        else:
            review_list.append((domain, data))

    if allow_list:
        allow_list.sort(key=lambda x: x[1].get("rating", 1), reverse=True)
        print(f"\n--- 🟢 Potential Allow List ({len(allow_list)} Domains) ---")
        for domain, data in allow_list:
            print(f"Domain: {domain}\n"
                  f"Rating: {data.get('rating', 'N/A')}/10\n"
                  f"Reason: {data.get('reason', 'No reason provided.')}\n")
    else:
        print("\n--- 🟢 No potential false positives found. ---")

    if review_list:
        review_list.sort(key=lambda x: x[1].get("rating", 1))
        print(f"\n--- 🔴 Review / Blocked List ({len(review_list)} Domains) ---")
        for domain, data in review_list:
            rating = data.get('rating', 1)
            print(f"Rating: {rating:<2}/10 | Domain: {domain}")
    else:
        print("\n--- 🔴 No domains rated low enough to review. ---")


def main():
    print("--- Cloudflare Gateway Log Analysis (with OpenAI API) ---")

    # Get OpenAI API Key
    openai_api_key = os.environ.get("OPENAI_API_KEY")
    if not openai_api_key:
        logging.error("Error: OPENAI_API_KEY environment variable not set.")
        sys.exit(1)
    
    try:
        client = OpenAI(api_key=openai_api_key)
    except Exception as e:
        logging.error(f"Failed to initialize OpenAI client: {e}")
        sys.exit(1)

    # Get Cloudflare API Credentials
    cf_account_id = os.environ.get("CF_ACCOUNT_ID")
    cf_api_token = os.environ.get("CF_API_TOKEN")

    if not cf_account_id or not cf_api_token:
        logging.error("Error: CF_ACCOUNT_ID or CF_API_TOKEN env variables not set.")
        sys.exit(1)

    logging.info("Fetching latest blocked domains from Cloudflare API...")
    domains_to_analyze = fetch_blocked_domains_from_api(cf_account_id, cf_api_token)
    
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

    logging.info("Analysis complete. Generating report...")
    generate_report(all_results, REPORT_THRESHOLD)


if __name__ == "__main__":
    main()
