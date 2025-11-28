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

CLOUDFLARE_POLICY_NAME = "Block ads"
API_FETCH_LIMIT = 10000

# Define report filenames
ALLOW_LIST_FILE = Path("allow_list.md")
REVIEW_LIST_FILE = Path("review_list.md")
ANALYSIS_CACHE_FILE = Path("analysis_cache.json") 

FETCHED_DOMAINS_LOG = Path("_daily_fetched_domains.log")
OPENAI_AUDIT_LOG = Path("_openai_audit.log")

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

# --- Cache Functions (UPDATED) ---

def save_cache(cache_file: Path, cache_data: Dict[str, Dict[str, Any]]):
    """Saves the analysis cache to a file."""
    try:
        with cache_file.open("w") as f:
            json.dump(cache_data, f, indent=2)
    except IOError as e:
        logging.error(f"Could not write to cache file: {e}")

def load_cache(cache_file: Path) -> Dict[str, Dict[str, Any]]:
    """Loads the analysis cache file. If it doesn't exist, create it."""
    if not cache_file.exists():
        logging.info(f"No cache file found at {cache_file}. Creating an empty one.")
        try:
            # --- THIS IS THE FIX ---
            # Create an empty file so git add doesn't fail
            save_cache(cache_file, {})
            # --- END OF FIX ---
        except Exception as e:
            logging.warning(f"Could not create empty cache file: {e}")
        return {}
        
    try:
        with cache_file.open("r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logging.warning(f"Could not read cache file ({e}). Starting fresh.")
        return {}

# --- API Fetch Function (REVERTED TO CORRECT QUERY) ---

def fetch_blocked_domains_from_api(
    account_id: str, api_token: str
) -> List[str]:
    """
    Fetches ALL unique blocked domains from the last 24 hours
    that match a specific policy name, using pagination.
    """
    blocked_domains: Set[str] = set()
    start_time_str = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    end_time = datetime.now(timezone.utc)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }
    
    # --- THIS QUERY IS REVERTED TO THE CORRECT VERSION ---
    query = """
    query GetBlockedDns($accountTag: string, $filter: GatewayDnsAnalyticsFilter_InputObject, $limit: int) {
      viewer {
        accounts(filter: {accountTag: $accountTag}) {
          gatewayDnsAnalytics(
            limit: $limit
            orderBy: [datetime_DESC]
            filter: $filter
          ) {
            dimensions {
              queryName
              datetime
            }
          }
        }
      }
    }
    """
    
    while True:
        end_time_str = end_time.isoformat()
        
        # Note: The filter type is also reverted
        variables = {
            "accountTag": account_id,
            "limit": API_FETCH_LIMIT,
            "filter": {
                "action_in": ["block"],
                "policyName_in": [CLOUDFLARE_POLICY_NAME],
                "datetime_geq": start_time_str,
                "datetime_leq": end_time_str
            }
        }
        # --- END OF QUERY REVERT ---
        
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
                break
                
            results = data.get("data", {}).get("viewer", {}).get("accounts", [])
            if not results:
                logging.error("No 'accounts' data returned from Cloudflare API.")
                break
            
            # Note: Parsing logic is also reverted
            analytics = results[0].get("gatewayDnsAnalytics", [])
            
            if not analytics:
                logging.info("Pagination complete (no more results in this time range).")
                break
            
            for item in analytics:
                domain = item.get("dimensions", {}).get("queryName")
                if domain:
                    blocked_domains.add(domain)
            
            logging.info(f"Fetched a batch of {len(analytics)} records. Total unique domains so far: {len(blocked_domains)}")

            if len(analytics) < API_FETCH_LIMIT:
                logging.info(f"Pagination complete (last batch was < {API_FETCH_LIMIT}).")
                break 

            last_timestamp_str = analytics[-1]["dimensions"]["datetime"]
            
            if last_timestamp_str.endswith('Z'):
                last_timestamp_str = last_timestamp_str[:-1] + '+00:00'
            last_datetime = datetime.fromisoformat(last_timestamp_str)
            end_time = last_datetime - timedelta(microseconds=1)

        except requests.exceptions.RequestException as e:
            logging.error(f"Error calling Cloudflare API: {e}")
            break

    logging.info(
        f"Full 24-hour log fetch complete. Found {len(blocked_domains)} unique blocked domains "
        f"from policy '{CLOUDFLARE_POLICY_NAME}'."
    )
    return list(blocked_domains)

# --- Analysis Function (Unchanged) ---

def analyze_domains(
    domain_list: List[str], client: OpenAI, model: str
) -> Dict[str, Dict[str, Any]]:
    """Analyzes a list of domains using the OpenAI API and logs the interaction."""
    if not domain_list:
        return {}
    user_prompt = json.dumps(domain_list)
    try:
        with OPENAI_AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(f"--- {datetime.now(timezone.utc).isoformat()} ---\n")
            f.write("[REQUEST]\n")
            f.write(f"{user_prompt}\n\n")
    except Exception as e:
        logging.warning(f"Could not write to audit log: {e}")
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
        try:
            with OPENAI_AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write("[RESPONSE]\n")
                f.write(f"{text}\n\n")
        except Exception as e:
            logging.warning(f"Could not write to audit log: {e}")
        return json.loads(text)
    except (APIError, json.JSONDecodeError, Exception) as e:
        logging.error(f"Error during OpenAI analysis: {e}")
        try:
            with OPENAI_AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(f"[ERROR]\n{e}\n\n")
        except Exception as log_e:
            logging.warning(f"Could not write to audit log: {log_e}")
        return {}


# --- Report Function (Unchanged) ---

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

# --- Main Function (Unchanged) ---

def main():
    print("--- Cloudflare Gateway Log Analysis (with OpenAI API) ---")
    
    for log_file in [FETCHED_DOMAINS_LOG, OPENAI_AUDIT_LOG]:
        try:
            if log_file.exists():
                log_file.unlink()
            logging.info(f"Initialized log file: {log_file}")
        except Exception as e:
            logging.warning(f"Could not clear log file {log_file}: {e}")

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

    # This will now create 'analysis_cache.json' if it's missing
    analysis_cache = load_cache(ANALYSIS_CACHE_FILE)

    logging.info("Fetching latest blocked domains from Cloudflare API...")
    domains_from_api = fetch_blocked_domains_from_api(account_id, api_token)
    
    try:
        with FETCHED_DOMAINS_LOG.open("w", encoding="utf-8") as f:
            f.write(f"# Fetched {len(domains_from_api)} unique domains on {datetime.now(timezone.utc).isoformat()}\n")
            for domain in sorted(domains_from_api):
                f.write(f"{domain}\n")
        logging.info(f"Wrote {len(domains_from_api)} domains to {FETCHED_DOMAINS_LOG}")
    except Exception as e:
        logging.error(f"Could not write fetched domains log: {e}")
    
    domains_to_analyze = [
        domain for domain in domains_from_api if domain not in analysis_cache
    ]
    
    logging.info(
        f"Found {len(domains_from_api)} unique domains. "
        f"{len(domains_to_analyze)} need new analysis."
    )

    if domains_to_analyze:
        new_results: Dict[str, Dict[str, Any]] = {}
        total_batches = (len(domains_to_analyze) + CHUNK_SIZE - 1) // CHUNK_SIZE

        for i in range(0, len(domains_to_analyze), CHUNK_SIZE):
            chunk = domains_to_analyze[i:i + CHUNK_SIZE]
            logging.info(f"Analyzing batch {i//CHUNK_SIZE + 1} of {total_batches} ({len(chunk)} new domains)...")
            
            chunk_results = analyze_domains(chunk, client, model=API_MODEL)
            if chunk_results:
                new_results.update(chunk_results)
            else:
                logging.warning(f"Batch {i//CHUNK_SIZE + 1} failed or returned no results.")
        
        analysis_cache.update(new_results)
        save_cache(ANALYSIS_CACHE_FILE, analysis_cache) # Save the updated cache
        logging.info(f"Updated cache with {len(new_results)} new entries.")
    
    else:
        logging.info("No new domains to analyze. Cache is up-to-date.")

    report_data = {
        domain: analysis_cache[domain] 
        for domain in domains_from_api if domain in analysis_cache
    }

    logging.info("Analysis complete. Generating report files...")
    generate_report(report_data, REPORT_THRESHOLD)

if __name__ == "__main__":
    main()
