import os
import json
import sys
import google.generativai as genai

# --- Configuration ---
LOG_FILE = "logs.json"
# Send domains to Gemini in batches of this size
CHUNK_SIZE = 200
# Your 1-10 scale: 10 = False Positive. We'll report on domains >= this.
REPORT_THRESHOLD = 7  # Report domains 7 or higher as potential false positives

# This is the prompt that instructs Gemini how to behave.
SYSTEM_PROMPT = """
You are a DNS analysis expert. You specialize in identifying false positives in 
ad/tracker/malware blocklists. The user will provide a JSON list of domain 
names that were blocked by their filter.

Analyze each domain and respond with *only* a valid JSON object. 

The JSON object should be a dictionary where each key is the domain name from 
the input. The value for each domain should be a dictionary containing:
1. "rating": An integer from 1 to 10.
   - 1 = Absolutely an ad, tracker, or malicious domain.
   - 10 = Absolutely a false positive (a safe, legitimate domain).
2. "reason": A brief one-sentence justification for the rating.

Example Input:
["example.com", "ads.example.com", "analytics.mybank.com"]

Example Output:
```json
{
  "example.com": {
    "rating": 10,
    "reason": "This is a benign, primary domain and should not be blocked."
  },
  "ads.example.com": {
    "rating": 1,
    "reason": "The 'ads' subdomain clearly indicates it serves advertisements."
  },
  "analytics.mybank.com": {
    "rating": 9,
    "reason": "This is likely a required analytics domain for a legitimate banking service."
  }
}
```
"""

def load_blocked_domains(log_file):
    """Reads the NDJSON log file and returns a set of unique blocked domains."""
    blocked_domains = set()
    try:
        with open(log_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    # We only care about blocked queries
                    if event.get("Action") == "block":
                        domain = event.get("QueryName")
                        if domain:
                            blocked_domains.add(domain)
                except json.JSONDecodeError:
                    pass  # Skip malformed lines
    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        return None

    print(f"Found {len(blocked_domains)} unique blocked domains in logs.")
    return list(blocked_domains)

def analyze_domains_with_gemini(domain_list, model):
    """Sends a list of domains to Gemini and returns the parsed JSON response."""
    if not domain_list:
        return {}

    # Format the user's prompt (the list of domains)
    user_prompt = json.dumps(domain_list)

    try:
        # Send the system prompt and user prompt to the model
        response = model.generate_content([SYSTEM_PROMPT, user_prompt])

        # Clean up the response: Gemini often wraps JSON in ```json ... ```
        response_text = response.text.strip().replace("```json", "").replace("```", "").strip()

        return json.loads(response_text)

    except Exception as e:
        print(f"Error calling Gemini API: {e}", file=sys.stderr)
        if hasattr(response, 'prompt_feedback'):
            print(f"Prompt Feedback: {response.prompt_feedback}", file=sys.stderr)
        return {}

def main():
    """Main function to run the analysis."""
    print("--- Cloudflare Gateway Log Analysis (with Gemini) ---")

    # 1. Configure the API
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable not set.", file=sys.stderr)
        print("Please add it to your GitHub repository secrets.")
        sys.exit(1)

    genai.configure(api_key=api_key)
    # Use Flash for speed and cost-effectiveness
    model = genai.GenerativeModel('gemini-1.5-flash-latest')

    # 2. Load Domains from Log File
    domains_to_analyze = load_blocked_domains(LOG_FILE)
    if domains_to_analyze is None or not domains_to_analyze:
        print("No blocked domains found or error reading log file. Exiting.")
        sys.exit(0)

    # 3. Analyze in Chunks
    all_results = {}
    for i in range(0, len(domains_to_analyze), CHUNK_SIZE):
        chunk = domains_to_analyze[i:i + CHUNK_SIZE]
        print(f"Analyzing batch {i//CHUNK_SIZE + 1} of {len(domains_to_analyze)//CHUNK_SIZE + 1} ({len(chunk)} domains)...")
        chunk_results = analyze_domains_with_gemini(chunk, model)
        all_results.update(chunk_results)

    # 4. Filter and Report
    print(f"\n--- Analysis Complete: {len(all_results)} domains rated ---")

    allow_list_domains = []
    review_list_domains = []

    # Iterate through all results and sort them into the two lists
    for domain, data in all_results.items():
        # Default to 1 (blocked) if rating is missing or invalid
        rating = data.get("rating", 1)
        
        if rating >= REPORT_THRESHOLD:
            allow_list_domains.append((domain, data))
        else:
            review_list_domains.append((domain, data))

    # --- Print the Allow List (7 or higher) ---
    if not allow_list_domains:
        print(f"\nNo potential false positives found (Threshold: {REPORT_THRESHOLD}+).")
    else:
        # Sort by rating, highest first
        allow_list_domains.sort(key=lambda x: x[1].get("rating", 0), reverse=True)
        print(f"\n--- Gemini Allow List ({len(allow_list_domains)} Domains) ---")
        print(f"--- (Domains rated {REPORT_THRESHOLD}/10 or higher) ---")
        print("-" * 50)
        for domain, data in allow_list_domains:
            print(f"Domain:    {domain}")
            print(f"Rating:    {data.get('rating')}/10")
            print(f"Reason:    {data.get('reason')}")
            print("-" * 20)

    # --- Print the Confirmed Blocked / Review List (6 or lower) ---
    if not review_list_domains:
        print("\nNo domains rated 6 or below.")
    else:
        # Sort by rating, lowest first (most likely to be ads)
        review_list_domains.sort(key=lambda x: x[1].get("rating", 0))
        print(f"\n--- Confirmed Blocked / Review List ({len(review_list_domains)} Domains) ---")
        print("--- (Domains rated 6/10 or lower) ---")
        print("-" * 50)
        
        # We'll use a more compact format for this list
        for domain, data in review_list_domains:
            print(f"Rating: {data.get('rating', 1):<2}/10 | Domain: {domain}")
        print("-" * 50)


if __name__ == "__main__":
    main()
