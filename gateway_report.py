import os
import json
import sys
import openai

# --- Configuration ---

LOG_FILE = "logs.json"
CHUNK_SIZE = 200
REPORT_THRESHOLD = 7  # Domains rated 7+ are potential false positives

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

def load_blocked_domains(log_file):
blocked_domains = set()
try:
with open(log_file, "r") as f:
for line in f:
if not line.strip():
continue
try:
event = json.loads(line)
if event.get("Action") == "block":
domain = event.get("QueryName")
if domain:
blocked_domains.add(domain)
except json.JSONDecodeError:
continue
except Exception as e:
print(f"Error reading log file: {e}", file=sys.stderr)
return None
print(f"Found {len(blocked_domains)} unique blocked domains in logs.")
return list(blocked_domains)

def analyze_domains_with_chatgpt(domain_list, model="gpt-4.1"):
if not domain_list:
return {}
user_prompt = json.dumps(domain_list)
try:
response = openai.ChatCompletion.create(
model=model,
messages=[
{"role": "system", "content": SYSTEM_PROMPT},
{"role": "user", "content": user_prompt}
],
temperature=0
)
text = response.choices[0].message.content.strip()
text = text.replace("`json", "").replace("`", "").strip()
return json.loads(text)
except Exception as e:
print(f"Error calling ChatGPT API: {e}", file=sys.stderr)
return {}

def main():
print("--- Cloudflare Gateway Log Analysis (with ChatGPT API) ---")

```
api_key = os.environ.get("OPENAI_API_KEY")
if not api_key:
    print("Error: OPENAI_API_KEY environment variable not set.", file=sys.stderr)
    sys.exit(1)
openai.api_key = api_key

domains_to_analyze = load_blocked_domains(LOG_FILE)
if not domains_to_analyze:
    print("No blocked domains found or error reading log file. Exiting.")
    sys.exit(0)

all_results = {}
for i in range(0, len(domains_to_analyze), CHUNK_SIZE):
    chunk = domains_to_analyze[i:i + CHUNK_SIZE]
    print(f"Analyzing batch {i//CHUNK_SIZE + 1} of {len(domains_to_analyze)//CHUNK_SIZE + 1} ({len(chunk)} domains)...")
    chunk_results = analyze_domains_with_chatgpt(chunk)
    all_results.update(chunk_results)

allow_list = []
review_list = []
for domain, data in all_results.items():
    rating = data.get("rating", 1)
    if rating >= REPORT_THRESHOLD:
        allow_list.append((domain, data))
    else:
        review_list.append((domain, data))

if allow_list:
    allow_list.sort(key=lambda x: x[1]["rating"], reverse=True)
    print(f"\n--- Allow List ({len(allow_list)} Domains) ---")
    for domain, data in allow_list:
        print(f"Domain: {domain}\nRating: {data['rating']}/10\nReason: {data['reason']}\n")
else:
    print("\nNo potential false positives found.")

if review_list:
    review_list.sort(key=lambda x: x[1]["rating"])
    print(f"\n--- Review / Blocked List ({len(review_list)} Domains) ---")
    for domain, data in review_list:
        print(f"Rating: {data.get('rating',1):<2}/10 | Domain: {domain}")
else:
    print("\nNo domains rated low enough to review.")
```

if **name** == "**main**":
main()
