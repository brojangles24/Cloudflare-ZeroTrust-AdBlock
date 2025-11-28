import json
import sys

def score_false_positive(event):
    """
    Analyzes a single DNS log event and returns a "false positive"
    confidence score from 0.0 (Not a FP) to 1.0 (Likely a FP).
    """
    s = 0.0
    query = event.get("QueryName", "")
    action = event.get("Action", "")

    # We only care about events that were BLOCKED.
    # If it was allowed, it can't be a false positive.
    if action != "block":
        return 0.0

    # --- Start of your Heuristics (This is the part you'll customize) ---
    
    # Heuristic 1: It contains words that are often part of legitimate
    # services, but also trigger blocklists (e.g., "analytics", "data").
    if any(t in query for t in ["analytics", "metric", "data", "stats", "config"]):
        s += 0.4

    # Heuristic 2: It ALSO contains "safe" words, making it
    # more likely to be legitimate (e.g., "analytics.mybank.com")
    if any(t in query for t in ["bank", "health", "school", "login", "payment", "internal", "office", "apple", "microsoft"]):
        s += 0.5
    
    # Heuristic 3: It's NOT a super-obvious ad domain.
    # If it's a known tracker, it's not a false positive, so set score to 0.
    if any(t in query for t in ["doubleclick", "googlesyndication", "adservice", "criteo", "taboola"]):
        return 0.0

    # Heuristic 4: If we know which policy blocked it, we can be more confident.
    # (Requires 'PolicyName' in the 'fields' param of the curl command)
    policy_name = event.get("PolicyName", "")
    if "Hagezi" in policy_name or "OISD" in policy_name:
         # Blocked by one of your main lists
         s += 0.1

    # --- End of Heuristics ---
    
    # Clamp score between 0.0 and 1.0
    return max(0, min(1, s))

def main():
    """
    Main function to read logs and print the report.
    """
    print("--- Cloudflare Gateway Log Analysis Report ---")
    
    log_file = "logs.json"
    results = []

    try:
        with open(log_file, "r") as f:
            for line in f:
                if not line.strip():
                    continue # skip empty lines
                
                try:
                    event = json.loads(line)
                    confidence = score_false_positive(event)
                    
                    # You can change this threshold (e.g., 0.5)
                    if confidence > 0.7:
                        results.append((confidence, event))
                        
                except json.JSONDecodeError:
                    print(f"Skipping malformed log line: {line.strip()}", file=sys.stderr)

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.", file=sys.stderr)
        print("This may be because the 'Get DNS logs' step failed.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)

    # Sort results by confidence, highest first
    results.sort(key=lambda x: x[0], reverse=True)

    if not results:
        print("\nNo potential false positives found. All clear!")
        return

    print(f"\nFound {len(results)} potential false positives (Confidence > 0.7):")
    print("-" * 50)
    for confidence, event in results:
        user_id = event.get('Email') or event.get('DeviceName') or 'Unknown'
        print(f"Query:     {event.get('QueryName')}")
        print(f"User:      {user_id}")
        print(f"Policy:    {event.get('PolicyName', 'N/A')}")
        print(f"Score:     {confidence:.2f}")
        print("-" * 20)

if __name__ == "__main__":
    main()
