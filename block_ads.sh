#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error.
set -u
# The return value of a pipeline is the status of the last command to exit with a non-zero status.
set -o pipefail

echo "Starting Cloudflare blocklist update..."

# --- Configuration ---
API_TOKEN="${API_TOKEN:-}"
ACCOUNT_ID="${ACCOUNT_ID:-}"
PREFIX="Block ads" # This is the prefix for ALL lists AND policies
MAX_LIST_SIZE=1000
MAX_LISTS=300       # Your account's limit for total lists
MAX_LISTS_PER_POLICY=50 # CRITICAL: How many lists to put in each policy
MAX_RETRIES=10
SOURCE_FILE="sources.txt" # The external file containing your blocklist URLs
OUTPUT_FILE="Aggregated_List.txt"
TARGET_BRANCH="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null)}"
[[ -n "${TARGET_BRANCH}" ]] || TARGET_BRANCH="main"

# Create a temporary directory that will be cleaned up automatically
TEMP_DIR=$(mktemp -d)

# --- SAFETY TRAP ---
# This 'trap' command ensures that no matter how the script exits (success or error),
# the temporary directory will be removed.
trap 'rm -rf "$TEMP_DIR"' EXIT

# --- Helper Functions ---
function error() {
    # GitHub Actions: Log an error annotation
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::error::Error: $1"
    else
        echo "Error: $1"
    fi
    exit 1
}

function warning() {
    # GitHub Actions: Log a warning annotation
    if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
        echo "::warning::Warning: $1"
    else
        echo "Warning: $1"
    fi
}

# Dependency check
function check_dependencies() {
    echo "Checking dependencies..."
    local missing_deps=0
    for cmd in curl jq git awk mktemp grep sed sort; do
        if ! command -v "$cmd" &> /dev/null; then
            error "$cmd is not installed. Please install it to continue."
            missing_deps=1
        fi
    done
    [[ "$missing_deps" -eq 0 ]] || exit 1
}

# --- 1. CRITICAL: API Paging Function ---
# Gets ALL results from a paged Cloudflare API endpoint.
function cf_api_get_all() {
    local url="$1"
    local query_param="?per_page=100&page=1"
    
    echo "Fetching all pages from $url..."

    # Make the first call to get page 1 and total_pages
    local first_response
    first_response=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "${url}${query_param}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json") || error "API call failed for: $url"

    local total_pages
    total_pages=$(echo "$first_response" | jq -r '.result_info.total_pages // 1')
    
    local all_results
    all_results=$(echo "$first_response" | jq '.result // []')

    # Loop if there are more pages
    if [[ "$total_pages" -gt 1 ]]; then
        local i
        for i in $(seq 2 "$total_pages"); do
            echo "Fetching page $i/$total_pages from $url..."
            local page_response
            page_response=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "${url}?per_page=100&page=${i}" \
                -H "Authorization: Bearer ${API_TOKEN}" \
                -H "Content-Type: application/json") || error "API call failed for: $url page $i"
            
            local page_results
            page_results=$(echo "$page_response" | jq '.result // []')
            
            # Merge the arrays
            all_results=$(echo "$all_results $page_results" | jq -s 'add')
        done
    fi

    # Return the final, complete JSON object
    echo "{\"result\": $all_results, \"success\": true}"
}


# --- 2. Aggregation Function (IMPROVED) ---
function run_aggregation() {
    echo "--- 1. Aggregating Lists ---"
    
    if [[ ! -f "$SOURCE_FILE" ]]; then
        error "$SOURCE_FILE not found. Please create it and add your list URLs."
    fi
    
    # Read all non-comment, non-empty lines from SOURCE_FILE into an array
    local LIST_URLS=()
    mapfile -t LIST_URLS < <(grep -vE '^\s*#|^\s*$' "$SOURCE_FILE")
    
    if [[ ${#LIST_URLS[@]} -eq 0 ]]; then
        error "No valid URLs found in $SOURCE_FILE."
    fi

    echo "Using temporary directory: $TEMP_DIR"
    echo "Downloading ${#LIST_URLS[@]} lists in parallel..."
    
    local i
    for i in "${!LIST_URLS[@]}"; do
        curl -L -sS -o "$TEMP_DIR/list_$i.txt" "${LIST_URLS[$i]}" &
    done
    wait
    echo "All lists downloaded."

    echo "Processing, normalizing, and deduplicating domains..."
    
    # IMPROVEMENT: This single awk command replaces the entire grep/awk/tr/sed pipeline.
    cat "$TEMP_DIR"/list_*.txt | \
    awk '
        # 1. Skip comments and empty lines
        /^\s*#|^\s*$/ {next}
        
        # 2. Get the domain (from hosts file or domain list)
        {if (NF >= 2) d=$2; else d=$1}
        
        # 3. Filter out junk and invalid domains
        if (d ~ /^(localhost|127.0.0.1|0.0.0.0|::1)$/) {next}
        if (d !~ /\./ || d ~ /[<>&;\"\/'=]/) {next}
        
        # 4. Convert to lowercase
        d = tolower(d)
        
        # 5. Remove carriage returns (just in case)
        gsub(/\r$/, "", d)
        
        # 6. Print the cleaned domain if it has content
        if (length(d) > 0) {print d}
    ' | \
    # 7. Sort and find unique entries
    sort -u \
    > "$OUTPUT_FILE"

    echo "Processing complete. Aggregated list saved to $OUTPUT_FILE."
}

# --- 3. Cloudflare Sync Function (HEAVILY IMPROVED) ---
function sync_cloudflare() {
    echo "--- 2. Syncing to Cloudflare ---"
    
    # --- 0. Define all local variables ---
    local total_lines total_lists
    local current_lists current_policies
    local current_lists_count current_lists_count_without_prefix
    local chunked_lists=()
    local file
    local used_list_ids=()
    local excess_list_ids=()
    local list_counter=1
    local list_id
    local list_items_array
    local payload_file
    local formatted_counter
    local items_json
    local list
    local list_details list_name list_desc
    local policy_id
    local expression_json
    local ids_json
    local policy_file
    local total_policy_chunks
    local chunk_index
    local policy_name
    local used_policy_ids=()
    local excess_policy_ids=()
    
    # --- 1. Validate aggregated file ---
    # We already know the file has changed, thanks to the check in main()
    [[ -s "$OUTPUT_FILE" ]] || error "The aggregated domains list is empty"
    total_lines=$(wc -l < "$OUTPUT_FILE")
    echo "Total unique domains aggregated: $total_lines"

    (( total_lines <= MAX_LIST_SIZE * MAX_LISTS )) || error "The domains list has more than $((MAX_LIST_SIZE * MAX_LISTS)) lines"

    total_lists=$((total_lines / MAX_LIST_SIZE))
    [[ $((total_lines % MAX_LIST_SIZE)) -ne 0 ]] && total_lists=$((total_lists + 1))
    echo "This will require $total_lists Cloudflare lists."

    # --- 2. Fetch current Cloudflare state (IMPROVEMENT: Using Paging) ---
    current_lists=$(cf_api_get_all "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists")
    current_policies=$(cf_api_get_all "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules")

    # --- 3. Count lists (using safer jq) ---
    current_lists_count=$(echo "${current_lists}" | jq -r --arg PREFIX "${PREFIX}" '(.result // []) | map(select(.name | contains($PREFIX))) | length') || error "Failed to count current lists"
    current_lists_count_without_prefix=$(echo "${current_lists}" | jq -r --arg PREFIX "${PREFIX}" '(.result // []) | map(select(.name | contains($PREFIX) | not)) | length') || error "Failed to count current lists without prefix"

    # --- 4. Check size constraints ---
    [[ ${total_lists} -le $((MAX_LISTS - current_lists_count_without_prefix)) ]] || error "The number of lists required (${total_lists}) is greater than the maximum allowed (${MAX_LISTS - current_lists_count_without_prefix})"

    # --- 5. Split file and prepare chunks ---
    split -l ${MAX_LIST_SIZE} "$OUTPUT_FILE" "${OUTPUT_FILE}." || error "Failed to split the domains list"
    for file in ${OUTPUT_FILE}.*; do
        chunked_lists+=("${file}")
    done

    # --- 6. Update existing lists (IMPROVEMENT: Using efficient PUT) ---
    if [[ ${current_lists_count} -gt 0 ]]; then
        for list_id in $(echo "${current_lists}" | jq -r --arg PREFIX "${PREFIX}" '(.result // []) | map(select(.name | contains($PREFIX))) | .[].id'); do
            
            [[ ${#chunked_lists[@]} -eq 0 ]] && {
                echo "Marking list ${list_id} for deletion..."
                excess_list_ids+=("${list_id}")
                continue
            }

            echo "Updating list ${list_id} with PUT..."
            list_details=$(echo "${current_lists}" | jq --arg LIST_ID "$list_id" '.result[] | select(.id == $LIST_ID)')
            list_name=$(echo "$list_details" | jq -r '.name')
            list_desc=$(echo "$list_details" | jq -r '.description // ""')
            list_items_array=$(jq -R -s 'split("\n") | map(select(length > 0) | { "value": . })' "${chunked_lists[0]}")
            payload_file=$(mktemp -p "$TEMP_DIR") || error "Failed to create temporary file for list payload"
            
            jq -n --arg name "$list_name" \
                    --arg desc "$list_desc" \
                    --argjson items "$list_items_array" \
                    '{ "name": $name, "description": $desc, "type": "DOMAIN", "items": $items }' > "${payload_file}"

            curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X PUT "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists/${list_id}" \
                -H "Authorization: Bearer ${API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "@${payload_file}" > /dev/null || { error "Failed to update list ${list_id}"; }

            used_list_ids+=("${list_id}")
            rm -f "${chunked_lists[0]}"
            chunked_lists=("${chunked_lists[@]:1}")
            list_counter=$((list_counter + 1))
        done
    fi

    # --- 7. Create extra lists if required ---
    for file in "${chunked_lists[@]}"; do
        echo "Creating list..."
        formatted_counter=$(printf "%03d" "$list_counter")
        list_name="${PREFIX} - ${formatted_counter}"
        items_json=$(jq -R -s 'split("\n") | map(select(length > 0) | { "value": . })' "${file}")
        payload_file=$(mktemp -p "$TEMP_DIR") || error "Failed to create temporary file for list payload"
        
        jq -n --arg name "${list_name}" --argjson items "$items_json" '{
            "name": $name,
            "type": "DOMAIN",
            "items": $items,
            "description": "Aggregated blocklist chunk"
        }' > "${payload_file}"

        list=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X POST "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists" \
            -H "Authorization: Bearer ${API_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "@${payload_file}") || { error "Failed to create list"; }

        used_list_ids+=("$(echo "${list}" | jq -r '.result.id')")
        rm -f "${file}"
        list_counter=$((list_counter + 1))
    done
    
    echo "All ${#used_list_ids[@]} lists are synced."

    # --- 8. CRITICAL FIX: Policy Chunking ---
    total_policy_chunks=$(( (${#used_list_ids[@]} + MAX_LISTS_PER_POLICY - 1) / MAX_LISTS_PER_POLICY ))
    echo "This requires $total_policy_chunks policies."

    for (( chunk_index=0; chunk_index<total_policy_chunks; chunk_index++ )); do
        policy_name="${PREFIX} - P$((chunk_index + 1))"
        echo "Syncing policy: ${policy_name}..."
        
        local start_index=$(( chunk_index * MAX_LISTS_PER_POLICY ))
        local list_id_slice=("${used_list_ids[@]:start_index:MAX_LISTS_PER_POLICY}")
        
        ids_json=$(printf '%s\n' "${list_id_slice[@]}" | jq -R -s 'split("\n") | map(select(length > 0))')
        expression_json=$(jq -n --argjson ids "$ids_json" '{
            "or": ($ids | map({
                "any": {
                    "in": {
                        "lhs": { "splat": "dns.domains" },
                        "rhs": ("$" + .)
                    }
                }
            }))
        }')

        policy_file=$(mktemp -p "$TEMP_DIR") || error "Failed to create temporary file for policy payload"
        jq -n --arg name "$policy_name" --argjson expression "$expression_json" '{
            "name": $name,
            "conditions": [ { "type": "traffic", "expression": $expression } ],
            "action": "block",
            "enabled": true,
            "description": "Aggregated blocklist policy chunk",
            "rule_settings": { "block_page_enabled": false },
            "filters": ["dns"]
        }' > "${policy_file}"
        
        policy_id=$(echo "${current_policies}" | jq -r --arg NAME "$policy_name" '(.result // []) | map(select(.name == $NAME)) | .[0].id')
        
        if [[ -z "${policy_id}" || "${policy_id}" == "null" ]]; then
            echo "Creating policy ${policy_name}..."
            local new_policy
            new_policy=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X POST "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules" \
                -H "Authorization: Bearer ${API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "@${policy_file}") || { error "Failed to create policy ${policy_name}"; }
            
            used_policy_ids+=("$(echo "$new_policy" | jq -r '.result.id')")
        else
            echo "Updating policy ${policy_name} (${policy_id})..."
            curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X PUT "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules/${policy_id}" \
                -H "Authorization: Bearer ${API_TOKEN}" \
                -H "Content-Type: application/json" \
                --data "@${policy_file}" > /dev/null || { error "Failed to update policy ${policy_id}"; }
            
            used_policy_ids+=("${policy_id}")
        fi
    done
    
    # --- 9. Delete excess POLICIES ---
    for policy_id in $(echo "${current_policies}" | jq -r --arg PREFIX "${PREFIX}" '(.result // []) | map(select(.name | contains($PREFIX))) | .[].id'); do
        local found=0
        for used_id in "${used_policy_ids[@]}"; do
            if [[ "$policy_id" == "$used_id" ]]; then
                found=1
                break
            fi
        done
        
        if [[ $found -eq 0 ]]; then
            excess_policy_ids+=("$policy_id")
        fi
    done
    
    if [[ ${#excess_policy_ids[@]} -gt 0 ]]; then
        echo "Deleting ${#excess_policy_ids[@]} excess policies in parallel..."
        for policy_id in "${excess_policy_ids[@]}"; do
        (
            echo "Deleting policy ${policy_id}..."
            curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X DELETE "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules/${policy_id}" \
                -H "Authorization: Bearer ${API_TOKEN}" \
                -H "Content-Type: application/json" || warning "Failed to delete policy ${policy_id}"
        ) &
        done
        wait
    fi

    # --- 10. Delete excess LISTS (IN PARALLEL) ---
    if [[ ${#excess_list_ids[@]} -gt 0 ]]; then
        echo "Deleting ${#excess_list_ids[@]} excess lists in parallel..."
        for list_id in "${excess_list_ids[@]}"; do
            (
                echo "Deleting list ${list_id}..."
                curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X DELETE "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists/${list_id}" \
                    -H "Authorization: Bearer ${API_TOKEN}" \
                    -H "Content-Type: application/json" || warning "Failed to delete list ${list_id}"
            ) &
        done
        wait
    fi

    echo "Cloudflare sync complete."
    # Return 0 (success) to indicate changes were made
    return 0
}

# --- 4. Git Commit Function ---
function commit_to_git() {
    echo "--- 3. Committing to Git ---"
    local total_lines=$1
    
    echo "Configuring Git user for this commit..."
    # Use default values if GITHUB_ACTOR is not set (for local testing)
    local git_user_name="${GITHUB_ACTOR:-Bot}[bot]"
    local git_user_email="${GITHUB_ACTOR_ID:-41898282}+${GITHUB_ACTOR:-github-actions}@users.noreply.github.com"

    echo "Committing and pushing updated list..."
    git add "$OUTPUT_FILE" || error "Failed to add the domains list to repo"
    
    git commit \
        -m "Update domains list ($total_lines domains)" \
        --author="${git_user_name} <${git_user_email}>" \
        || error "Failed to commit the domains list to repo"
    
    if git remote get-url origin >/dev/null 2>&1 && git ls-remote --exit-code --heads origin "${TARGET_BRANCH}" >/dev/null 2>&1; then
        git pull --rebase origin "${TARGET_BRANCH}" || error "Failed to rebase onto the latest ${TARGET_BRANCH}"
    fi
    git push origin "${TARGET_BRANCH}" || error "Failed to push the domains list to repo"
    
    echo "Git commit and push complete."
}


# --- Main Execution (IMPROVED) ---
function main() {
    # --- -1. Check Dependencies ---
    check_dependencies

    # --- 0. Validate Secrets and Sync Git ---
    echo "--- 0. Initializing ---"
    
    if [ -z "${API_TOKEN}" ]; then
        error "API_TOKEN secret is not set. Please set it in GitHub repository settings."
    fi
    if [ -z "${ACCOUNT_ID}" ]; then
        error "ACCOUNT_ID secret is not set. Please set it in GitHub repository settings."
    fi

    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        if git remote get-url origin >/dev/null 2>&1; then
            if git ls-remote --exit-code --heads origin "${TARGET_BRANCH}" >/dev/null 2>&1; then
                git fetch origin "${TARGET_BRANCH}" || error "Failed to fetch ${TARGET_BRANCH} from origin"
                git checkout -B "${TARGET_BRANCH}" "origin/${TARGET_BRANCH}" || error "Failed to sync local ${TARGET_BRANCH} with origin"
            else
                git checkout -B "${TARGET_BRANCH}" || error "Failed to ensure local ${TARGET_BRANCH} exists"
            fi
        fi
    fi

    # --- 1. Run the Aggregation ---
    run_aggregation

    # --- 2. IMPROVEMENT: Early Exit ---
    # Check for changes *before* running the API-heavy sync.
    if git diff --exit-code "$OUTPUT_FILE" > /dev/null; then
        echo "The aggregated domains list has not changed. No sync needed."
        exit 0
    fi
    
    # --- 3. Run the Cloudflare Sync ---
    # If we are here, there are changes to sync.
    sync_cloudflare
    
    # --- 4. Run the Git Commit ---
    local total_lines
    total_lines=$(wc -l < "$OUTPUT_FILE")
    commit_to_git "$total_lines"

    echo "================================================"
    echo "Aggregation and Cloudflare upload finished!"
    echo "Total unique domains: $total_lines"
    echo "================================================"
}

# Run the main function
main "$@"
