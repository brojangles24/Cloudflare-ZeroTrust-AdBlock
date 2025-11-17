#!/bin/bash

# Replace these variables with your actual Cloudflare API token and account ID
API_TOKEN="$API_TOKEN"
ACCOUNT_ID="$ACCOUNT_ID"
PREFIX="Block ads"
MAX_LIST_SIZE=1000
MAX_LISTS=300
MAX_RETRIES=10
TARGET_BRANCH="${GITHUB_REF_NAME:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null)}"
[[ -n "${TARGET_BRANCH}" ]] || TARGET_BRANCH="main"

# Define error function
function error() {
    echo "Error: $1"
    rm -f HaGeZi_Ultimate_domains.txt.*
    exit 1
}

# Define silent error function
function silent_error() {
    echo "Silent error: $1"
    rm -f HaGeZi_Ultimate_domains.txt.*
    exit 0
}

# Ensure the local checkout is up to date with the remote target branch before
# making any changes so the subsequent commit can fast-forward cleanly.
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

# Download the latest domains list
curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro.plus-onlydomains.txt | grep -vE '^\s*(#|$)' > HaGeZi_Ultimate_domains.txt || silent_error "Failed to download the domains list"

# Check if the file has changed
git diff --exit-code HaGeZi_Ultimate_domains.txt > /dev/null && silent_error "The domains list has not changed"

# Ensure the file is not empty
[[ -s HaGeZi_Ultimate_domains.txt ]] || error "The domains list is empty"

# Calculate the number of lines in the file
total_lines=$(wc -l < HaGeZi_Ultimate_domains.txt)

# Ensure the file is not over the maximum allowed lines
(( total_lines <= MAX_LIST_SIZE * MAX_LISTS )) || error "The domains list has more than $((MAX_LIST_SIZE * MAX_LISTS)) lines"

# Calculate the number of lists required
total_lists=$((total_lines / MAX_LIST_SIZE))
[[ $((total_lines % MAX_LIST_SIZE)) -ne 0 ]] && total_lists=$((total_lists + 1))

# Get current lists from Cloudflare
current_lists=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Content-Type: application/json") || error "Failed to get current lists from Cloudflare"
    
# Get current policies from Cloudflare
current_policies=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Content-Type: application/json") || error "Failed to get current policies from Cloudflare"

# Count number of lists that have $PREFIX in name
current_lists_count=$(echo "${current_lists}" | jq -r --arg PREFIX "${PREFIX}" 'if (.result | length > 0) then .result | map(select(.name | contains($PREFIX))) | length else 0 end') || error "Failed to count current lists"

# Count number of lists without $PREFIX in name
current_lists_count_without_prefix=$(echo "${current_lists}" | jq -r --arg PREFIX "${PREFIX}" 'if (.result | length > 0) then .result | map(select(.name | contains($PREFIX) | not)) | length else 0 end') || error "Failed to count current lists without prefix"

# Ensure total_lists name is less than or equal to $MAX_LISTS - current_lists_count_without_prefix
[[ ${total_lists} -le $((MAX_LISTS - current_lists_count_without_prefix)) ]] || error "The number of lists required (${total_lists}) is greater than the maximum allowed (${MAX_LISTS - current_lists_count_without_prefix})"

# Split lists into chunks of $MAX_LIST_SIZE
split -l ${MAX_LIST_SIZE} HaGeZi_Ultimate_domains.txt HaGeZi_Ultimate_domains.txt. || error "Failed to split the domains list"

# Create array of chunked lists
chunked_lists=()
for file in HaGeZi_Ultimate_domains.txt.*; do
    chunked_lists+=("${file}")
done

# Create array of used list IDs
used_list_ids=()

# Create array of excess list IDs
excess_list_ids=()

# Create list counter
list_counter=1

# Update existing lists
if [[ ${current_lists_count} -gt 0 ]]; then
    # For each list ID
    for list_id in $(echo "${current_lists}" | jq -r --arg PREFIX "${PREFIX}" '.result | map(select(.name | contains($PREFIX))) | .[].id'); do
        # If there are no more chunked lists, mark the list ID for deletion
        [[ ${#chunked_lists[@]} -eq 0 ]] && {
            echo "Marking list ${list_id} for deletion..."
            excess_list_ids+=("${list_id}")
            continue
        }

        echo "Updating list ${list_id}..."

        # Get list contents
        list_items=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists/${list_id}/items?limit=${MAX_LIST_SIZE}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json") || error "Failed to get list ${list_id} contents"

        # Create list item values for removal
        list_items_values=$(echo "${list_items}" | jq '.result | map(.value) | map(select(. != null))')

        # Create list item array for appending from first chunked list
        list_items_array=$(jq -R -s 'split("\n") | map(select(length > 0) | { "value": . })' "${chunked_lists[0]}")

        # Create payload file
        payload_file=$(mktemp) || error "Failed to create temporary file for list payload"
        jq -n --argjson append_items "$list_items_array" --argjson remove_items "$list_items_values" '{
            "append": $append_items,
            "remove": $remove_items
        }' > "${payload_file}"

        # Patch list with payload file to avoid oversized command invocations
        curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X PATCH "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists/${list_id}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "@${payload_file}" > /dev/null || { rm -f "${payload_file}"; error "Failed to patch list ${list_id}"; }

        rm -f "${payload_file}"

        # Store the list ID
        used_list_ids+=("${list_id}")

        # Delete the first chunked file and in the list
        rm -f "${chunked_lists[0]}"
        chunked_lists=("${chunked_lists[@]:1}")

        # Increment list counter
        list_counter=$((list_counter + 1))
    done
fi

# Create extra lists if required
for file in "${chunked_lists[@]}"; do
    echo "Creating list..."

    # Format list counter
    formatted_counter=$(printf "%03d" "$list_counter")

    # Create payload file
    items_json=$(jq -R -s 'split("\n") | map(select(length > 0) | { "value": . })' "${file}")
    payload_file=$(mktemp) || error "Failed to create temporary file for list payload"
    jq -n --arg PREFIX "${PREFIX} - ${formatted_counter}" --argjson items "$items_json" '{
        "name": $PREFIX,
        "type": "DOMAIN",
        "items": $items
    }' > "${payload_file}"

    # Create list
    list=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X POST "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "@${payload_file}") || { rm -f "${payload_file}"; error "Failed to create list"; }

    rm -f "${payload_file}"

    # Store the list ID
    used_list_ids+=("$(echo "${list}" | jq -r '.result.id')")

    # Delete the file
    rm -f "${file}"

    # Increment list counter
    list_counter=$((list_counter + 1))
done

# Ensure policy called exactly $PREFIX exists, else create it
policy_id=$(echo "${current_policies}" | jq -r --arg PREFIX "${PREFIX}" '.result | map(select(.name == $PREFIX)) | .[0].id') || error "Failed to get policy ID"

# Loop through the used_list_ids and build the policy expression dynamically
if [[ ${#used_list_ids[@]} -eq 1 ]]; then
    expression_json=$(jq -n --arg id "${used_list_ids[0]}" '{
        "any": {
            "in": {
                "lhs": { "splat": "dns.domains" },
                "rhs": ("$" + $id)
            }
        }
    }')
else
    ids_json=$(printf '%s\n' "${used_list_ids[@]}" | jq -R -s 'split("\n") | map(select(length > 0))')
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
fi

# Create the JSON data dynamically in a temporary file
policy_file=$(mktemp) || error "Failed to create temporary file for policy payload"
jq -n --arg name "${PREFIX}" --argjson expression "$expression_json" '{
    "name": $name,
    "conditions": [
        {
            "type": "traffic",
            "expression": $expression
        }
    ],
    "action": "block",
    "enabled": true,
    "description": "",
    "rule_settings": {
        "block_page_enabled": false,
        "block_reason": "",
        "biso_admin_controls": {
            "dcp": false,
            "dcr": false,
            "dd": false,
            "dk": false,
            "dp": false,
            "du": false
        },
        "add_headers": {},
        "ip_categories": false,
        "override_host": "",
        "override_ips": null,
        "l4override": null,
        "check_session": null
    },
    "filters": ["dns"]
}' > "${policy_file}"

[[ -z "${policy_id}" || "${policy_id}" == "null" ]] &&
{
    # Create the policy
    echo "Creating policy..."
    curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X POST "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "@${policy_file}" > /dev/null || { rm -f "${policy_file}"; error "Failed to create policy"; }
} ||
{
    # Update the policy
    echo "Updating policy ${policy_id}..."
    curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X PUT "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules/${policy_id}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "@${policy_file}" > /dev/null || { rm -f "${policy_file}"; error "Failed to update policy"; }
}

rm -f "${policy_file}"

# Delete excess lists in $excess_list_ids
for list_id in "${excess_list_ids[@]}"; do
    echo "Deleting list ${list_id}..."
    curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X DELETE "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists/${list_id}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json" > /dev/null || error "Failed to delete list ${list_id}"
done

# Add, commit and push the file
git config --global user.email "${GITHUB_ACTOR_ID}+${GITHUB_ACTOR}@users.noreply.github.com"
git config --global user.name "$(gh api /users/${GITHUB_ACTOR} | jq .name -r)"
git add HaGeZi_Ultimate_domains.txt || error "Failed to add the domains list to repo"
git commit -m "Update domains list" --author=. || error "Failed to commit the domains list to repo"
if git remote get-url origin >/dev/null 2>&1 && git ls-remote --exit-code --heads origin "${TARGET_BRANCH}" >/dev/null 2>&1; then
    git pull --rebase origin "${TARGET_BRANCH}" || error "Failed to rebase onto the latest ${TARGET_BRANCH}"
fi
git push origin "${TARGET_BRANCH}" || error "Failed to push the domains list to repo"
