#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error.
set -u
# The return value of a pipeline is the status of the last command to exit with a non-zero status.
set -o pipefail

echo "Starting Cloudflare list and policy deletion..."

# --- Configuration ---
API_TOKEN="${API_TOKEN:-}"
ACCOUNT_ID="${ACCOUNT_ID:-}"
PREFIX="Block ads"
MAX_RETRIES=10

# --- Helper Function ---
function error() {
    echo "Error: $1"
    # Don't exit on error, to allow script to continue
}

# --- 0. Validate Secrets ---
if [ -z "${API_TOKEN}" ]; then
    echo "API_TOKEN secret is not set. Please set it in GitHub repository settings."
    exit 1
fi
if [ -z "${ACCOUNT_ID}" ]; then
    echo "ACCOUNT_ID secret is not set. Please set it in GitHub repository settings."
    exit 1
fi

# --- 1. Delete local files ---
echo "Deleting local list files..."
rm -f Aggregated_List.txt
rm -f Aggregated_List.txt.*
echo "Local files deleted."

# --- 2. Get Cloudflare Data ---
# Get current lists from Cloudflare
echo "Fetching current lists from Cloudflare..."
current_lists=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Content-Type: application/json") || error "Failed to get current lists from Cloudflare"
    
# Get current policies from Cloudflare
echo "Fetching current policies from Cloudflare..."
current_policies=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Content-Type: application/json") || error "Failed to get current policies from Cloudflare"

# --- 3. Delete Policy ---
echo "Deleting policy..."
policy_id=$(echo "${current_policies}" | jq -r --arg PREFIX "${PREFIX}" '.result | map(select(.name == $PREFIX)) | .[0].id') || error "Failed to get policy ID"

if [ -z "${policy_id}" ] || [ "${policy_id}" == "null" ]; then
    echo "No policy found with prefix '$PREFIX'. Skipping policy deletion."
else
    curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X DELETE "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules/${policy_id}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json" > /dev/null || error "Failed to delete policy ${policy_id}"
    echo "Policy ${policy_id} deleted."
fi

# --- 4. Delete Lists ---
echo "Deleting lists..."
list_ids_to_delete=$(echo "${current_lists}" | jq -r --arg PREFIX "${PREFIX}" '.result | map(select(.name | contains($PREFIX))) | .[].id')

if [ -z "${list_ids_to_delete}" ]; then
    echo "No lists found with prefix '$PREFIX'. Skipping list deletion."
else
    for list_id in $list_ids_to_delete; do
        echo "Deleting list ${list_id}..."
        curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X DELETE "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists/${list_id}" \
            -H "Authorization: Bearer ${API_TOKEN}" \
            -H "Content-Type: application/json" > /dev/null || error "Failed to delete list ${list_id}"
    done
    echo "All lists deleted."
fi

echo "================================================"
echo "Cloudflare cleanup finished!"
echo "================================================"#!/bin/bash

# Replace these variables with your actual Cloudflare API token and account ID
API_TOKEN="$API_TOKEN"
ACCOUNT_ID="$ACCOUNT_ID"
PREFIX="Block ads"
MAX_RETRIES=10

# Define error function
function error() {
    echo "Error: $1"
}

# Delete files
echo "Deleting files..."
rm -f Aggregated_List.txt
rm -f Aggregated_List.txt.*

# Get current lists from Cloudflare
current_lists=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Content-Type: application/json") || error "Failed to get current lists from Cloudflare"
    
# Get current policies from Cloudflare
current_policies=$(curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X GET "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Content-Type: application/json") || error "Failed to get current policies from Cloudflare"

# Delete policy with $PREFIX as name
echo "Deleting policy..."
policy_id=$(echo "${current_policies}" | jq -r --arg PREFIX "${PREFIX}" '.result | map(select(.name == $PREFIX)) | .[0].id') || error "Failed to get policy ID"
curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X DELETE "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/rules/${policy_id}" \
    -H "Authorization: Bearer ${API_TOKEN}" \
    -H "Content-Type: application/json" > /dev/null || error "Failed to delete policy"

# Delete all lists with $PREFIX in name
echo "Deleting lists..."
for list_id in $(echo "${current_lists}" | jq -r --arg PREFIX "${PREFIX}" '.result | map(select(.name | contains($PREFIX))) | .[].id'); do
    echo "Deleting list ${list_id}..."
    curl -sSfL --retry "$MAX_RETRIES" --retry-all-errors -X DELETE "https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/gateway/lists/${list_id}" \
        -H "Authorization: Bearer ${API_TOKEN}" \
        -H "Content-Type: application/json" > /dev/null || error "Failed to delete list ${list_id}"
