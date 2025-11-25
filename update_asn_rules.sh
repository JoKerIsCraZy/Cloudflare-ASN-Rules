#!/bin/bash

# Cloudflare ASN Rules Updater (Bash)
# Requires: curl, jq

API_BASE="https://api.cloudflare.com/client/v4"
ASN_LIST_FILENAME="ASN List"
LIST_NAME="managed_bad_asns"
RULE_DESCRIPTION="Block Bad ASNs"

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo "Error: curl is required but not installed."
    exit 1
fi

echo "Cloudflare ASN Rules Updater"
echo "----------------------------"

read -p "Enter Cloudflare Zone ID: " ZONE_ID
read -p "Enter Cloudflare API Token: " API_TOKEN

if [ -z "$ZONE_ID" ] || [ -z "$API_TOKEN" ]; then
    echo "Error: Zone ID and API Token are required."
    exit 1
fi

AUTH_HEADER="Authorization: Bearer $API_TOKEN"
CONTENT_TYPE="Content-Type: application/json"

# 1. Read ASNs
if [ ! -f "$ASN_LIST_FILENAME" ]; then
    echo "Error: File '$ASN_LIST_FILENAME' not found."
    exit 1
fi

echo "Reading ASNs from '$ASN_LIST_FILENAME'..."
# Read file, remove empty lines, remove 'AS' prefix, create JSON array
# We use jq to construct the JSON array of objects {"value": 12345}
# tr -d '\r' handles Windows line endings if present
ITEMS=$(grep -vE '^\s*$' "$ASN_LIST_FILENAME" | tr -d '\r' | sed 's/^AS//i' | jq -R -s 'split("\n") | map(select(length > 0)) | map({value: (. | tonumber)})')
COUNT=$(echo "$ITEMS" | jq 'length')
echo "Found $COUNT ASNs."

# 2. Get Account ID
echo "Fetching Account ID..."
RESPONSE=$(curl -s -X GET "$API_BASE/zones/$ZONE_ID" -H "$AUTH_HEADER" -H "$CONTENT_TYPE")
SUCCESS=$(echo "$RESPONSE" | jq '.success')

if [ "$SUCCESS" != "true" ]; then
    echo "Error fetching zone info: $(echo "$RESPONSE" | jq -r '.errors[0].message')"
    exit 1
fi

ACCOUNT_ID=$(echo "$RESPONSE" | jq -r '.result.account.id')
echo "Account ID: $ACCOUNT_ID"

# 3. Manage ASN List
echo "Checking for existing ASN list..."
RESPONSE=$(curl -s -X GET "$API_BASE/accounts/$ACCOUNT_ID/rules/lists" -H "$AUTH_HEADER" -H "$CONTENT_TYPE")
LIST_ID=$(echo "$RESPONSE" | jq -r ".result[] | select(.name == \"$LIST_NAME\" and .kind == \"asn\") | .id")

if [ -n "$LIST_ID" ]; then
    echo "Updating ASN list '$LIST_ID'..."
    # PUT /items replaces all items
    RESPONSE=$(curl -s -X PUT "$API_BASE/accounts/$ACCOUNT_ID/rules/lists/$LIST_ID/items" \
        -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
        -d "$ITEMS")
else
    echo "Creating new ASN list '$LIST_NAME'..."
    PAYLOAD=$(jq -n \
        --arg name "$LIST_NAME" \
        --arg desc "List of bad ASNs managed by script" \
        --argjson items "$ITEMS" \
        '{name: $name, kind: "asn", description: $desc, items: $items}')
    
    RESPONSE=$(curl -s -X POST "$API_BASE/accounts/$ACCOUNT_ID/rules/lists" \
        -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
        -d "$PAYLOAD")
    
    LIST_ID=$(echo "$RESPONSE" | jq -r '.result.id')
fi

SUCCESS=$(echo "$RESPONSE" | jq '.success')
if [ "$SUCCESS" != "true" ]; then
    echo "Error managing list: $(echo "$RESPONSE" | jq -r '.errors[0].message')"
    exit 1
fi
echo "ASN List managed successfully."

# 4. Manage WAF Rule
# Get Ruleset ID for custom rules
echo "Configuring WAF Rule..."
RESPONSE=$(curl -s -X GET "$API_BASE/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" -H "$AUTH_HEADER" -H "$CONTENT_TYPE")
RULESET_ID=$(echo "$RESPONSE" | jq -r '.result.id')

RULE_PAYLOAD=$(jq -n \
    --arg desc "$RULE_DESCRIPTION" \
    --arg expr "ip.asn in \$$LIST_NAME" \
    '{action: "managed_challenge", expression: $expr, description: $desc, enabled: true}')

if [ "$RULESET_ID" == "null" ]; then
    # Create Ruleset
    echo "Creating new Ruleset..."
    PAYLOAD=$(jq -n \
        --arg phase "http_request_firewall_custom" \
        --argjson rules "[$RULE_PAYLOAD]" \
        '{name: "default", kind: "zone", phase: $phase, rules: $rules}')
        
    RESPONSE=$(curl -s -X POST "$API_BASE/zones/$ZONE_ID/rulesets" \
        -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
        -d "$PAYLOAD")
else
    # Check for existing rule
    EXISTING_RULE_ID=$(echo "$RESPONSE" | jq -r ".result.rules[] | select(.description == \"$RULE_DESCRIPTION\") | .id")
    
    if [ -n "$EXISTING_RULE_ID" ]; then
        echo "Updating existing WAF rule..."
        RESPONSE=$(curl -s -X PATCH "$API_BASE/zones/$ZONE_ID/rulesets/$RULESET_ID/rules/$EXISTING_RULE_ID" \
            -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
            -d "$RULE_PAYLOAD")
    else
        echo "Creating new WAF rule..."
        RESPONSE=$(curl -s -X POST "$API_BASE/zones/$ZONE_ID/rulesets/$RULESET_ID/rules" \
            -H "$AUTH_HEADER" -H "$CONTENT_TYPE" \
            -d "$RULE_PAYLOAD")
    fi
fi

SUCCESS=$(echo "$RESPONSE" | jq '.success')
if [ "$SUCCESS" != "true" ]; then
    echo "Error configuring WAF rule: $(echo "$RESPONSE" | jq -r '.errors[0].message')"
    exit 1
fi

echo "Done! Your Cloudflare protection has been updated."
