import os
import sys
import json
import requests
import argparse

# Constants
API_BASE = "https://api.cloudflare.com/client/v4"
ASN_LIST_FILENAME = "ASN List"
LIST_NAME = "managed_bad_asns"
RULE_NAME = "Block Bad ASNs"
RULE_DESCRIPTION = "Block traffic from bad ASNs defined in the managed list"

def get_headers(api_token):
    return {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json"
    }

def read_asn_list(filepath):
    """Reads ASNs from the file, stripping 'AS' prefix if present."""
    asns = []
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Remove 'AS' prefix if present, though Cloudflare API usually expects just the number for some endpoints,
            # for ASN Lists, the value should be the ASN number.
            # However, let's check if it starts with AS and remove it to be safe, 
            # or keep it if the API requires it. 
            # Cloudflare ASN list items expect `value` to be the ASN number (integer).
            if line.upper().startswith("AS"):
                try:
                    asns.append(int(line[2:]))
                except ValueError:
                    print(f"Warning: Invalid ASN format '{line}', skipping.")
            else:
                try:
                    asns.append(int(line))
                except ValueError:
                    print(f"Warning: Invalid ASN format '{line}', skipping.")
    return list(set(asns)) # Deduplicate

def get_account_id(zone_id, api_token):
    """Fetches Account ID from Zone ID."""
    url = f"{API_BASE}/zones/{zone_id}"
    response = requests.get(url, headers=get_headers(api_token))
    if response.status_code != 200:
        print(f"Error fetching zone info: {response.text}")
        sys.exit(1)
    
    data = response.json()
    if not data.get("success"):
        print(f"Error: {data.get('errors')}")
        sys.exit(1)
        
    return data["result"]["account"]["id"]

def get_existing_list(account_id, api_token, list_name):
    """Checks if an ASN list with the given name already exists."""
    url = f"{API_BASE}/accounts/{account_id}/rules/lists"
    response = requests.get(url, headers=get_headers(api_token))
    if response.status_code != 200:
        print(f"Error fetching lists: {response.text}")
        sys.exit(1)
        
    data = response.json()
    for item in data.get("result", []):
        if item["name"] == list_name and item["kind"] == "asn":
            return item
    return None

def create_asn_list(account_id, api_token, list_name, asns):
    """Creates a new ASN list."""
    print(f"Creating new ASN list '{list_name}'...")
    url = f"{API_BASE}/accounts/{account_id}/rules/lists"
    
    # Prepare items
    items = [{"value": asn} for asn in asns]
    
    payload = {
        "name": list_name,
        "kind": "asn",
        "description": "List of bad ASNs managed by script",
        "items": items
    }
    
    response = requests.post(url, headers=get_headers(api_token), json=payload)
    if response.status_code == 200 and response.json().get("success"):
        print("ASN List created successfully.")
        return response.json()["result"]
    else:
        print(f"Error creating list: {response.text}")
        sys.exit(1)

def update_asn_list(account_id, api_token, list_id, asns):
    """Updates an existing ASN list. 
    Note: Cloudflare List API 'PUT' replaces all items.
    """
    print(f"Updating ASN list '{list_id}'...")
    url = f"{API_BASE}/accounts/{account_id}/rules/lists/{list_id}/items"
    
    # We need to replace items. The PUT endpoint on /items appends? 
    # Actually PUT /accounts/{account_id}/rules/lists/{list_id} updates metadata.
    # PUT /accounts/{account_id}/rules/lists/{list_id}/items replaces all items.
    
    items = [{"value": asn} for asn in asns]
    payload = items
    
    # Using PUT to replace all items
    response = requests.put(url, headers=get_headers(api_token), json=payload)
    
    if response.status_code == 200 and response.json().get("success"):
        print("ASN List updated successfully.")
    else:
        print(f"Error updating list: {response.text}")
        sys.exit(1)

def create_or_update_waf_rule(zone_id, api_token, list_id):
    """Creates or updates the WAF custom rule to block the ASN list."""
    
    # 1. Get existing ruleset for custom rules (entry point)
    url = f"{API_BASE}/zones/{zone_id}/rulesets/phases/http_request_firewall_custom/entrypoint"
    response = requests.get(url, headers=get_headers(api_token))
    
    ruleset_id = None
    existing_rule_id = None
    
    if response.status_code == 200:
        data = response.json()
        if data.get("success"):
            ruleset_id = data["result"]["id"]
            # Check if our rule exists
            if "rules" in data["result"]:
                for rule in data["result"]["rules"]:
                    if rule.get("description") == RULE_DESCRIPTION:
                        existing_rule_id = rule["id"]
                        break
    
    # Expression to match ASNs in the list
    expression = f"ip.asn in ${LIST_NAME}"
    action = "block" # or "managed_challenge" as per original script? Original was managed_challenge.
    # Original script: "mode":"managed_challenge"
    action = "managed_challenge"
    
    rule_payload = {
        "action": action,
        "expression": expression,
        "description": RULE_DESCRIPTION,
        "enabled": True
    }

    if existing_rule_id:
        print(f"Updating existing WAF rule '{RULE_DESCRIPTION}'...")
        # Update rule
        update_url = f"{API_BASE}/zones/{zone_id}/rulesets/{ruleset_id}/rules/{existing_rule_id}"
        response = requests.patch(update_url, headers=get_headers(api_token), json=rule_payload)
    else:
        print(f"Creating new WAF rule '{RULE_DESCRIPTION}'...")
        # Create rule. If ruleset doesn't exist, we create it.
        if ruleset_id:
            create_url = f"{API_BASE}/zones/{zone_id}/rulesets/{ruleset_id}/rules"
            response = requests.post(create_url, headers=get_headers(api_token), json=rule_payload)
        else:
            # Create ruleset with rule
            create_ruleset_url = f"{API_BASE}/zones/{zone_id}/rulesets"
            payload = {
                "name": "default",
                "kind": "zone",
                "phase": "http_request_firewall_custom",
                "rules": [rule_payload]
            }
            response = requests.post(create_ruleset_url, headers=get_headers(api_token), json=payload)

    if response.status_code == 200 and response.json().get("success"):
        print("WAF Rule configured successfully.")
    else:
        print(f"Error configuring WAF rule: {response.text}")
        sys.exit(1)

def main():
    print("Cloudflare ASN Rules Updater")
    print("----------------------------")
    
    # Inputs
    zone_id = input("Enter Cloudflare Zone ID: ").strip()
    api_token = input("Enter Cloudflare API Token (Permissions: Zone:Read, Firewall:Edit, Account Filter Lists:Edit): ").strip()
    
    if not zone_id or not api_token:
        print("Error: Zone ID and API Token are required.")
        sys.exit(1)

    # 1. Read ASNs
    print(f"Reading ASNs from '{ASN_LIST_FILENAME}'...")
    asns = read_asn_list(ASN_LIST_FILENAME)
    print(f"Found {len(asns)} unique ASNs.")

    # 2. Get Account ID
    print("Fetching Account ID...")
    account_id = get_account_id(zone_id, api_token)
    print(f"Account ID: {account_id}")

    # 3. Manage ASN List
    existing_list = get_existing_list(account_id, api_token, LIST_NAME)
    
    if existing_list:
        update_asn_list(account_id, api_token, existing_list["id"], asns)
    else:
        create_asn_list(account_id, api_token, LIST_NAME, asns)

    # 4. Manage WAF Rule
    create_or_update_waf_rule(zone_id, api_token, existing_list["id"] if existing_list else LIST_NAME)

    print("\nDone! Your Cloudflare protection has been updated.")

if __name__ == "__main__":
    main()
