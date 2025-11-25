import os
import sys
import json
import time
import requests
import csv
import io
from datetime import datetime

# --- Configuration ---
# You can set these via environment variables or directly here
ZONE_ID = os.getenv("CF_ZONE_ID", "")
API_TOKEN = os.getenv("CF_API_TOKEN", "")

# URLs and Constants
ASN_LIST_URL = "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"
STATE_FILE = "asn_state.json"
CHECK_INTERVAL_SECONDS = 30 * 24 * 60 * 60  # 30 days

# Cloudflare Settings
CF_API_BASE = "https://api.cloudflare.com/client/v4"
LIST_NAME = "managed_bad_asns"
RULE_NAME = "Block Bad ASNs"
RULE_DESCRIPTION = "Block traffic from bad ASNs defined in the managed list"

def get_headers():
    if not API_TOKEN:
        print("Error: API_TOKEN is not set. Please configure it in the script or environment variables.")
        sys.exit(1)
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }

def fetch_asns():
    """Fetches the latest ASN list from the source."""
    print(f"[{datetime.now()}] Fetching latest ASN list...")
    try:
        response = requests.get(ASN_LIST_URL)
        response.raise_for_status()
        
        content = response.content.decode('utf-8')
        csv_reader = csv.reader(io.StringIO(content))
        
        asns = set()
        next(csv_reader, None) # Skip header
        
        for row in csv_reader:
            if row:
                asn = row[0].strip()
                if asn.isdigit():
                    asns.add(int(asn))
                elif asn.upper().startswith("AS") and asn[2:].isdigit():
                    asns.add(int(asn[2:]))
        
        print(f"[{datetime.now()}] Fetched {len(asns)} unique ASNs.")
        return asns
    except Exception as e:
        print(f"[{datetime.now()}] Error fetching ASNs: {e}")
        return None

def load_state():
    """Loads the previously synced ASNs from the state file."""
    if not os.path.exists(STATE_FILE):
        return set()
    
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            return set(data.get("asns", []))
    except Exception as e:
        print(f"[{datetime.now()}] Warning: Could not load state file: {e}")
        return set()

def save_state(asns):
    """Saves the current ASNs to the state file."""
    try:
        with open(STATE_FILE, 'w') as f:
            json.dump({"last_updated": str(datetime.now()), "asns": list(asns)}, f)
        print(f"[{datetime.now()}] State saved to {STATE_FILE}.")
    except Exception as e:
        print(f"[{datetime.now()}] Error saving state: {e}")

def get_account_id():
    """Fetches Account ID from Zone ID."""
    if not ZONE_ID:
        print("Error: ZONE_ID is not set.")
        sys.exit(1)
        
    url = f"{CF_API_BASE}/zones/{ZONE_ID}"
    response = requests.get(url, headers=get_headers())
    if response.status_code != 200:
        print(f"Error fetching zone info: {response.text}")
        sys.exit(1)
    
    data = response.json()
    return data["result"]["account"]["id"]

def get_existing_list(account_id):
    """Checks if the ASN list exists."""
    url = f"{CF_API_BASE}/accounts/{account_id}/rules/lists"
    response = requests.get(url, headers=get_headers())
    if response.status_code == 200:
        for item in response.json().get("result", []):
            if item["name"] == LIST_NAME and item["kind"] == "asn":
                return item
    return None

def update_cloudflare_list(account_id, asns):
    """Creates or updates the ASN list in Cloudflare."""
    existing_list = get_existing_list(account_id)
    items = [{"value": asn} for asn in asns]
    
    if existing_list:
        print(f"[{datetime.now()}] Updating existing list '{LIST_NAME}'...")
        # PUT /items replaces all items
        url = f"{CF_API_BASE}/accounts/{account_id}/rules/lists/{existing_list['id']}/items"
        response = requests.put(url, headers=get_headers(), json=items)
    else:
        print(f"[{datetime.now()}] Creating new list '{LIST_NAME}'...")
        url = f"{CF_API_BASE}/accounts/{account_id}/rules/lists"
        payload = {
            "name": LIST_NAME,
            "kind": "asn",
            "description": "Auto-managed bad ASN list",
            "items": items
        }
        response = requests.post(url, headers=get_headers(), json=payload)
        
    if response.status_code == 200 and response.json().get("success"):
        print(f"[{datetime.now()}] Cloudflare List updated successfully.")
        return existing_list["id"] if existing_list else response.json()["result"]["id"]
    else:
        print(f"[{datetime.now()}] Error updating Cloudflare List: {response.text}")
        return None

def update_waf_rule(list_id):
    """Ensures the WAF rule exists and blocks the list."""
    # Get entry point
    url = f"{CF_API_BASE}/zones/{ZONE_ID}/rulesets/phases/http_request_firewall_custom/entrypoint"
    response = requests.get(url, headers=get_headers())
    
    ruleset_id = None
    existing_rule_id = None
    
    if response.status_code == 200 and response.json().get("success"):
        ruleset_id = response.json()["result"]["id"]
        if "rules" in response.json()["result"]:
            for rule in response.json()["result"]["rules"]:
                if rule.get("description") == RULE_DESCRIPTION:
                    existing_rule_id = rule["id"]
                    break
    
    expression = f"ip.asn in ${LIST_NAME}"
    action = "managed_challenge" # or "block"
    
    rule_payload = {
        "action": action,
        "expression": expression,
        "description": RULE_DESCRIPTION,
        "enabled": True
    }
    
    if existing_rule_id:
        print(f"[{datetime.now()}] Verifying WAF rule...")
        # We could update it just to be sure, or skip if we assume it's fine. 
        # Let's update it to ensure it points to the correct list name/expression.
        update_url = f"{CF_API_BASE}/zones/{ZONE_ID}/rulesets/{ruleset_id}/rules/{existing_rule_id}"
        requests.patch(update_url, headers=get_headers(), json=rule_payload)
    else:
        print(f"[{datetime.now()}] Creating WAF rule...")
        if ruleset_id:
            create_url = f"{CF_API_BASE}/zones/{ZONE_ID}/rulesets/{ruleset_id}/rules"
            requests.post(create_url, headers=get_headers(), json=rule_payload)
        else:
            # Create ruleset
            create_ruleset_url = f"{CF_API_BASE}/zones/{ZONE_ID}/rulesets"
            payload = {
                "name": "default",
                "kind": "zone",
                "phase": "http_request_firewall_custom",
                "rules": [rule_payload]
            }
            requests.post(create_ruleset_url, headers=get_headers(), json=payload)
            
    print(f"[{datetime.now()}] WAF Rule checked/updated.")

def job():
    print(f"\n[{datetime.now()}] Starting update job...")
    
    # 1. Fetch New Data
    new_asns = fetch_asns()
    if new_asns is None:
        return # Retry next time
        
    # 2. Load Old Data
    old_asns = load_state()
    
    # 3. Compare
    added = new_asns - old_asns
    removed = old_asns - new_asns
    
    if not added and not removed and old_asns:
        print(f"[{datetime.now()}] No changes detected in ASN list.")
        # We can skip API calls if nothing changed, OR force update to be safe.
        # Let's skip to save API calls, but maybe run once if state file was empty (first run).
    else:
        print(f"[{datetime.now()}] Changes detected: +{len(added)} added, -{len(removed)} removed.")
    
    # Always update Cloudflare on first run or if changes detected
    # Or if we want to enforce consistency.
    # Let's update if there are changes OR if local state was empty (first run)
    if added or removed or not old_asns:
        account_id = get_account_id()
        list_id = update_cloudflare_list(account_id, new_asns)
        if list_id:
            update_waf_rule(list_id)
            save_state(new_asns)

def main():
    print("Cloudflare ASN Auto-Updater Started")
    print(f"Interval: {CHECK_INTERVAL_SECONDS} seconds ({CHECK_INTERVAL_SECONDS/86400} days)")
    
    if not ZONE_ID or not API_TOKEN:
        print("WARNING: ZONE_ID or API_TOKEN not set. Script will fail to update Cloudflare.")
        print("Please edit the script or set environment variables.")
    
    while True:
        job()
        print(f"[{datetime.now()}] Sleeping for {CHECK_INTERVAL_SECONDS} seconds...")
        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
