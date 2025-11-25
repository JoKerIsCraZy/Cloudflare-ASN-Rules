import requests
import csv
import io
import os

# Source URL for the ASN list
URL = "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"
OUTPUT_FILE = "ASN List"

def main():
    print(f"Fetching latest ASN list from: {URL}")
    try:
        response = requests.get(URL)
        response.raise_for_status()
        
        content = response.content.decode('utf-8')
        csv_reader = csv.reader(io.StringIO(content))
        
        asns = []
        # Skip header if present
        next(csv_reader, None) 
        
        for row in csv_reader:
            if row:
                # The first column is the ASN
                asn = row[0].strip()
                
                # Basic validation/cleaning
                if asn.isdigit():
                    asns.append(asn)
                elif asn.upper().startswith("AS") and asn[2:].isdigit():
                    asns.append(asn[2:])
        
        # Remove duplicates
        asns = sorted(list(set(asns)), key=lambda x: int(x))
        
        # Write to file
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for asn in asns:
                f.write(f"{asn}\n")
                
        print(f"Success! Updated '{OUTPUT_FILE}' with {len(asns)} unique ASNs.")
        print("You can now run 'update_asn_rules.py' to push these changes to Cloudflare.")
        
    except Exception as e:
        print(f"Error updating ASN list: {e}")

if __name__ == "__main__":
    main()
