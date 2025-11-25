# Cloudflare ASN Rules Updater

This project helps you block malicious traffic from specific Autonomous Systems (ASNs) using Cloudflare's modern **ASN Lists** and **WAF Custom Rules**.

This is a modern replacement for the old IP Access Rules method, offering better performance and management.

## Features
- **Modern API**: Uses Cloudflare's ASN Lists and WAF Custom Rules.
- **Bulk Management**: Manages hundreds of ASNs efficiently.
- **Cross-Platform**: Scripts available for Python, Bash (Linux/macOS), and Windows Batch/PowerShell.

## Prerequisites
- **Cloudflare Account**: You need a Cloudflare account and a Zone ID.
- **API Token**: Create an API Token with the following permissions:
    - `Zone` > `Zone` > `Read`
    - `Zone` > `Firewall Services` > `Edit`
    - `Account` > `Account Filter Lists` > `Edit`

## Usage

### Option 1: Python (Recommended)
Requires Python 3.x installed.

1.  Open a terminal.
2.  Run the script:
    ```bash
    python update_asn_rules.py
    ```
3.  Follow the prompts to enter your Zone ID and API Token.

### Option 2: Windows Batch
No Python required. Uses PowerShell built into Windows.

1.  Double-click `update_asn_rules.bat`.
2.  Follow the prompts.

### Option 3: Bash (Linux/macOS)
Requires `curl` and `jq`.

1.  Make the script executable:
    ```bash
    chmod +x update_asn_rules.sh
    ```
2.  Run the script:
    ```bash
    ./update_asn_rules.sh
    ```

## How it works
1.  Reads the list of ASNs from the `ASN List` file.
2.  Creates or updates a Cloudflare **ASN List** named `managed_bad_asns` in your account.
3.  Creates or updates a **WAF Custom Rule** named `Block Bad ASNs` in your zone to block/challenge traffic from these ASNs.

## Updating the ASN List
To fetch the latest list of bad ASNs from the source (brianhama/bad-asn-list), run:
```bash
python update_local_list.py
```
This will update the `ASN List` file locally. Then run one of the update scripts above to push the changes to Cloudflare.

## Source
Original ASN list from [FireHOL](https://iplists.firehol.org).
Current source: [brianhama/bad-asn-list](https://github.com/brianhama/bad-asn-list).
