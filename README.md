# 🛡️ Cloudflare ASN Rules Manager

**Protect your web infrastructure by automatically blocking malicious Autonomous Systems (ASNs).**

This repository provides a suite of tools to manage Cloudflare ASN Lists and WAF Custom Rules. Whether you need a simple one-time update or a fully automated background scheduler, we have you covered.

---

## 🚀 Features

- **Modern Cloudflare API**: Utilizes the latest ASN Lists and WAF Custom Rules for optimal performance.
- **Bulk Management**: Efficiently handles hundreds of ASNs without hitting rule limits.
- **Automated Protection**: "Set and forget" scheduler script to keep your rules up-to-date.
- **Cross-Platform**: Scripts for Python, Windows Batch, and Bash (Linux/macOS).

---

## 🛠️ Tools Overview

| Tool | Description | Best For |
| :--- | :--- | :--- |
| **`auto_update_asn.py`** | **The All-in-One Solution.** Fetches new ASNs, compares with local state, and updates Cloudflare automatically every 30 days. | **Servers / Always-on PCs** |
| **`update_asn_rules.py`** | Manually pushes the current local `ASN List` file to Cloudflare. | **Manual Updates** |
| **`update_local_list.py`** | Downloads the latest bad ASN list to your local machine. | **Manual Updates** |
| **`update_asn_rules.bat`** | Windows Batch wrapper for the update process. | **Windows Users (No Python)** |
| **`update_asn_rules.sh`** | Bash script for Linux/macOS. | **Linux/Mac Users** |

---

## 📋 Prerequisites

1.  **Cloudflare Account**: You need a Zone ID for the domain you want to protect.
2.  **API Token**: Create a token at [Cloudflare Profile > API Tokens](https://dash.cloudflare.com/profile/api-tokens) with these permissions:
    - `Zone` > `Zone` > `Read`
    - `Zone` > `Firewall Services` > `Edit`
    - `Account` > `Account Filter Lists` > `Edit`

---

## 📖 Usage Guide

### 🤖 1. Auto-Scheduler (Recommended)

The `auto_update_asn.py` script is designed to run continuously. It handles everything: fetching, diffing, and updating.

1.  **Configure**: Open `auto_update_asn.py` and set your credentials:
    ```python
    ZONE_ID = "your_zone_id"
    API_TOKEN = "your_api_token"
    ```
2.  **Run**:
    ```bash
    python auto_update_asn.py
    ```
3.  **Result**: The script will run immediately and then sleep for 30 days. It creates a `managed_bad_asns` list and a `Block Bad ASNs` WAF rule in your Cloudflare account.

### 🖐️ 2. Manual Update (Python)

If you prefer to update manually:

1.  **Fetch latest list**:
    ```bash
    python update_local_list.py
    ```
2.  **Push to Cloudflare**:
    ```bash
    python update_asn_rules.py
    ```
    *Follow the interactive prompts to enter your Zone ID and API Token.*

### 🪟 3. Windows Batch

1.  Double-click `update_asn_rules.bat`.
2.  Follow the on-screen prompts.

### 🐧 4. Linux / macOS Bash

1.  Make executable: `chmod +x update_asn_rules.sh`
2.  Run: `./update_asn_rules.sh`

---

## ⚙️ How It Works

1.  **Source**: Fetches bad ASNs from [brianhama/bad-asn-list](https://github.com/brianhama/bad-asn-list).
2.  **List Management**: Creates a centralized **ASN List** in your Cloudflare Account (under Configurations > Lists).
3.  **WAF Rule**: Creates a single **WAF Custom Rule** that references this list (`ip.asn in $managed_bad_asns`) and performs a `Managed Challenge` (or Block).

---

## 📝 License

This project is open-source. Feel free to modify and distribute.
