# 🛡 Cloudflare ASN Rules Manager

**Block malicious Autonomous Systems (ASNs) on Cloudflare — interactive, menu-driven, one Python file.**

A single tool that fetches the latest bad-ASN list, syncs it into a Cloudflare Account List, and wires it into a WAF Custom Rule. Includes a clean `Remove All` action to undo everything.

---

## ⚡ Quick start

```bash
pip install -r requirements.txt
python cf_asn.py
```

That's it — the menu takes over.

---

## 🖥 What it looks like

```text
╔════════════════════════════════════════════════════════╗
║ 🛡  Cloudflare ASN Rules Manager                       ║
║ Protect your infrastructure by blocking malicious ASNs ║
╚════════════════════════════════════════════════════════╝

┌───────────────────────── Status ──────────────────────────┐
│   Zone ID        abc12345…                                │
│   API Token      set ✓                                    │
│   WAF action     managed_challenge                        │
│   Local list     1,247 ASNs                               │
│   Last sync      1,247 ASNs                               │
└───────────────────────────────────────────────────────────┘

                    Actions
┌─────┬────────────────────────────────────────┐
│  #  │ Description                            │
├─────┼────────────────────────────────────────┤
│  1  │ Download latest ASN list (from source) │
│  2  │ Push local ASN list → Cloudflare       │
│  3  │ Full sync (download + push)            │
│  4  │ Remove all (WAF rule + ASN list)       │
│  5  │ Show remote Cloudflare status          │
│  6  │ Auto-update mode (scheduled loop)      │
│  9  │ Settings / credentials                 │
│  0  │ Exit                                   │
└─────┴────────────────────────────────────────┘

Select [1/2/3/4/5/6/9/0] (3):
```

---

## 📋 Prerequisites

1. **Cloudflare Zone ID** for the domain you want to protect.
2. **API Token** — [create here](https://dash.cloudflare.com/profile/api-tokens) with:
   - `Zone` → `Zone` → **Read**
   - `Zone` → `Zone WAF` → **Edit**
   - `Account` → `Account Filter Lists` → **Edit**
3. Python **3.10+**.

---

## 🎛 Menu actions

| #   | Action          | What it does                                                                                                                                                                                            |
| --- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Download**    | Fetches the latest bad-ASN list from [brianhama/bad-asn-list](https://github.com/brianhama/bad-asn-list) into the local `ASN List` file. Shows a diff versus your previous copy.                        |
| 2   | **Push**        | Uploads the local `ASN List` to Cloudflare. Creates the account list `managed_bad_asns` if missing, otherwise replaces all items atomically. Ensures the WAF Custom Rule exists and is enabled.         |
| 3   | **Full sync**   | `Download` + `Push` in one step. Default for most users.                                                                                                                                                |
| 4   | **Remove all**  | Destructive: deletes the WAF rule first (Cloudflare rejects deleting a referenced list), then deletes the ASN list. Optionally wipes local `ASN List` and `asn_state.json` too. Always asks to confirm. |
| 5   | **Show remote** | Read-only status of the list + rule in your Cloudflare account.                                                                                                                                         |
| 6   | **Auto-update** | Runs `download → push` on a schedule (default 30 days) in the foreground. For unattended servers, cron/systemd is more reliable than keeping this process alive.                                        |
| 9   | **Settings**    | Change the WAF action (`block`, `managed_challenge`, `js_challenge`, `challenge`, `log`), update zone ID / API token. Saves to `.cf_asn_config.json` — **token is never written to disk.**              |

---

## 🔐 Credentials

The tool looks for credentials in this order:

1. **Environment variables** — `CF_ZONE_ID`, `CF_API_TOKEN`, `CF_ACTION`
2. **Stored config** — `.cf_asn_config.json` (zone ID + action only; chmod 600 on POSIX)
3. **Interactive prompt** — Zone ID via plain prompt, token via `getpass` (hidden)

For unattended use:

```bash
export CF_ZONE_ID=your_zone_id
export CF_API_TOKEN=your_api_token
python cf_asn.py
```

---

## ⚙ How it works

1. **Source** — pulls bad ASNs from [brianhama/bad-asn-list](https://github.com/brianhama/bad-asn-list).
2. **Account List** — creates/updates `managed_bad_asns` under your Cloudflare account (Configurations → Lists). The list is populated via a two-step create + `PUT /items` so large payloads (thousands of ASNs) work reliably.
3. **WAF Custom Rule** — single rule with expression `ip.asn in $managed_bad_asns`, action configurable, described as `Block traffic from bad ASNs defined in the managed list` (used as the idempotency key).
4. **State** — `asn_state.json` records the last-synced ASNs so auto-mode can detect no-op cycles and skip API calls.

---

## 🗂 Files in this repo

| File                  | Purpose                                                           |
| --------------------- | ----------------------------------------------------------------- |
| `cf_asn.py`           | **The tool.** Everything lives here.                              |
| `requirements.txt`    | `requests`, `rich`.                                               |
| `ASN List`            | Local cache of current ASN numbers (one per line).                |
| `.cf_asn_config.json` | Auto-generated, gitignored; stores zone ID + action (no secrets). |
| `asn_state.json`      | Auto-generated, gitignored; sync state.                           |

---

## 📝 License

Open-source. Modify and distribute freely.
