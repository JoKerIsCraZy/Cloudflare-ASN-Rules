#!/usr/bin/env python3
"""Cloudflare ASN Rules Manager — interactive CLI.

One unified tool that replaces update_asn_rules.py, auto_update_asn.py and
update_local_list.py with a menu-driven interface.
"""
from __future__ import annotations

import csv
import io
import json
import os
import stat
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import Any, Callable, Optional

import requests
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

# Ensure unicode output works on Windows terminals with cp1252 default.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass

# ─────────────────────── Constants ───────────────────────
CF_API_BASE = "https://api.cloudflare.com/client/v4"
ASN_SOURCE_URL = (
    "https://raw.githubusercontent.com/brianhama/bad-asn-list/master/bad-asn-list.csv"
)
ASN_LIST_FILE = Path("ASN List")
STATE_FILE = Path("asn_state.json")
CONFIG_FILE = Path(".cf_asn_config.json")

LIST_NAME = "managed_bad_asns"
LIST_DESCRIPTION = "Auto-managed list of bad/malicious ASNs"
RULE_DESCRIPTION = "Block traffic from bad ASNs defined in the managed list"
DEFAULT_ACTION = "managed_challenge"
VALID_ACTIONS = ("block", "managed_challenge", "js_challenge", "challenge", "log")
REQUEST_TIMEOUT = 30

console = Console()


# ─────────────────────── Config ───────────────────────
@dataclass
class Config:
    zone_id: str = ""
    api_token: str = ""
    action: str = DEFAULT_ACTION

    @classmethod
    def load(cls) -> "Config":
        cfg = cls(
            zone_id=os.getenv("CF_ZONE_ID", ""),
            api_token=os.getenv("CF_API_TOKEN", ""),
            action=os.getenv("CF_ACTION", DEFAULT_ACTION),
        )
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                if not cfg.zone_id and data.get("zone_id"):
                    cfg.zone_id = data["zone_id"]
                stored = data.get("action")
                if stored in VALID_ACTIONS:
                    cfg.action = stored
            except (json.JSONDecodeError, OSError) as exc:
                console.print(
                    f"[yellow]Warning: could not read {CONFIG_FILE}: {exc}[/]"
                )
        if cfg.action not in VALID_ACTIONS:
            cfg.action = DEFAULT_ACTION
        return cfg

    def save(self) -> None:
        """Persist non-secret config only (never the token)."""
        CONFIG_FILE.write_text(
            json.dumps({"zone_id": self.zone_id, "action": self.action}, indent=2),
            encoding="utf-8",
        )
        # Restrict to owner-only read/write where supported (POSIX).
        try:
            CONFIG_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except (NotImplementedError, OSError):
            pass


# ─────────────────────── Cloudflare client ───────────────────────
class CloudflareError(Exception):
    pass


@dataclass
class CloudflareClient:
    zone_id: str
    api_token: str
    _account_id: Optional[str] = None

    @property
    def headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, url: str, **kwargs: Any) -> dict:
        try:
            resp = requests.request(
                method, url, headers=self.headers, timeout=REQUEST_TIMEOUT, **kwargs
            )
        except requests.RequestException as e:
            raise CloudflareError(f"Network error: {e}") from e

        # DELETE may return 200 with empty body — treat as success
        if not resp.content:
            if resp.ok:
                return {"success": True, "result": None}
            raise CloudflareError(f"HTTP {resp.status_code} with empty body")

        try:
            data = resp.json()
        except ValueError:
            raise CloudflareError(
                f"Non-JSON response ({resp.status_code}): {resp.text[:200]}"
            )

        if not data.get("success"):
            errors = data.get("errors") or []
            msg = "; ".join(
                f"{e.get('code')}: {e.get('message')}" for e in errors
            ) or resp.text[:300]
            raise CloudflareError(f"API error ({resp.status_code}): {msg}")
        return data

    @property
    def account_id(self) -> str:
        if self._account_id:
            return self._account_id
        data = self._request("GET", f"{CF_API_BASE}/zones/{self.zone_id}")
        self._account_id = data["result"]["account"]["id"]
        return self._account_id

    def find_list(self, name: str = LIST_NAME) -> Optional[dict]:
        data = self._request(
            "GET", f"{CF_API_BASE}/accounts/{self.account_id}/rules/lists"
        )
        for item in data.get("result") or []:
            if item.get("name") == name and item.get("kind") == "asn":
                return item
        return None

    def create_list(self, asns: list[int], name: str = LIST_NAME) -> dict:
        # Two-step create: metadata first, then items via PUT.
        # Inline "items" on create is unreliable for large payloads.
        data = self._request(
            "POST",
            f"{CF_API_BASE}/accounts/{self.account_id}/rules/lists",
            json={
                "name": name,
                "kind": "asn",
                "description": LIST_DESCRIPTION,
            },
        )
        result = data["result"]
        if asns:
            self.replace_list_items(result["id"], asns)
        return result

    def replace_list_items(self, list_id: str, asns: list[int]) -> None:
        items = [{"value": asn} for asn in sorted(asns)]
        self._request(
            "PUT",
            f"{CF_API_BASE}/accounts/{self.account_id}/rules/lists/{list_id}/items",
            json=items,
        )

    def delete_list(self, list_id: str) -> None:
        self._request(
            "DELETE",
            f"{CF_API_BASE}/accounts/{self.account_id}/rules/lists/{list_id}",
        )

    def _custom_ruleset(self) -> Optional[dict]:
        try:
            data = self._request(
                "GET",
                f"{CF_API_BASE}/zones/{self.zone_id}/rulesets/phases/"
                "http_request_firewall_custom/entrypoint",
            )
            return data["result"]
        except CloudflareError:
            return None

    def find_rule(self) -> tuple[Optional[str], Optional[str]]:
        ruleset = self._custom_ruleset()
        if not ruleset:
            return None, None
        for rule in ruleset.get("rules") or []:
            if rule.get("description") == RULE_DESCRIPTION:
                return ruleset["id"], rule["id"]
        return ruleset["id"], None

    def upsert_rule(self, action: str = DEFAULT_ACTION) -> None:
        ruleset_id, rule_id = self.find_rule()
        payload = {
            "action": action,
            "expression": f"ip.asn in ${LIST_NAME}",
            "description": RULE_DESCRIPTION,
            "enabled": True,
        }
        if ruleset_id and rule_id:
            self._request(
                "PATCH",
                f"{CF_API_BASE}/zones/{self.zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
                json=payload,
            )
        elif ruleset_id:
            self._request(
                "POST",
                f"{CF_API_BASE}/zones/{self.zone_id}/rulesets/{ruleset_id}/rules",
                json=payload,
            )
        else:
            self._request(
                "POST",
                f"{CF_API_BASE}/zones/{self.zone_id}/rulesets",
                json={
                    "name": "default",
                    "kind": "zone",
                    "phase": "http_request_firewall_custom",
                    "rules": [payload],
                },
            )

    def delete_rule(self) -> bool:
        ruleset_id, rule_id = self.find_rule()
        if not ruleset_id or not rule_id:
            return False
        self._request(
            "DELETE",
            f"{CF_API_BASE}/zones/{self.zone_id}/rulesets/{ruleset_id}/rules/{rule_id}",
        )
        return True


# ─────────────────────── ASN I/O ───────────────────────
def _parse_asn(raw: str) -> Optional[int]:
    raw = raw.strip()
    if not raw:
        return None
    if raw.upper().startswith("AS"):
        raw = raw[2:]
    # isdecimal() restricts to ASCII digits; isdigit() would accept Unicode
    # digit code points that int() still rejects or interprets unexpectedly.
    return int(raw) if raw.isdecimal() else None


def fetch_asns_from_source() -> set[int]:
    resp = requests.get(ASN_SOURCE_URL, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    reader = csv.reader(io.StringIO(resp.text))
    next(reader, None)  # skip header
    asns: set[int] = set()
    for row in reader:
        if row and (asn := _parse_asn(row[0])) is not None:
            asns.add(asn)
    return asns


def read_local_asns() -> set[int]:
    if not ASN_LIST_FILE.exists():
        return set()
    asns: set[int] = set()
    for line in ASN_LIST_FILE.read_text(encoding="utf-8").splitlines():
        if (asn := _parse_asn(line)) is not None:
            asns.add(asn)
    return asns


def write_local_asns(asns: set[int]) -> None:
    sorted_asns = sorted(asns)
    ASN_LIST_FILE.write_text(
        "\n".join(str(a) for a in sorted_asns) + "\n", encoding="utf-8"
    )


def load_state() -> set[int]:
    if not STATE_FILE.exists():
        return set()
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return set(data.get("asns", []))
    except (json.JSONDecodeError, OSError):
        return set()


def save_state(asns: set[int]) -> None:
    STATE_FILE.write_text(
        json.dumps({"last_updated": datetime.now().isoformat(), "asns": sorted(asns)}),
        encoding="utf-8",
    )


# ─────────────────────── UI ───────────────────────
def banner() -> None:
    console.print()
    console.print(
        Panel.fit(
            "[bold cyan]🛡  Cloudflare ASN Rules Manager[/]\n"
            "[dim]Protect your infrastructure by blocking malicious ASNs[/]",
            border_style="cyan",
            box=box.DOUBLE,
        )
    )


def status_panel(config: Config) -> None:
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="dim", width=14)
    table.add_column()

    zone = f"[green]{config.zone_id[:8]}…[/]" if config.zone_id else "[red]— not set —[/]"
    token = "[green]set ✓[/]" if config.api_token else "[red]— not set —[/]"
    table.add_row("Zone ID", zone)
    table.add_row("API Token", token)
    table.add_row("WAF action", f"[yellow]{config.action}[/]")

    local = read_local_asns()
    table.add_row(
        "Local list",
        f"[green]{len(local):,} ASNs[/]" if local else "[dim]empty / missing[/]",
    )
    state = load_state()
    if state:
        table.add_row("Last sync", f"[dim]{len(state):,} ASNs[/]")

    console.print(Panel(table, title="[bold]Status[/]", border_style="blue"))


def ensure_credentials(config: Config) -> bool:
    if not config.zone_id:
        config.zone_id = Prompt.ask("[yellow]Enter Cloudflare Zone ID[/]").strip()
    if not config.api_token:
        console.print(
            "[dim]Token needs: Zone:Read, Zone WAF:Edit, Account Filter Lists:Edit[/]"
        )
        config.api_token = getpass("Enter API Token (hidden): ").strip()
    if not config.zone_id or not config.api_token:
        console.print("[red]✗ Credentials required.[/]")
        return False
    return True


# ─────────────────────── Actions ───────────────────────
def action_download(config: Config) -> None:
    console.print("\n[bold]→ Downloading latest ASN list from source…[/]")
    try:
        with console.status("[cyan]Fetching…[/]"):
            asns = fetch_asns_from_source()
    except requests.RequestException as e:
        console.print(f"[red]✗ Download failed: {e}[/]")
        return
    if not asns:
        console.print("[red]✗ No ASNs parsed from source.[/]")
        return
    existing = read_local_asns()
    added = asns - existing
    removed = existing - asns
    write_local_asns(asns)
    console.print(f"[green]✓ Saved {len(asns):,} ASNs to '{ASN_LIST_FILE}'[/]")
    if existing:
        console.print(
            f"  [dim]Changes:[/] [green]+{len(added)}[/] [red]-{len(removed)}[/]"
        )


def action_push(config: Config) -> None:
    if not ensure_credentials(config):
        return
    asns = read_local_asns()
    if not asns:
        console.print("[red]✗ Local ASN list is empty. Download first.[/]")
        return
    console.print(f"\n[bold]→ Pushing {len(asns):,} ASNs to Cloudflare…[/]")
    try:
        client = CloudflareClient(config.zone_id, config.api_token)
        with console.status("[cyan]Syncing list…[/]"):
            existing = client.find_list()
            if existing:
                client.replace_list_items(existing["id"], sorted(asns))
                console.print(
                    f"[green]✓ Updated list '{LIST_NAME}' "
                    f"({len(asns):,} items)[/]"
                )
            else:
                client.create_list(sorted(asns))
                console.print(
                    f"[green]✓ Created list '{LIST_NAME}' "
                    f"({len(asns):,} items)[/]"
                )
        with console.status(f"[cyan]Configuring WAF rule ({config.action})…[/]"):
            client.upsert_rule(action=config.action)
        console.print(
            f"[green]✓ WAF rule active — action: [bold]{config.action}[/][/]"
        )
        save_state(asns)
    except CloudflareError as e:
        console.print(f"[red]✗ {e}[/]")


def action_sync(config: Config) -> None:
    action_download(config)
    if ASN_LIST_FILE.exists():
        action_push(config)


def action_remove_all(config: Config) -> None:
    if not ensure_credentials(config):
        return
    console.print()
    console.print(
        Panel(
            "[bold red]⚠  DESTRUCTIVE OPERATION[/]\n\n"
            "This will permanently:\n"
            f"  • Delete WAF rule '[yellow]{RULE_DESCRIPTION}[/]'\n"
            f"  • Delete ASN list '[yellow]{LIST_NAME}[/]'\n"
            "  • Optionally remove local files",
            border_style="red",
        )
    )
    if not Confirm.ask("[bold red]Proceed with deletion?[/]", default=False):
        console.print("[yellow]Cancelled.[/]")
        return

    try:
        client = CloudflareClient(config.zone_id, config.api_token)
        # Rule MUST be deleted before list — CF rejects deletion of referenced lists
        with console.status("[cyan]Removing WAF rule…[/]"):
            removed_rule = client.delete_rule()
        if removed_rule:
            console.print("[green]✓ WAF rule deleted[/]")
        else:
            console.print("[dim]• No matching WAF rule found[/]")

        with console.status("[cyan]Removing ASN list…[/]"):
            existing_list = client.find_list()
            if existing_list:
                client.delete_list(existing_list["id"])
                console.print(f"[green]✓ ASN list '{LIST_NAME}' deleted[/]")
            else:
                console.print("[dim]• No matching ASN list found[/]")
    except CloudflareError as e:
        console.print(f"[red]✗ {e}[/]")
        return

    if Confirm.ask(
        "Also delete local files (ASN List, asn_state.json)?", default=False
    ):
        for f in (ASN_LIST_FILE, STATE_FILE):
            if f.exists():
                f.unlink()
                console.print(f"[green]✓ Deleted [dim]{f}[/][/]")


def action_show_remote(config: Config) -> None:
    if not ensure_credentials(config):
        return
    try:
        client = CloudflareClient(config.zone_id, config.api_token)
        with console.status("[cyan]Fetching remote status…[/]"):
            existing_list = client.find_list()
            ruleset_id, rule_id = client.find_rule()
    except CloudflareError as e:
        console.print(f"[red]✗ {e}[/]")
        return

    table = Table(title="[bold]Cloudflare State[/]", box=box.SIMPLE_HEAVY)
    table.add_column("Resource", style="cyan")
    table.add_column("Status")
    if existing_list:
        count = existing_list.get("num_items", "?")
        table.add_row(
            "ASN List",
            f"[green]found[/]  id=[dim]{existing_list['id']}[/]  items=[bold]{count}[/]",
        )
    else:
        table.add_row("ASN List", "[red]not found[/]")
    if rule_id:
        table.add_row(
            "WAF Rule", f"[green]found[/]  id=[dim]{rule_id}[/]"
        )
    else:
        table.add_row("WAF Rule", "[red]not found[/]")
    console.print(table)


def action_settings(config: Config) -> None:
    console.print("\n[bold]Settings[/]")
    console.print(f"[dim]Current action: {config.action}[/]")
    new_action = Prompt.ask(
        "WAF action", default=config.action, choices=list(VALID_ACTIONS)
    )
    config.action = new_action

    if Confirm.ask("Update Zone ID?", default=False):
        config.zone_id = Prompt.ask("Zone ID", default=config.zone_id).strip()
    if Confirm.ask("Update API Token?", default=False):
        config.api_token = getpass("New API Token (hidden): ").strip()

    config.save()
    console.print(
        f"[green]✓ Saved to {CONFIG_FILE}[/] "
        "[dim](token is never stored on disk)[/]"
    )


def _run_sync_job(config: Config) -> None:
    """Single iteration of the auto-update job."""
    new_asns = fetch_asns_from_source()
    prev = load_state()
    added = new_asns - prev
    removed = prev - new_asns
    if not added and not removed and prev:
        console.print("[dim]  No changes detected — skipping push.[/]")
        return
    write_local_asns(new_asns)
    client = CloudflareClient(config.zone_id, config.api_token)
    existing = client.find_list()
    if existing:
        client.replace_list_items(existing["id"], sorted(new_asns))
    else:
        client.create_list(sorted(new_asns))
    client.upsert_rule(action=config.action)
    save_state(new_asns)
    console.print(
        f"[green]  ✓ Synced — [/]"
        f"[green]+{len(added)}[/] [red]-{len(removed)}[/]"
    )


def _interruptible_sleep(total_seconds: int, tick: int = 5) -> None:
    """Sleep in short chunks so Ctrl+C is responsive on all platforms."""
    remaining = total_seconds
    while remaining > 0:
        time.sleep(min(tick, remaining))
        remaining -= tick


def action_auto_run(config: Config) -> None:
    if not ensure_credentials(config):
        return
    days = IntPrompt.ask("Check interval in days", default=30)
    interval = max(1, days) * 86400
    console.print(
        f"\n[bold]→ Auto-updater running every {days} day(s). "
        "Press Ctrl+C to stop.[/]\n"
        "[dim]Note: for unattended long intervals, a cron/systemd timer is "
        "more reliable than keeping this process alive.[/]"
    )
    try:
        while True:
            console.print(
                f"\n[cyan][{datetime.now():%Y-%m-%d %H:%M:%S}][/] Running job…"
            )
            try:
                _run_sync_job(config)
            except (CloudflareError, requests.RequestException) as e:
                console.print(f"[red]  ✗ Job failed: {e}[/]")
            next_run = datetime.fromtimestamp(time.time() + interval)
            console.print(f"[dim]  Next run: {next_run:%Y-%m-%d %H:%M}[/]")
            _interruptible_sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Auto-updater stopped.[/]")


# ─────────────────────── Menu ───────────────────────
MenuEntry = tuple[str, str, Optional[Callable[[Config], None]]]

MENU: list[MenuEntry] = [
    ("1", "Download latest ASN list (from source)", action_download),
    ("2", "Push local ASN list → Cloudflare", action_push),
    ("3", "Full sync (download + push)", action_sync),
    ("4", "Remove all (WAF rule + ASN list)", action_remove_all),
    ("5", "Show remote Cloudflare status", action_show_remote),
    ("6", "Auto-update mode (scheduled loop)", action_auto_run),
    ("9", "Settings / credentials", action_settings),
    ("0", "Exit", None),
]


def menu_loop(config: Config) -> None:
    while True:
        console.print()
        status_panel(config)
        console.print()
        table = Table(title="[bold]Actions[/]", box=box.ROUNDED, title_style="cyan")
        table.add_column("#", style="bold cyan", justify="center", width=3)
        table.add_column("Description")
        for key, desc, _ in MENU:
            table.add_row(key, desc)
        console.print(table)

        choice = Prompt.ask(
            "\n[bold]Select[/]",
            choices=[k for k, _, _ in MENU],
            default="3",
        )
        if choice == "0":
            console.print("[cyan]Bye.[/]")
            return
        for key, _, handler in MENU:
            if key == choice and handler is not None:
                try:
                    handler(config)
                except KeyboardInterrupt:
                    console.print("\n[yellow]Interrupted.[/]")
                break


def main() -> None:
    banner()
    config = Config.load()
    try:
        menu_loop(config)
    except KeyboardInterrupt:
        console.print("\n[cyan]Bye.[/]")
        sys.exit(0)


if __name__ == "__main__":
    main()
