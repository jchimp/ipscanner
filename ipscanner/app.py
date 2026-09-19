"""Textual TUI for ipscanner."""

from __future__ import annotations

import argparse
import asyncio
import time
from ipaddress import IPv4Address
from pathlib import Path

import pyperclip
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import ModalScreen
from textual.widgets import (
    Button, Checkbox, DataTable, Footer, Header, Input, Label, RadioButton, RadioSet, Select,
    Static,
)

from ipscanner import __version__, export
from ipscanner.netinfo import Subnet, local_subnets, parse_range
from ipscanner.scanner import (
    STATUS_ARP, STATUS_OFFLINE, STATUS_ONLINE, STATUS_PENDING, Host, scan,
)

LARGE_RANGE = 4096
CUSTOM = "custom"

# Fixed widths for bounded columns so they never shift as results arrive; None = auto.
COLUMNS = (
    ("ip", "IP", 15),
    ("status", "Status", 7),
    ("latency", "Latency", 8),
    ("fqdn", "FQDN", None),
    ("mac", "MAC", 17),
    ("vendor", "Vendor", None),
)
COLUMN_KEYS = tuple(c[0] for c in COLUMNS)
RELOAD_INTERVAL = 1.0  # min seconds between full table reloads while scanning

STATUS_LABEL = {
    STATUS_ONLINE: "[green]online[/]",
    STATUS_ARP: "[yellow]arp[/]",
    STATUS_OFFLINE: "[dim]offline[/]",
    STATUS_PENDING: "[dim]...[/]",
}


def _latency_text(h: Host) -> str:
    if h.latency_ms is None:
        return ""
    return "<1 ms" if h.latency_ms < 1 else f"{h.latency_ms:.0f} ms"


def _row_cells(h: Host) -> tuple[str, ...]:
    """Cell values for one table row, in COLUMNS order."""
    return (
        str(h.ip), STATUS_LABEL.get(h.status, h.status), _latency_text(h),
        h.fqdn or "", h.mac or "", h.vendor or "",
    )


def _sort_key(column: str):
    """Return a per-column sort key; None/missing values sort last."""
    if column == "ip":
        return lambda h: int(h.ip)
    if column == "latency":
        return lambda h: (h.latency_ms is None, h.latency_ms or 0)
    if column == "status":
        order = {STATUS_ONLINE: 0, STATUS_ARP: 1, STATUS_PENDING: 2, STATUS_OFFLINE: 3}
        return lambda h: order.get(h.status, 9)
    return lambda h: ((getattr(h, column) or "") == "", (getattr(h, column) or "").lower())


class ConfirmScreen(ModalScreen[bool]):
    """Yes/No modal."""

    BINDINGS = [Binding("escape", "dismiss(False)", "Cancel", show=False)]

    def __init__(self, message: str, yes_label: str = "Yes") -> None:
        super().__init__()
        self._message = message
        self._yes = yes_label

    def compose(self) -> ComposeResult:
        with Static(id="dialog"):
            yield Label(self._message)
            with Horizontal(id="buttons"):
                yield Button("Cancel", id="no")
                yield Button(self._yes, id="yes", variant="primary")

    @on(Button.Pressed)
    def _pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")


class ExportScreen(ModalScreen[tuple[str, Path] | None]):
    """Pick a format and a path."""

    BINDINGS = [Binding("escape", "dismiss(None)", "Cancel", show=False)]

    def __init__(self, scan_range: str, count: int) -> None:
        super().__init__()
        self._range = scan_range
        self._count = count
        self._fmt = "csv"
        self._overwrite_armed = False

    def compose(self) -> ComposeResult:
        with Static(id="dialog"):
            yield Label(f"Export {self._count} rows (current view)")
            with RadioSet(id="fmt"):
                yield RadioButton("CSV", value=True, id="csv")
                yield RadioButton("JSON", id="json")
                yield RadioButton("HTML", id="html")
            yield Input(export.default_filename(self._range, "csv"), id="path")
            with Horizontal(id="buttons"):
                yield Button("Cancel", id="cancel")
                yield Button("Save", id="save", variant="primary")

    @on(RadioSet.Changed)
    def _fmt_changed(self, event: RadioSet.Changed) -> None:
        new_fmt = event.pressed.id or "csv"
        path = self.query_one("#path", Input)
        # Only swap the extension when the user has not typed their own name.
        if path.value.startswith("ipscan_") and path.value.endswith(f".{self._fmt}"):
            path.value = str(Path(path.value).with_suffix(f".{new_fmt}"))
        self._fmt = new_fmt
        self._overwrite_armed = False

    @on(Input.Submitted, "#path")
    def _submit(self) -> None:
        self._save()

    @on(Button.Pressed, "#save")
    def _save(self) -> None:
        path = Path(self.query_one("#path", Input).value.strip()).expanduser()
        if not path.name:
            self.notify("Enter a file name", severity="warning")
            return
        if path.exists() and not self._overwrite_armed:
            self._overwrite_armed = True
            self.notify(f"{path.name} exists - press Save again to overwrite",
                        severity="warning")
            return
        self.dismiss((self._fmt, path))

    @on(Button.Pressed, "#cancel")
    def _cancel(self) -> None:
        self.dismiss(None)


class IPScannerApp(App[None]):
    """Scan an IP range and browse the results."""

    TITLE = f"ipscan {__version__}"
    CSS_PATH = "app.tcss"
    BINDINGS = [
        Binding("s", "scan", "Scan"),
        Binding("escape", "stop_or_table", "Stop", show=False),
        Binding("slash", "focus_search", "Search"),
        Binding("o", "toggle_offline", "Offline"),
        Binding("c", "copy('ip')", "Copy IP"),
        Binding("f", "copy('fqdn')", "Copy FQDN"),
        Binding("m", "copy('mac')", "Copy MAC"),
        Binding("e", "export", "Export"),
        Binding("r", "clear_filter", "Clear filter", show=False),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, initial_range: str | None = None) -> None:
        super().__init__()
        self._initial_range = initial_range
        self._subnets: list[Subnet] = []
        self._hosts: dict[IPv4Address, Host] = {}
        self._scan_range = ""
        self._stop = asyncio.Event()
        self._scanning = False
        self._started_at = 0.0
        self._elapsed = 0.0
        self._dirty = False
        self._sort_col = "ip"
        self._sort_reverse = False
        self._visible: list[Host] = []
        self._table_keys: list[str] = []  # row keys currently in the table, in order
        self._rendered: dict[str, tuple[str, ...]] = {}  # last cell values written per row
        self._last_reload = 0.0
        self._settled = False  # True once mount-time widget events have settled.

    # ---------- layout ----------

    def compose(self) -> ComposeResult:
        self._subnets = local_subnets()
        # Select inner width is SELECT_WIDTH - 7 (border, padding, arrow); keep labels inside it.
        options = [(f"{s.cidr} ({s.iface[:14]})", s.cidr) for s in self._subnets]
        options.append(("Custom range", CUSTOM))
        first = self._initial_range or (self._subnets[0].cidr if self._subnets else "")
        selected = first if any(s.cidr == first for s in self._subnets) else CUSTOM

        yield Header()
        with Horizontal(id="range-bar"):
            yield Select(options, value=selected, allow_blank=False, id="subnet")
            yield Input(first, placeholder="10.0.0.0/24  |  10.0.0.1-254  |  10.0.0.1-10.0.0.50",
                        id="range")
            yield Button("Scan", id="scan-btn", variant="primary")
        with Horizontal(id="filter-bar"):
            yield Input(placeholder="Filter: IP, FQDN, MAC, vendor, status", id="search")
            yield Checkbox("Show offline", value=True, id="show-offline")
            yield Checkbox("Resolve DNS", value=True, id="resolve-dns")
        yield DataTable(id="table", cursor_type="row", zebra_stripes=True)
        yield Static("Ready. Press Enter or [b]s[/b] to scan.", id="status")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for key, label, width in COLUMNS:
            table.add_column(label, key=key, width=width)
        self.set_interval(0.25, self._tick)

        def settle() -> None:
            self._settled = True
            table.focus()

        self.call_after_refresh(settle)

    # ---------- range selection ----------

    @on(Select.Changed, "#subnet")
    def _subnet_changed(self, event: Select.Changed) -> None:
        if event.value != CUSTOM:
            self.query_one("#range", Input).value = str(event.value)
        # Select fires Changed once during mount; do not steal focus from the table then.
        if self._settled:
            self.query_one("#range", Input).focus()

    @on(Input.Changed, "#range")
    def _range_typed(self, event: Input.Changed) -> None:
        select = self.query_one("#subnet", Select)
        match = next((s.cidr for s in self._subnets if s.cidr == event.value.strip()), CUSTOM)
        if select.value != match:
            select.value = match

    @on(Input.Submitted, "#range")
    @on(Button.Pressed, "#scan-btn")
    def _scan_requested(self) -> None:
        if self._scanning:
            self.action_stop()
        else:
            self.action_scan()

    # ---------- scanning ----------

    def action_scan(self) -> None:
        if self._scanning:
            self.notify("Scan already running (Esc to stop)", severity="warning")
            return
        text = self.query_one("#range", Input).value
        try:
            addresses = parse_range(text)
        except ValueError as exc:
            self.notify(f"Bad range: {exc}", severity="error")
            self.query_one("#range", Input).focus()
            return
        if len(addresses) > LARGE_RANGE:
            self.push_screen(
                ConfirmScreen(f"Scan {len(addresses)} addresses? This may take several minutes.",
                              "Scan"),
                callback=lambda ok: self._start(text, addresses) if ok else None,
            )
        else:
            self._start(text, addresses)

    def _start(self, text: str, addresses: list[IPv4Address]) -> None:
        self._scan_range = text.strip()
        self._hosts = {ip: Host(ip) for ip in addresses}
        self._stop = asyncio.Event()
        self._scanning = True
        self._started_at = time.monotonic()
        self._dirty = True
        self.query_one("#scan-btn", Button).label = "Stop"
        self.query_one(DataTable).focus()
        resolve = self.query_one("#resolve-dns", Checkbox).value
        self._run_scan(addresses, resolve)

    @work(exclusive=True)
    async def _run_scan(self, addresses: list[IPv4Address], resolve: bool) -> None:
        def on_update(host: Host) -> None:
            self._hosts[host.ip] = host
            self._dirty = True

        try:
            await scan(addresses, on_update, stop=self._stop, resolve_dns=resolve)
        finally:
            self._scanning = False
            self._elapsed = time.monotonic() - self._started_at
            self._dirty = True
            self.query_one("#scan-btn", Button).label = "Scan"

    def action_stop(self) -> None:
        if self._scanning:
            self._stop.set()
            self.notify("Stopping...")

    def action_stop_or_table(self) -> None:
        if self._scanning:
            self.action_stop()
        else:
            self.query_one(DataTable).focus()

    # ---------- table ----------

    def _tick(self) -> None:
        if self._dirty:
            self._dirty = False
            self._rebuild()
        elif self._scanning:
            self._update_status()

    def _filtered(self) -> list[Host]:
        needle = self.query_one("#search", Input).value.strip().lower()
        show_offline = self.query_one("#show-offline", Checkbox).value
        rows = []
        for h in self._hosts.values():
            if not show_offline and h.status in (STATUS_OFFLINE, STATUS_PENDING):
                continue
            if needle:
                hay = " ".join(filter(None, (str(h.ip), h.status, h.fqdn, h.mac, h.vendor)))
                if needle not in hay.lower():
                    continue
            rows.append(h)
        rows.sort(key=_sort_key(self._sort_col), reverse=self._sort_reverse)
        return rows

    def _cursor_key(self, table: DataTable) -> str | None:
        if not table.row_count:
            return None
        try:
            return str(table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value)
        except Exception:  # noqa: BLE001 - cursor can point past a shrunk table
            return None

    def _rebuild(self) -> None:
        table = self.query_one(DataTable)
        self._visible = self._filtered()
        keys = [str(h.ip) for h in self._visible]
        if keys == self._table_keys:
            # Same rows in the same order: patch cells in place, no clear/scroll reset.
            self._patch_cells(table, self._visible)
        elif self._scanning and time.monotonic() - self._last_reload < RELOAD_INTERVAL:
            # Row set is changing every tick (volatile sort or offline hidden); rate-limit
            # the full reload but keep the rows already shown up to date.
            self._patch_cells(table, [h for h in self._visible if str(h.ip) in self._rendered])
            self._dirty = True
        else:
            self._reload_rows(table, keys)
        self._update_status()

    def _patch_cells(self, table: DataTable, hosts: list[Host]) -> None:
        for h in hosts:
            key = str(h.ip)
            cells = _row_cells(h)
            old = self._rendered.get(key)
            if cells == old:
                continue
            for i, (col, value) in enumerate(zip(COLUMN_KEYS, cells)):
                if old is None or value != old[i]:
                    # update_width lets the auto columns (FQDN, vendor) grow; they never shrink.
                    table.update_cell(key, col, value, update_width=True)
            self._rendered[key] = cells

    def _reload_rows(self, table: DataTable, keys: list[str]) -> None:
        # Remember the cursor host and scroll offset so they survive the rebuild.
        current_key = self._cursor_key(table)
        scroll_y = table.scroll_y

        table.clear()
        self._rendered = {}
        new_index = None
        for i, h in enumerate(self._visible):
            cells = _row_cells(h)
            table.add_row(*cells, key=cells[0])
            self._rendered[cells[0]] = cells
            if cells[0] == current_key:
                new_index = i
        self._table_keys = keys
        self._last_reload = time.monotonic()
        if new_index is not None:
            table.move_cursor(row=new_index, animate=False, scroll=False)
        table.scroll_to(y=scroll_y, animate=False, force=True)

    def _update_status(self) -> None:
        total = len(self._hosts)
        done = sum(1 for h in self._hosts.values() if h.status != STATUS_PENDING)
        online = sum(1 for h in self._hosts.values() if h.status == STATUS_ONLINE)
        arp = sum(1 for h in self._hosts.values() if h.status == STATUS_ARP)
        elapsed = (time.monotonic() - self._started_at) if self._scanning else self._elapsed
        state = "[yellow]Scanning[/] " if self._scanning else "Scanned "
        arrow = "desc" if self._sort_reverse else "asc"
        text = (f"{state}{done}/{total} | [green]{online} online[/] | {arp} arp-only | "
                f"{elapsed:.1f}s | showing {len(self._visible)} | sort {self._sort_col} {arrow}")
        self.query_one("#status", Static).update(text)

    @on(DataTable.HeaderSelected)
    def _sort(self, event: DataTable.HeaderSelected) -> None:
        col = str(event.column_key.value)
        if col == self._sort_col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col, self._sort_reverse = col, False
        self._dirty = True

    @on(Input.Changed, "#search")
    @on(Checkbox.Changed, "#show-offline")
    def _filter_changed(self) -> None:
        self._dirty = True

    @on(Input.Submitted, "#search")
    def _search_done(self) -> None:
        self.query_one(DataTable).focus()

    # ---------- actions ----------

    def action_focus_search(self) -> None:
        self.query_one("#search", Input).focus()

    def action_clear_filter(self) -> None:
        self.query_one("#search", Input).value = ""
        self.query_one(DataTable).focus()

    def action_toggle_offline(self) -> None:
        cb = self.query_one("#show-offline", Checkbox)
        cb.value = not cb.value

    def _current_host(self) -> Host | None:
        key = self._cursor_key(self.query_one(DataTable))
        return self._hosts.get(IPv4Address(key)) if key else None

    def action_copy(self, field: str) -> None:
        host = self._current_host()
        if host is None:
            self.notify("No row selected", severity="warning")
            return
        value = str(host.ip) if field == "ip" else getattr(host, field)
        if not value:
            self.notify(f"{host.ip} has no {field.upper()}", severity="warning")
            return
        try:
            pyperclip.copy(value)
        except pyperclip.PyperclipException as exc:
            self.notify(f"Clipboard unavailable: {exc}", severity="error")
            return
        self.notify(f"Copied {value}")

    def action_export(self) -> None:
        if not self._visible:
            self.notify("Nothing to export", severity="warning")
            return
        self.push_screen(ExportScreen(self._scan_range, len(self._visible)),
                         callback=self._do_export)

    def _do_export(self, result: tuple[str, Path] | None) -> None:
        if result is None:
            return
        fmt, path = result
        try:
            export.write(self._visible, path, fmt, scan_range=self._scan_range)
        except OSError as exc:
            self.notify(f"Export failed: {exc}", severity="error")
            return
        self.notify(f"Saved {len(self._visible)} rows to {path}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="ipscan", description="Text-mode IP range scanner.")
    ap.add_argument("range", nargs="?", help="range to pre-fill (CIDR, a-b, or single IP)")
    ap.add_argument("--version", action="version", version=f"ipscan {__version__}")
    args = ap.parse_args(argv)
    IPScannerApp(initial_range=args.range).run()


if __name__ == "__main__":
    main()
