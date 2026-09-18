# ipscanner

Fast text-mode IP range scanner (Textual TUI). Ping sweep + ARP merge, reverse DNS,
MAC vendor lookup, live filter, clipboard copy, CSV/JSON/HTML export.

No admin rights needed: it drives the system `ping` and reads the OS ARP table.

## Install

```sh
uv tool install .            # installs the `ipscan` command
# or, for development:
uv sync --extra dev
uv run ipscan
```

Plain pip works too: `pip install .`

## Use

```sh
ipscan                       # pre-fills your primary local subnet
ipscan 10.0.0.1-50           # pre-fill any range (CIDR, a-b, a.b.c.d-e.f.g.h, single IP)
```

Pick a detected subnet from the drop-down or type any range, then press **Enter** or **s**.

| Key     | Action                                   |
|---------|------------------------------------------|
| `s`     | Scan the range in the box                |
| `Esc`   | Stop a running scan / return to the table|
| `/`     | Focus the filter box (Enter returns)     |
| `r`     | Clear the filter                         |
| `o`     | Toggle "Show offline"                    |
| `c`     | Copy selected IP to clipboard            |
| `f`     | Copy selected FQDN                       |
| `m`     | Copy selected MAC                        |
| `e`     | Export current view (CSV / JSON / HTML)  |
| `q`     | Quit                                     |

Click a column header to sort; click again to reverse.

Status values: `online` (ping reply), `arp` (no ping reply but present in the ARP table -
usually a host that blocks ICMP), `offline`.

Copy keys work when the results table has focus. The clipboard content stays after you quit.
On Linux, pyperclip needs `xclip`, `xsel` or `wl-copy` installed.

Export writes what is currently shown (filter and sort applied). The HTML file is
self-contained with click-to-sort headers.

## MAC vendor table

`ipscanner/data/oui.csv` is generated from the IEEE OUI registry. Refresh it with:

```sh
python scripts/update_oui.py        # add --dry-run to only fetch and count
```

## Tests

```sh
uv run pytest
```
