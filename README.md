# ipscanner

A fast, keyboard-driven IP range scanner that runs in your terminal.

Point it at a subnet and it finds every live host, then shows the hostname, MAC address
and hardware vendor for each one. Filter the results as you type, copy any value to the
clipboard, or export the whole table to CSV, JSON or a self-contained HTML page.

**No admin rights needed.** ipscanner drives the system `ping` command and reads the OS
ARP table, so it works on a normal user account on Windows, macOS and Linux.

## Features

- Ping sweep with ARP merge — finds hosts that block ICMP too
- Reverse DNS lookup
- MAC vendor lookup from the IEEE OUI registry (bundled, works offline)
- Auto-detects your local subnets and pre-fills the range
- Live filter, click-to-sort columns, show/hide offline hosts
- Copy IP, hostname or MAC to the clipboard with one key
- Export the current view to CSV, JSON or HTML

## Install

### 1. Install uv

[uv](https://docs.astral.sh/uv/) is a fast Python package manager. It also installs Python
for you if you do not have it yet.

**Windows** (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**macOS / Linux**:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Close and reopen your terminal after the install so `uv` is on your PATH.

### 2. Install ipscanner

```sh
uv tool install git+https://github.com/jchimp/ipscanner.git
```

This installs the `ipscan` command in its own isolated environment. Check it works:

```sh
ipscan --version
```

**Linux only:** clipboard copy needs one of `xclip`, `xsel` or `wl-clipboard` installed
(for example `sudo apt install xclip`).

### Upgrade or remove

```sh
uv tool upgrade ipscanner
uv tool uninstall ipscanner
```

## Usage

```sh
ipscan                       # pre-fills your primary local subnet
ipscan 192.168.1.0/24        # CIDR
ipscan 10.0.0.1-50           # short range
ipscan 10.0.0.1-10.0.0.254   # full range
ipscan 10.0.0.5              # single host
```

Pick a detected subnet from the drop-down or type any range, then press **Enter** or **s**
to scan.

### Keys

| Key   | Action                                     |
|-------|--------------------------------------------|
| `s`   | Scan the range in the box                  |
| `Esc` | Stop a running scan / return to the table  |
| `/`   | Focus the filter box (Enter returns)       |
| `r`   | Clear the filter                           |
| `o`   | Toggle "Show offline"                      |
| `c`   | Copy selected IP to clipboard              |
| `f`   | Copy selected hostname (FQDN)              |
| `m`   | Copy selected MAC                          |
| `e`   | Export current view (CSV / JSON / HTML)    |
| `q`   | Quit                                       |

Click a column header to sort; click again to reverse. Copy keys work when the results
table has focus, and the clipboard content stays after you quit.

### Status column

| Status    | Meaning                                                              |
|-----------|----------------------------------------------------------------------|
| `online`  | Replied to ping                                                      |
| `arp`     | No ping reply, but present in the ARP table (usually blocks ICMP)    |
| `offline` | No response                                                          |

### Export

Export writes exactly what is on screen, with the current filter and sort applied.
The export dialog suggests a filename like `ipscan_<range>_<timestamp>.csv`; you can change it.
The HTML file is self-contained and has click-to-sort headers.

## Development

```sh
git clone https://github.com/jchimp/ipscanner.git
cd ipscanner
uv sync --extra dev
uv run ipscan
uv run pytest
```

To install your local checkout as the `ipscan` tool instead of the GitHub version:

```sh
uv tool install --editable .
```

### Refresh the MAC vendor table

`ipscanner/data/oui.csv` is generated from the IEEE OUI registry. To refresh it:

```sh
uv run python scripts/update_oui.py        # add --dry-run to only fetch and count
```

## Requirements

- Python 3.10+ (uv installs this for you if needed)
- Windows, macOS or Linux
