"""Download the IEEE OUI registry and write a trimmed ``ipscanner/data/oui.csv``.

Usage: python scripts/update_oui.py [--dry-run]
"""

from __future__ import annotations

import argparse
import csv
import io
import sys
import urllib.request
from pathlib import Path

SOURCE = "https://standards-oui.ieee.org/oui/oui.csv"
TARGET = Path(__file__).resolve().parent.parent / "ipscanner" / "data" / "oui.csv"


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "ipscanner-oui-updater"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def trim(raw_csv: str) -> list[tuple[str, str]]:
    """Reduce the IEEE CSV (Registry,Assignment,Organization Name,Address) to prefix,vendor."""
    rows: list[tuple[str, str]] = []
    reader = csv.DictReader(io.StringIO(raw_csv))
    for row in reader:
        prefix = row.get("Assignment", "").strip().upper()
        vendor = " ".join(row.get("Organization Name", "").split())
        if len(prefix) == 6 and vendor:
            rows.append((prefix, vendor))
    rows.sort()
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="fetch and report, do not write")
    args = ap.parse_args(argv)

    print(f"Fetching {SOURCE} ...")
    rows = trim(fetch(SOURCE))
    print(f"{len(rows)} OUI entries")
    if args.dry_run:
        print(f"Dry run: would write {TARGET}")
        return 0
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    with TARGET.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerows(rows)
    print(f"Wrote {TARGET} ({TARGET.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
