"""MAC vendor lookup from the bundled IEEE OUI table."""

from __future__ import annotations

import csv
from functools import lru_cache
from importlib import resources


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    """Load ``data/oui.csv`` (prefix,vendor) once."""
    table: dict[str, str] = {}
    try:
        path = resources.files("ipscanner").joinpath("data/oui.csv")
        with path.open("r", encoding="utf-8", newline="") as fh:
            for row in csv.reader(fh):
                if len(row) >= 2:
                    table[row[0]] = row[1]
    except (OSError, FileNotFoundError):
        pass  # Missing table just means no vendor column; scanning still works.
    return table


def lookup(mac: str | None) -> str | None:
    """Return the vendor name for a MAC address, or None if unknown."""
    if not mac:
        return None
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    return _table().get(prefix)
