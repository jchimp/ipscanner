"""Write scan results to CSV, JSON or a self-contained HTML page."""

from __future__ import annotations

import csv
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Iterable

from ipscanner.scanner import Host

FIELDS = ("ip", "status", "latency_ms", "fqdn", "mac", "vendor")
FORMATS = ("csv", "json", "html")


def _row(host: Host) -> dict[str, object]:
    return {
        "ip": str(host.ip),
        "status": host.status,
        "latency_ms": host.latency_ms,
        "fqdn": host.fqdn,
        "mac": host.mac,
        "vendor": host.vendor,
    }


def write_csv(hosts: Iterable[Host], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for h in hosts:
            w.writerow(_row(h))


def write_json(hosts: Iterable[Host], path: Path, *, scan_range: str = "") -> None:
    doc = {
        "range": scan_range,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "hosts": [_row(h) for h in hosts],
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")


_HTML_HEAD = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>ipscan {range}</title>
<style>
body{{font-family:system-ui,Segoe UI,sans-serif;margin:1.5rem;background:#fafafa;color:#222}}
h1{{font-size:1.2rem;margin:0 0 .25rem}} p{{margin:0 0 1rem;color:#666}}
table{{border-collapse:collapse;width:100%;font-size:.9rem;background:#fff}}
th,td{{border:1px solid #ddd;padding:.3rem .5rem;text-align:left;white-space:nowrap}}
th{{background:#eee;cursor:pointer;user-select:none}} th:after{{content:" \2195";color:#999}}
tr.online td:nth-child(2){{color:#080}} tr.arp td:nth-child(2){{color:#a60}}
tr.offline td:nth-child(2){{color:#999}}
</style></head><body>
<h1>ipscan {range}</h1>
<p>{generated} &middot; {count} hosts</p>
<table id="t"><thead><tr>{headers}</tr></thead><tbody>
"""

_HTML_TAIL = """</tbody></table>
<script>
document.querySelectorAll('#t th').forEach((th,i)=>th.addEventListener('click',()=>{
  const tb=th.closest('table').tBodies[0], rows=[...tb.rows];
  const asc=!(th.dataset.asc==='1'); th.dataset.asc=asc?'1':'0';
  const key=r=>{const v=r.cells[i].dataset.sort??r.cells[i].textContent; const n=parseFloat(v); return isNaN(n)?v:n;};
  rows.sort((a,b)=>{const x=key(a),y=key(b); return (x>y?1:x<y?-1:0)*(asc?1:-1);});
  rows.forEach(r=>tb.appendChild(r));
}));
</script></body></html>
"""


def write_html(hosts: Iterable[Host], path: Path, *, scan_range: str = "") -> None:
    hosts = list(hosts)
    headers = "".join(f"<th>{html.escape(f)}</th>" for f in FIELDS)
    body: list[str] = []
    for h in hosts:
        row = _row(h)
        cells = []
        for f in FIELDS:
            v = row[f]
            text = "" if v is None else html.escape(str(v))
            # Numeric sort key for IPs; the JS falls back to text otherwise.
            attr = f' data-sort="{int(h.ip)}"' if f == "ip" else ""
            cells.append(f"<td{attr}>{text}</td>")
        body.append(f'<tr class="{h.status}">{"".join(cells)}</tr>\n')
    page = _HTML_HEAD.format(
        range=html.escape(scan_range),
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        count=len(hosts),
        headers=headers,
    ) + "".join(body) + _HTML_TAIL
    path.write_text(page, encoding="utf-8")


def write(hosts: Iterable[Host], path: Path, fmt: str, *, scan_range: str = "") -> None:
    """Dispatch on ``fmt`` (csv / json / html)."""
    if fmt == "csv":
        write_csv(hosts, path)
    elif fmt == "json":
        write_json(hosts, path, scan_range=scan_range)
    elif fmt == "html":
        write_html(hosts, path, scan_range=scan_range)
    else:
        raise ValueError(f"Unknown export format: {fmt}")


def default_filename(scan_range: str, fmt: str) -> str:
    safe = scan_range.replace("/", "_").replace(" ", "")
    return f"ipscan_{safe}_{datetime.now():%Y%m%d-%H%M%S}.{fmt}"
