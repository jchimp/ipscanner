import csv
import json
from ipaddress import IPv4Address

from ipscanner import export
from ipscanner.scanner import Host


def _hosts():
    return [
        Host(IPv4Address("10.0.0.1"), "online", 2.0, "gw.example.com", "00:11:22:33:44:55", "ACME"),
        Host(IPv4Address("10.0.0.2"), "offline"),
    ]


def test_csv(tmp_path):
    p = tmp_path / "out.csv"
    export.write(_hosts(), p, "csv")
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    assert rows[0]["ip"] == "10.0.0.1" and rows[0]["vendor"] == "ACME"
    assert rows[1]["fqdn"] == ""


def test_json(tmp_path):
    p = tmp_path / "out.json"
    export.write(_hosts(), p, "json", scan_range="10.0.0.0/30")
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert doc["range"] == "10.0.0.0/30"
    assert doc["hosts"][1]["latency_ms"] is None


def test_html_escapes(tmp_path):
    hosts = _hosts()
    hosts[0].fqdn = "<script>x</script>"
    p = tmp_path / "out.html"
    export.write(hosts, p, "html", scan_range="10.0.0.0/30")
    text = p.read_text(encoding="utf-8")
    assert "<script>x</script>" not in text
    assert "&lt;script&gt;" in text
    assert text.count("<tr class=") == 2


def test_default_filename():
    name = export.default_filename("10.0.0.0/24", "csv")
    assert name.startswith("ipscan_10.0.0.0_24_") and name.endswith(".csv")
