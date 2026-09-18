"""Local network discovery helpers: range parsing, interface subnets, ARP table."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

MAX_ADDRESSES = 65_536

_IS_WINDOWS = sys.platform.startswith("win")


@dataclass(frozen=True)
class Subnet:
    """An IPv4 subnet attached to a local interface."""

    iface: str
    network: IPv4Network
    has_gateway: bool

    @property
    def cidr(self) -> str:
        return str(self.network)


def parse_range(text: str) -> list[IPv4Address]:
    """Parse a user-typed range into a list of addresses.

    Accepted forms: ``10.0.0.0/24``, ``10.0.0.1-254``, ``10.0.0.1-10.0.0.50``, ``10.0.0.5``.

    Args:
        text: Range text as typed by the user.

    Returns:
        Ordered list of addresses to scan.

    Raises:
        ValueError: If the text is not a recognised range or is too large.
    """
    text = text.strip()
    if not text:
        raise ValueError("Range is empty")

    if "/" in text:
        net = IPv4Network(text, strict=False)
        if net.num_addresses > MAX_ADDRESSES:
            raise ValueError(f"Range too large (max {MAX_ADDRESSES} addresses)")
        # /31 and /32 have no usable-host distinction; everything else drops net/broadcast.
        hosts = list(net.hosts()) if net.prefixlen <= 30 else list(net)
        return hosts

    if "-" in text:
        start_text, end_text = (p.strip() for p in text.split("-", 1))
        start = IPv4Address(start_text)
        if "." in end_text:
            end = IPv4Address(end_text)
        else:
            # Short form: last octet only.
            last = int(end_text)
            if not 0 <= last <= 255:
                raise ValueError("Last octet must be 0-255")
            end = IPv4Address(start_text.rsplit(".", 1)[0] + f".{last}")
        if end < start:
            raise ValueError("Range end is before start")
        count = int(end) - int(start) + 1
        if count > MAX_ADDRESSES:
            raise ValueError(f"Range too large (max {MAX_ADDRESSES} addresses)")
        return [IPv4Address(int(start) + i) for i in range(count)]

    return [IPv4Address(text)]


def _run(cmd: list[str]) -> str:
    """Run a command and return stdout; empty string on any failure."""
    try:
        creation = subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0  # type: ignore[attr-defined]
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, creationflags=creation,
            errors="replace",
        )
        return out.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _usable(net: IPv4Network) -> bool:
    return not (net.is_loopback or net.is_link_local or net.prefixlen == 32)


def parse_ipconfig(text: str) -> list[Subnet]:
    """Parse Windows ``ipconfig`` output into subnets."""
    subnets: list[Subnet] = []
    iface = ""
    ip = mask = None
    gateway = False

    def flush() -> None:
        if ip and mask:
            net = IPv4Network(f"{ip}/{mask}", strict=False)
            if _usable(net):
                subnets.append(Subnet(iface, net, gateway))

    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            flush()
            # "Ethernet adapter Ethernet 2:" -> "Ethernet 2"; keeps labels short in the UI.
            iface = re.sub(r"^.*? adapter ", "", line.strip().rstrip(":"))
            ip = mask = None
            gateway = False
            continue
        m = re.match(r"\s+IPv4 Address[ .]*:\s*([\d.]+)", line)
        if m:
            ip = m.group(1)
            continue
        m = re.match(r"\s+Subnet Mask[ .]*:\s*([\d.]+)", line)
        if m:
            mask = m.group(1)
            continue
        m = re.match(r"\s+Default Gateway[ .]*:\s*([\d.]+)", line)
        if m:
            gateway = True
    flush()
    return subnets


def parse_ip_addr(addr_text: str, route_text: str) -> list[Subnet]:
    """Parse Linux ``ip -o -4 addr`` and ``ip route`` output into subnets."""
    gw_ifaces = set(re.findall(r"^default\s.*?\bdev\s+(\S+)", route_text, re.MULTILINE))
    subnets: list[Subnet] = []
    for line in addr_text.splitlines():
        m = re.match(r"\d+:\s+(\S+)\s+inet\s+([\d.]+/\d+)", line)
        if not m:
            continue
        iface, cidr = m.groups()
        net = IPv4Network(cidr, strict=False)
        if _usable(net):
            subnets.append(Subnet(iface, net, iface in gw_ifaces))
    return subnets


def _outbound_ip() -> IPv4Address | None:
    """Find the IP used for outbound traffic without sending any packets."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 53))
            return IPv4Address(s.getsockname()[0])
    except OSError:
        return None


def local_subnets() -> list[Subnet]:
    """Return local IPv4 subnets, interfaces with a default gateway first."""
    if _IS_WINDOWS:
        subnets = parse_ipconfig(_run(["ipconfig"]))
    else:
        subnets = parse_ip_addr(_run(["ip", "-o", "-4", "addr"]), _run(["ip", "route"]))

    if not subnets:
        ip = _outbound_ip()
        if ip:
            subnets = [Subnet("default", IPv4Network(f"{ip}/24", strict=False), True)]

    # Stable sort: gateway interfaces first, then the outbound one, keep detection order.
    out = _outbound_ip()
    subnets.sort(key=lambda s: (not s.has_gateway, out is None or out not in s.network))
    return subnets


_MAC_RE = re.compile(r"([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]"
                     r"([0-9a-f]{2})[-:]([0-9a-f]{2})[-:]([0-9a-f]{2})", re.IGNORECASE)


def normalise_mac(mac: str) -> str:
    return ":".join(p.lower() for p in re.split(r"[-:]", mac))


def _is_real_mac(mac: str) -> bool:
    if mac == "ff:ff:ff:ff:ff:ff" or mac == "00:00:00:00:00:00":
        return False
    # Multicast MACs have the low bit of the first octet set.
    return not (int(mac[:2], 16) & 1)


def parse_arp(text: str) -> dict[IPv4Address, str]:
    """Parse Windows ``arp -a`` or Linux ``ip neigh`` output."""
    table: dict[IPv4Address, str] = {}
    for line in text.splitlines():
        if "FAILED" in line or "INCOMPLETE" in line:
            continue
        ip_m = re.search(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", line)
        mac_m = _MAC_RE.search(line)
        if not ip_m or not mac_m:
            continue
        mac = normalise_mac(mac_m.group(0))
        if not _is_real_mac(mac):
            continue
        try:
            ip = IPv4Address(ip_m.group(1))
        except ValueError:
            continue
        if ip.is_multicast:
            continue
        table[ip] = mac
    return table


def arp_table() -> dict[IPv4Address, str]:
    """Read the OS neighbour table."""
    if _IS_WINDOWS:
        return parse_arp(_run(["arp", "-a"]))
    text = _run(["ip", "neigh"]) or _run(["arp", "-an"])
    return parse_arp(text)
