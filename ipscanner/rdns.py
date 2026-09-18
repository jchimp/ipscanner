"""Minimal async reverse-DNS (PTR) resolver.

``socket.gethostbyaddr`` has no timeout and a negative answer on Windows can take ~10 s,
which makes a /24 sweep crawl. This sends raw PTR queries over UDP with a short timeout.
"""

from __future__ import annotations

import asyncio
import random
import re
import socket
import struct
import subprocess
import sys
from ipaddress import IPv4Address
from pathlib import Path

_IS_WINDOWS = sys.platform.startswith("win")

TYPE_PTR = 12
CLASS_IN = 1


def _run(cmd: list[str]) -> str:
    try:
        flags = subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0  # type: ignore[attr-defined]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                              creationflags=flags, errors="replace").stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def system_nameservers() -> list[str]:
    """Return the OS-configured IPv4 DNS servers (best effort, may be empty)."""
    servers: list[str] = []
    if _IS_WINDOWS:
        text = _run(["ipconfig", "/all"])
        in_dns = False
        for line in text.splitlines():
            m = re.match(r"\s+DNS Servers[ .]*:\s*(\S+)", line)
            if m:
                in_dns = True
                servers.append(m.group(1))
                continue
            # Extra servers continue on indented lines with no label.
            if in_dns and re.match(r"\s{20,}(\S+)\s*$", line):
                servers.append(line.strip())
                continue
            in_dns = False
    else:
        try:
            for line in Path("/etc/resolv.conf").read_text().splitlines():
                m = re.match(r"nameserver\s+(\S+)", line)
                if m:
                    servers.append(m.group(1))
        except OSError:
            pass
    # Keep IPv4 only, drop duplicates, keep order.
    out: list[str] = []
    for s in servers:
        try:
            IPv4Address(s)
        except ValueError:
            continue
        if s not in out:
            out.append(s)
    return out


def _build_query(ip: IPv4Address, txid: int) -> bytes:
    name = ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # RD=1, 1 question
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", TYPE_PTR, CLASS_IN)


def _read_name(msg: bytes, pos: int) -> tuple[str, int]:
    """Decode a possibly-compressed DNS name; returns (name, position after it)."""
    labels: list[str] = []
    jumped = False
    end = pos
    hops = 0
    while True:
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if not jumped:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            jumped = True
            hops += 1
            if hops > 32:
                raise ValueError("compression loop")
            continue
        labels.append(msg[pos + 1:pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    if not jumped:
        end = pos
    return ".".join(labels), end


def parse_ptr_response(msg: bytes, txid: int) -> str | None:
    """Return the first PTR target in a response, or None."""
    if len(msg) < 12:
        return None
    rid, flags, qd, an, _, _ = struct.unpack("!HHHHHH", msg[:12])
    if rid != txid or (flags & 0x000F) != 0:  # RCODE != NOERROR
        return None
    pos = 12
    for _ in range(qd):
        _, pos = _read_name(msg, pos)
        pos += 4
    for _ in range(an):
        _, pos = _read_name(msg, pos)
        rtype, _, _, rdlen = struct.unpack("!HHIH", msg[pos:pos + 10])
        pos += 10
        if rtype == TYPE_PTR:
            name, _ = _read_name(msg, pos)
            return name.rstrip(".") or None
        pos += rdlen
    return None


class _Proto(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)


async def ptr_lookup(ip: IPv4Address, servers: list[str], timeout: float = 1.5) -> str | None:
    """Reverse-resolve ``ip`` against each server in turn; None if no answer."""
    loop = asyncio.get_running_loop()
    for server in servers:
        txid = random.randint(0, 0xFFFF)
        try:
            transport, proto = await loop.create_datagram_endpoint(
                _Proto, remote_addr=(server, 53), family=socket.AF_INET)
        except OSError:
            continue
        try:
            transport.sendto(_build_query(ip, txid))
            data = await asyncio.wait_for(proto.future, timeout)
            return parse_ptr_response(data, txid)  # Server answered: NXDOMAIN or a name.
        except (asyncio.TimeoutError, OSError, ValueError, IndexError):
            continue  # Try the next server.
        finally:
            transport.close()
    return None
