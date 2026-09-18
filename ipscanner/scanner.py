"""Async host sweep: ping, reverse DNS, ARP merge."""

from __future__ import annotations

import asyncio
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from ipaddress import IPv4Address
from typing import Callable

from ipscanner import oui
from ipscanner.netinfo import arp_table
from ipscanner.rdns import ptr_lookup, system_nameservers

_IS_WINDOWS = sys.platform.startswith("win")

STATUS_ONLINE = "online"
STATUS_OFFLINE = "offline"
STATUS_ARP = "arp"       # No ping reply, but present in the ARP table.
STATUS_PENDING = "pending"


@dataclass
class Host:
    ip: IPv4Address
    status: str = STATUS_PENDING
    latency_ms: float | None = None
    fqdn: str | None = None
    mac: str | None = None
    vendor: str | None = None

    @property
    def is_up(self) -> bool:
        return self.status in (STATUS_ONLINE, STATUS_ARP)


UpdateCallback = Callable[[Host], None]

_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)


def ping_command(ip: IPv4Address, timeout_ms: int) -> list[str]:
    if _IS_WINDOWS:
        return ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    secs = max(1, round(timeout_ms / 1000))
    return ["ping", "-c", "1", "-W", str(secs), str(ip)]


def parse_ping(output: str, returncode: int) -> tuple[bool, float | None]:
    """Decide online/offline and latency from ping output.

    Windows ping exits 0 for "Destination host unreachable", so success is judged on a
    reply line containing ``TTL=`` rather than on the exit code.
    """
    if _IS_WINDOWS:
        alive = "TTL=" in output.upper()
    else:
        alive = returncode == 0 and ("ttl=" in output.lower())
    if not alive:
        return False, None
    m = _TIME_RE.search(output)
    return True, (float(m.group(1)) if m else None)


async def _ping(ip: IPv4Address, timeout_ms: int) -> tuple[bool, float | None]:
    flags = subprocess.CREATE_NO_WINDOW if _IS_WINDOWS else 0  # type: ignore[attr-defined]
    try:
        proc = await asyncio.create_subprocess_exec(
            *ping_command(ip, timeout_ms),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            creationflags=flags,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout_ms / 1000 + 3)
        except asyncio.TimeoutError:
            proc.kill()
            return False, None
        return parse_ping(out.decode(errors="replace"), proc.returncode or 0)
    except OSError:
        return False, None


def _reverse_dns(ip: IPv4Address) -> str | None:
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


async def scan(
    addresses: list[IPv4Address],
    on_update: UpdateCallback,
    *,
    stop: asyncio.Event,
    concurrency: int = 64,
    timeout_ms: int = 1000,
    resolve_dns: bool = True,
) -> dict[IPv4Address, Host]:
    """Sweep ``addresses`` and report every host state change through ``on_update``.

    Args:
        addresses: Addresses to probe.
        on_update: Called with the Host after each change (ping result, DNS, ARP).
        stop: Set this event to abort the sweep early.
        concurrency: Max simultaneous ping processes.
        timeout_ms: Per-ping reply timeout.
        resolve_dns: Whether to run reverse DNS lookups.

    Returns:
        Mapping of address to final Host state (may be partial if stopped).
    """
    hosts = {ip: Host(ip) for ip in addresses}
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    dns_sem = asyncio.Semaphore(128)
    dns_pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="rdns")
    dns_tasks: list[asyncio.Task] = []
    # Direct PTR queries have a real timeout; gethostbyaddr does not (a miss can take ~10 s
    # on Windows), so the fallback is only used for hosts that are up.
    nameservers = await loop.run_in_executor(None, system_nameservers) if resolve_dns else []

    async def resolve(host: Host) -> None:
        if stop.is_set():
            return
        async with dns_sem:
            if nameservers:
                name = await ptr_lookup(host.ip, nameservers)
            elif host.is_up:
                name = await loop.run_in_executor(dns_pool, _reverse_dns, host.ip)
            else:
                return
        if name and not stop.is_set():
            host.fqdn = name
            on_update(host)

    async def probe(host: Host) -> None:
        if stop.is_set():
            return
        async with sem:
            if stop.is_set():
                return
            alive, latency = await _ping(host.ip, timeout_ms)
        host.status = STATUS_ONLINE if alive else STATUS_OFFLINE
        host.latency_ms = latency
        on_update(host)
        # Resolve live hosts as soon as they answer; offline ones wait until the end.
        if alive and resolve_dns:
            dns_tasks.append(asyncio.create_task(resolve(host)))

    try:
        await asyncio.gather(*(probe(h) for h in hosts.values()))
        if stop.is_set():
            return hosts

        # ARP merge: MACs for everything on-link, plus hosts that block ICMP.
        arp = await loop.run_in_executor(None, arp_table)
        for ip, mac in arp.items():
            host = hosts.get(ip)
            if host is None:
                continue
            host.mac = mac
            host.vendor = oui.lookup(mac)
            if host.status == STATUS_OFFLINE:
                host.status = STATUS_ARP
                if resolve_dns:
                    dns_tasks.append(asyncio.create_task(resolve(host)))
            on_update(host)

        if resolve_dns:
            for host in hosts.values():
                if host.status == STATUS_OFFLINE:
                    dns_tasks.append(asyncio.create_task(resolve(host)))
            await asyncio.gather(*dns_tasks)
    finally:
        for t in dns_tasks:
            t.cancel()
        dns_pool.shutdown(wait=False, cancel_futures=True)
    return hosts
