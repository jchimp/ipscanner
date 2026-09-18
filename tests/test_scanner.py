import pytest

from ipscanner import scanner
from ipscanner.scanner import parse_ping

WIN_OK = """
Pinging 10.26.1.1 with 32 bytes of data:
Reply from 10.26.1.1: bytes=32 time=3ms TTL=64

Ping statistics for 10.26.1.1:
"""
WIN_FAST = "Reply from 10.26.1.1: bytes=32 time<1ms TTL=64\n"
WIN_UNREACH = """
Pinging 10.26.1.77 with 32 bytes of data:
Reply from 10.26.1.64: Destination host unreachable.
"""
WIN_TIMEOUT = "Request timed out.\n"

LINUX_OK = """PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.412 ms
"""


@pytest.mark.parametrize("windows", [True, False])
def test_parse_ping_platforms(monkeypatch, windows):
    monkeypatch.setattr(scanner, "_IS_WINDOWS", windows)
    if windows:
        assert parse_ping(WIN_OK, 0) == (True, 3.0)
        assert parse_ping(WIN_FAST, 0) == (True, 1.0)
        # Exit code 0 but no TTL= line: Windows "host unreachable" must be offline.
        assert parse_ping(WIN_UNREACH, 0) == (False, None)
        assert parse_ping(WIN_TIMEOUT, 1) == (False, None)
    else:
        assert parse_ping(LINUX_OK, 0) == (True, 0.412)
        assert parse_ping(LINUX_OK, 1) == (False, None)
