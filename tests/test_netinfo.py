from ipaddress import IPv4Address

import pytest

from ipscanner.netinfo import parse_arp, parse_ip_addr, parse_ipconfig, parse_range


def test_parse_range_cidr_drops_network_and_broadcast():
    ips = parse_range("10.0.0.0/30")
    assert ips == [IPv4Address("10.0.0.1"), IPv4Address("10.0.0.2")]


def test_parse_range_cidr_31_keeps_both():
    assert len(parse_range("10.0.0.0/31")) == 2


def test_parse_range_short_dash():
    ips = parse_range("10.0.0.5-7")
    assert [str(i) for i in ips] == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]


def test_parse_range_full_dash_across_octet():
    ips = parse_range("10.0.0.254 - 10.0.1.1")
    assert [str(i) for i in ips] == ["10.0.0.254", "10.0.0.255", "10.0.1.0", "10.0.1.1"]


def test_parse_range_single():
    assert parse_range("192.168.1.9") == [IPv4Address("192.168.1.9")]


@pytest.mark.parametrize("bad", ["", "10.0.0.9-1", "10.0.0.0/8", "10.0.0.1-999", "nope"])
def test_parse_range_rejects(bad):
    with pytest.raises(ValueError):
        parse_range(bad)


IPCONFIG = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : hq.example.com
   IPv4 Address. . . . . . . . . . . : 10.26.1.64
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.26.1.1

Ethernet adapter VirtualBox Host-Only Network:

   IPv4 Address. . . . . . . . . . . : 192.168.56.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :

Ethernet adapter Bluetooth Network Connection:

   Media State . . . . . . . . . . . : Media disconnected
"""


def test_parse_ipconfig():
    subs = parse_ipconfig(IPCONFIG)
    assert [(s.cidr, s.has_gateway) for s in subs] == [
        ("10.26.1.0/24", True),
        ("192.168.56.0/24", False),
    ]
    assert subs[0].iface == "Ethernet"


IP_ADDR = r"""1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: eth0    inet 172.16.5.20/22 brd 172.16.7.255 scope global eth0\       valid_lft forever preferred_lft forever
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\       valid_lft forever preferred_lft forever
"""
IP_ROUTE = """default via 172.16.4.1 dev eth0 proto dhcp metric 100
172.16.4.0/22 dev eth0 proto kernel scope link src 172.16.5.20
"""


def test_parse_ip_addr():
    subs = parse_ip_addr(IP_ADDR, IP_ROUTE)
    assert [(s.iface, s.cidr, s.has_gateway) for s in subs] == [
        ("eth0", "172.16.4.0/22", True),
        ("docker0", "172.17.0.0/16", False),
    ]


ARP_WIN = """
Interface: 10.26.1.64 --- 0x5
  Internet Address      Physical Address      Type
  10.26.1.1             00-e0-97-1d-52-79     dynamic
  10.26.1.250           58-8B-1C-46-BF-D7     dynamic
  10.26.1.255           ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
"""


def test_parse_arp_windows():
    t = parse_arp(ARP_WIN)
    assert t == {
        IPv4Address("10.26.1.1"): "00:e0:97:1d:52:79",
        IPv4Address("10.26.1.250"): "58:8b:1c:46:bf:d7",
    }


ARP_LINUX = """172.16.4.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
172.16.5.99 dev eth0  FAILED
172.16.5.7 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
"""


def test_parse_arp_linux():
    t = parse_arp(ARP_LINUX)
    assert t == {
        IPv4Address("172.16.4.1"): "00:11:22:33:44:55",
        IPv4Address("172.16.5.7"): "aa:bb:cc:dd:ee:ff",
    }
