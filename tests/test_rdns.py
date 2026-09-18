from ipaddress import IPv4Address

from ipscanner.rdns import _build_query, parse_ptr_response


def _response(txid: int, rcode: int = 0, answer: bytes = b"") -> bytes:
    q = _build_query(IPv4Address("10.0.0.1"), txid)
    header = bytes([txid >> 8, txid & 0xFF, 0x81, 0x80 | rcode,
                    0, 1, 0, 1 if answer else 0, 0, 0, 0, 0])
    return header + q[12:] + answer


def test_ptr_parsed_with_compression_pointer():
    # Answer: name = pointer to question (offset 12), type PTR, class IN, ttl, rdlength, rdata.
    rdata = b"\x02gw\x07example\x03com\x00"
    answer = (b"\xc0\x0c" + b"\x00\x0c\x00\x01" + b"\x00\x00\x0e\x10"
              + len(rdata).to_bytes(2, "big") + rdata)
    assert parse_ptr_response(_response(0x1234, answer=answer), 0x1234) == "gw.example.com"


def test_nxdomain_is_none():
    assert parse_ptr_response(_response(7, rcode=3), 7) is None


def test_wrong_txid_is_none():
    assert parse_ptr_response(_response(7), 8) is None


def test_build_query_has_reversed_name():
    q = _build_query(IPv4Address("10.26.1.5"), 1)
    assert b"\x015\x011\x0226\x0210\x07in-addr\x04arpa\x00" in q
