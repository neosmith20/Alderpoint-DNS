from __future__ import annotations

import struct

from scripts.v2 import alderpointdns_v2_ctl as ctl


def _query(name: str, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    return b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def test_dns_observer_parses_question_name() -> None:
    qname, qtype, qclass, question = ctl._parse_dns_qname(_query("client-one.example"))

    assert qname == "client-one.example"
    assert qtype == 1
    assert qclass == 1
    assert question.endswith(struct.pack("!HH", 1, 1))


def test_dns_observer_returns_minimal_a_answer() -> None:
    response = ctl._dns_response(_query("client-one.example"))

    assert response[:2] == b"\x12\x34"
    flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHH", response[2:12])
    assert flags & 0x8000
    assert qdcount == 1
    assert ancount == 1
    assert nscount == 0
    assert arcount == 0
    assert response.endswith(b"\xc0\x00\x02\x01")


def test_dns_observer_malformed_packet_gets_formerr() -> None:
    response = ctl._dns_response(b"\x12\x34bad")

    assert response[:2] == b"\x12\x34"
    flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHH", response[2:12])
    assert flags & 0x8000
    assert flags & 0x000F == 1
    assert qdcount == 0
    assert ancount == 0
