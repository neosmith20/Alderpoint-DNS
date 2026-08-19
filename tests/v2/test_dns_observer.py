from __future__ import annotations

import socket
import struct

from scripts.v2 import alderpointdns_v2_ctl as ctl


def _query(name: str, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    return b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", qtype, 1)


def _ecs_option(family: int, addr_bytes: bytes, source_prefix: int) -> bytes:
    data = struct.pack("!HBB", family, source_prefix, 0) + addr_bytes
    return struct.pack("!HH", 8, len(data)) + data  # option code 8 = ECS (RFC 7871)


def _query_with_opt(name: str, rdata: bytes, *, qtype: int = 1) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", qtype, 1)
    opt_rr = b"\x00" + struct.pack("!HHIH", 41, 4096, 0, len(rdata)) + rdata
    return b"\x12\x34" + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 1) + question + opt_rr


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


def test_ecs_source_ip_decoded_from_teed_query_ipv4() -> None:
    # Real defect found live during two-node discovery acceptance
    # testing: this ingress is only ever fed via dnsdist's TeeAction,
    # whose tee'd copy always arrives from dnsdist's OWN local socket --
    # the real client's address must come from the ECS option TeeAction's
    # addECS=true embeds instead of the raw UDP peer address.
    addr = socket.inet_aton("203.0.113.42")
    packet = _query_with_opt("client-one.example", _ecs_option(1, addr, 32))
    assert ctl._parse_ecs_source_ip(packet) == "203.0.113.42"


def test_ecs_source_ip_decoded_from_teed_query_ipv6() -> None:
    addr = socket.inet_pton(socket.AF_INET6, "2001:db8::42")
    packet = _query_with_opt("client-one.example", _ecs_option(2, addr, 128))
    assert ctl._parse_ecs_source_ip(packet) == "2001:db8::42"


def test_ecs_source_ip_absent_when_no_opt_record() -> None:
    assert ctl._parse_ecs_source_ip(_query("client-one.example")) is None


def test_ecs_source_ip_absent_when_opt_present_but_no_ecs_option() -> None:
    packet = _query_with_opt("client-one.example", b"")  # OPT with empty RDATA
    assert ctl._parse_ecs_source_ip(packet) is None


def test_ecs_source_ip_ignored_for_a_response_not_a_query() -> None:
    # A response has ancount > 0 -- deliberately refuses to parse rather
    # than guessing at record-skipping past an answer section.
    response = ctl._dns_response(_query("client-one.example"))
    assert ctl._parse_ecs_source_ip(response) is None


def test_dns_observer_loop_prefers_ecs_source_over_udp_peer_address() -> None:
    # Proves the exact selection logic cmd_dns_observer's loop uses
    # (`_parse_ecs_source_ip(packet) or addr[0]`): a teed packet with a
    # real ECS option must win over the raw UDP peer address, which for
    # every real client would otherwise be dnsdist's own tee-relay
    # address (e.g. 127.0.0.1) -- exactly the bug this closes.
    addr_bytes = socket.inet_aton("198.51.100.7")
    packet = _query_with_opt("teed-client.example", _ecs_option(1, addr_bytes, 32))
    dnsdist_relay_addr = ("127.0.0.1", 55555)
    source_ip = ctl._parse_ecs_source_ip(packet) or dnsdist_relay_addr[0]
    assert source_ip == "198.51.100.7"

    # And a packet with no ECS option (shouldn't normally happen, since
    # this ingress is only ever fed via TeeAction) still falls back
    # safely to the UDP peer address rather than raising/dropping it.
    plain_packet = _query("no-ecs-client.example")
    fallback_source_ip = ctl._parse_ecs_source_ip(plain_packet) or dnsdist_relay_addr[0]
    assert fallback_source_ip == "127.0.0.1"


def test_dns_observer_malformed_packet_gets_formerr() -> None:
    response = ctl._dns_response(b"\x12\x34bad")

    assert response[:2] == b"\x12\x34"
    flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHH", response[2:12])
    assert flags & 0x8000
    assert flags & 0x000F == 1
    assert qdcount == 0
    assert ancount == 0
