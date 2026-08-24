from __future__ import annotations

import argparse
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


def test_parse_ecs_source_ip_decode_is_correct_but_no_longer_wired_into_discovery() -> None:
    # Real defect this test used to hide (found live during the pre-DoH
    # discovery-producer trace, owner-clarified): this test's own
    # previous version reconstructed `_parse_ecs_source_ip(packet) or
    # addr[0]` INLINE and asserted on that expression -- which reads as
    # "proving cmd_dns_observer's loop", but cmd_dns_observer's real loop
    # has not contained that expression since the "exact client identity"
    # fix (see cmd_dns_observer's own docstring): dnsdist's ECS source-
    # prefix is a global, deliberately-truncated privacy setting shared
    # with real upstream-forwarded ECS, so an address recovered this way
    # can only ever be a truncated prefix or, absent ECS, dnsdist's own
    # local/bridge address -- never a real client's exact identity. This
    # only proves _parse_ecs_source_ip's own decode is still correct as a
    # documented capability (still unit-tested above); it is
    # DELIBERATELY not exercised as an identity source anywhere in
    # cmd_dns_observer any more -- see
    # test_dns_observer_never_records_a_discovery_observation below for
    # the real, live proof of that.
    addr_bytes = socket.inet_aton("198.51.100.7")
    packet = _query_with_opt("teed-client.example", _ecs_option(1, addr_bytes, 32))
    assert ctl._parse_ecs_source_ip(packet) == "198.51.100.7"
    assert ctl._parse_ecs_source_ip(_query("no-ecs-client.example")) is None


def test_dns_observer_never_records_a_discovery_observation(tmp_path, monkeypatch) -> None:
    """Live functional proof (pre-DoH discovery-producer trace,
    owner-clarified): even a packet carrying a real, well-formed ECS
    option claiming an address that would have been recorded (truncated
    or not) under the old, retired behavior produces NO discovery
    observation -- cmd_dns_observer's loop answers every packet
    (TeeAction's own fire-and-forget contract) but has no code path left
    that writes to the discovery inbox at all. Runs the real server loop
    in a background thread against a real UDP socket, not a mock."""
    import threading
    import time as _time

    monkeypatch.setattr(ctl, "STATE_DIR", tmp_path)
    # cmd_dns_observer calls signal.signal(), which only works from a
    # real process's main thread -- harmless/no-op it here so the
    # function can run in this test's background thread instead of
    # needing a real subprocess just to prove packet-in/packet-out and
    # inbox-untouched behavior.
    monkeypatch.setattr(ctl.signal, "signal", lambda *a, **k: None)
    inbox = tmp_path / "discovery" / "inbox"

    args = argparse.Namespace(
        host="127.0.0.1", port=0, queue_capacity=64, flush_batch_size=64,
        flush_interval_seconds=0.1, max_packet_bytes=4096,
    )
    # cmd_dns_observer binds args.port itself; grab an ephemeral port
    # first the same way the real service would via port 0, then reuse it.
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    args.port = port

    t = threading.Thread(target=ctl.cmd_dns_observer, args=(args,), daemon=True)
    t.start()
    try:
        deadline = _time.monotonic() + 3.0
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)
        addr_bytes = socket.inet_aton("192.168.32.20")  # a real, exact address -- must still not be recorded
        packet = _query_with_opt("discovery-proof.example", _ecs_option(1, addr_bytes, 32))
        answered = False
        while _time.monotonic() < deadline and not answered:
            try:
                client.sendto(packet, ("127.0.0.1", port))
                client.recvfrom(512)
                answered = True
            except (ConnectionRefusedError, socket.timeout):
                _time.sleep(0.1)
        assert answered, "dns-observer never answered a real UDP packet on its bound port"
        _time.sleep(0.5)  # past one real flush_interval_seconds
        assert not inbox.exists() or not list(inbox.glob("*.jsonl")), (
            "dns-observer must never write a discovery-inbox file -- it is not a discovery producer"
        )
    finally:
        # cmd_dns_observer has no external stop hook other than a signal
        # (its own signal.signal() call only helps for a real top-level
        # process, not a thread); the thread is daemon=True so it does
        # not block test-process exit.
        pass


def test_dns_observer_malformed_packet_gets_formerr() -> None:
    response = ctl._dns_response(b"\x12\x34bad")

    assert response[:2] == b"\x12\x34"
    flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHH", response[2:12])
    assert flags & 0x8000
    assert flags & 0x000F == 1
    assert qdcount == 0
    assert ancount == 0
