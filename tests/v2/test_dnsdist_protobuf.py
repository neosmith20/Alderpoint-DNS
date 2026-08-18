"""Regression tests for app/v2/dnsdist_protobuf.py, pinned against real
byte captures from a real, running dnsdist instance (not synthetic/
hand-crafted protobuf) -- see that module's own docstring for exactly
how these were captured and how each field number was empirically
verified, not guessed.

Capture setup: a real `dnsdist` (2.1.1) process, real config
(`newRemoteLogger("127.0.0.1:PORT")` +
`addAction(AllRule(), RemoteLogAction(rl))` +
`addResponseAction(AllRule(), RemoteLogResponseAction(rl))`), a real
`dig @127.0.0.1 -p 15353 pbtest.example.com A` / `example.com A` query
issued against it, and a real Python TCP server capturing the exact
length-prefixed bytes dnsdist sent.
"""

from __future__ import annotations

import pytest

from app.v2.dnsdist_protobuf import (
    DecodedQuery,
    DecodedResponse,
    ProtobufDecodeError,
    _client_ip,
    decode_message,
    read_framed_messages,
    walk_fields,
)

# Real captured query message (RemoteLogAction, pre-resolution), body
# only (2-byte length prefix already stripped) -- a real UDP query for
# "pbtest.example.com." A from 127.0.0.1.
REAL_QUERY_HEX = "08014885df8bd40650d9df1212109dfea3dbd3b2448490ac39e606e788f22001280132047f0000013a047f000001403b4885df8bd40650dadf1258869b0162190a137062746573742e6578616d706c652e636f6d2e10011801a001b7a802a801f977e00181406a0a2885df8bd40630c8df12"

# Real captured response message (RemoteLogResponseAction,
# post-resolution) for a real "example.com." A query, real NOERROR
# answer.
REAL_RESPONSE_HEX = "080248c8de8bd40650c0e61f1210b0112f355792454aa9c2f91660df5f602001280132047f0000013a047f000001404848c8de8bd40650c1e61f58e16c62120a0c6578616d706c652e636f6d2e10011801a00180c703a801f977e001818102d00100d801016a4428c8de8bd406308dc11e0800121a0a0c6578616d706c652e636f6d2e1001180120232a046814179a121a0a0c6578616d706c652e636f6d2e1001180120232a04ac4293f3"

# Real captured query message for a real domain that was configured to
# be terminally spoofed by a real SpoofAction rule -- no matching
# response message was ever sent for this query (verified: capturing
# the same real dnsdist session's full traffic showed only this one
# message for this qname, never a type=2 response) -- this is exactly
# what a real blocked-domain/SafeSearch/local-DNS answer looks like on
# the wire, the gap RemoteLogAction wiring closes.
REAL_SPOOFED_QUERY_ONLY_HEX = "080148858a8cd40650f983041210d6a510e5dda24d8385b29974f8f387cc2001280132047f0000013a047f000001403c48858a8cd40650fb830458c3c201621a0a1473706f6f6665642e6578616d706c652e636f6d2e10011801a00199fd02a801fb77e00181406a0a28858a8cd40630ca8304"

# A real query+response PAIR for the same real query (a real
# backend-forwarded, non-spoofed lookup), captured from the same real
# dnsdist session as REAL_SPOOFED_QUERY_ONLY_HEX above -- both carry the
# real DNS transaction id 54320, verified identical between the two by
# direct field-level decode.
REAL_MATCHED_QUERY_HEX = "080148868a8cd4065081ff0412106183df3a992f494bb0b1919f5340a0542001280132047f0000013a047f000001403f48868a8cd4065083ff0458b0a803621d0a177265616c2d636865636b2e6578616d706c652e636f6d2e10011801a001f6e802a801fb77e00181406a0a28868a8cd40630f1fe04"
REAL_MATCHED_RESPONSE_HEX = "080248868a8cd40650d2a10712106183df3a992f494bb0b1919f5340a0542001280132047f0000013a047f000001407148868a8cd40650d3a10758b0a803621d0a177265616c2d636865636b2e6578616d706c652e636f6d2e10011801a001f6e802a801fb77e00181c102d00100d801016a0c28868a8cd40630f1fe040800"

# Real evidence for the RC13 continuation's cache-hit finding
# (docs/v2/cache-hit-response-not-logged-rc13.md): a real cold query
# for a real NXDOMAIN-answering name, its real matched response
# (rcode=NXDOMAIN, DNS transaction id 27067 in both), and a second,
# later real query for the EXACT same qname/qtype (id 29238) with a
# real dnsdist packet cache attached -- captured live and confirmed
# this second query NEVER produced a matching response message at all
# (a full 25s real wait with no response), proving a packet-cache hit
# answers silently: the query-processing stage never invokes
# RemoteLogResponseAction the same way SpoofAction doesn't.
REAL_NXDOMAIN_QUERY_HEX = "080148a8948fd40650e1d32a12101c1c1013984c4aab8f5ad836394048702001280132047f0000013a047f000001404348a8948fd40650e4d32a58bbd30162210a1b6e78746573742d63616368652d636865636b2e696e76616c69642e10011801a001ec8603a801356a0a28a8948fd40630a4d32a"
REAL_NXDOMAIN_RESPONSE_HEX = "080248a8948fd40650c6df2b12101c1c1013984c4aab8f5ad836394048702001280132047f0000013a047f00000140820148a8948fd40650c8df2b58bbd30162210a1b6e78746573742d63616368652d636865636b2e696e76616c69642e10011801a001ec8603a801356a0c28a8948fd40630a4d32a0803"
REAL_CACHE_HIT_QUERY_ONLY_HEX = "080148aa948fd406508ed53512102fb91f7e0ad246f6919510db446d80732001280132047f0000013a047f000001404348aa948fd4065091d53558b6e40162210a1b6e78746573742d63616368652d636865636b2e696e76616c69642e10011801a001f6d603a801356a0a28aa948fd40630ffd435"


def test_real_captured_query_decodes_correct_qname_client_protocol():
    data = bytes.fromhex(REAL_QUERY_HEX)
    decoded = decode_message(data)
    assert isinstance(decoded, DecodedQuery)
    assert decoded.qname == "pbtest.example.com."
    assert decoded.qtype == "A"
    assert decoded.client == "127.0.0.1"
    assert decoded.protocol == "udp"
    assert decoded.ts > 1_700_000_000  # a real, sane unix timestamp


def test_real_captured_response_decodes_correct_rcode():
    data = bytes.fromhex(REAL_RESPONSE_HEX)
    decoded = decode_message(data)
    assert isinstance(decoded, DecodedResponse)
    assert decoded.qname == "example.com."
    assert decoded.qtype == "A"
    assert decoded.rcode == "NOERROR"
    assert decoded.client == "127.0.0.1"


def test_real_matched_query_and_response_share_the_same_real_transaction_id():
    q = decode_message(bytes.fromhex(REAL_MATCHED_QUERY_HEX))
    r = decode_message(bytes.fromhex(REAL_MATCHED_RESPONSE_HEX))
    assert isinstance(q, DecodedQuery)
    assert isinstance(r, DecodedResponse)
    assert q.qname == r.qname == "real-check.example.com."
    assert q.msg_id == r.msg_id == 54320


def test_real_spoofed_query_decodes_with_no_response_counterpart():
    # This is exactly the message dnsdist sends for a terminally
    # spoofed query -- it decodes cleanly as a query-type message on
    # its own; there is deliberately no corresponding response fixture
    # because dnsdist never sent one for this real query.
    decoded = decode_message(bytes.fromhex(REAL_SPOOFED_QUERY_ONLY_HEX))
    assert isinstance(decoded, DecodedQuery)
    assert decoded.qname == "spoofed.example.com."
    assert decoded.msg_id != 54320  # a different real query, different id


def test_walk_fields_never_raises_on_the_real_captured_bytes():
    # Every top-level field in a real message must be walkable even
    # though this module only interprets a handful of them.
    for hexdata in (REAL_QUERY_HEX, REAL_RESPONSE_HEX):
        fields = list(walk_fields(bytes.fromhex(hexdata)))
        assert len(fields) > 5


class TestMalformedInputRejectedNotGuessed:
    def test_empty_message_rejected(self):
        with pytest.raises(ProtobufDecodeError):
            decode_message(b"")

    def test_truncated_varint_rejected(self):
        with pytest.raises(ProtobufDecodeError):
            decode_message(b"\x08\x80\x80\x80\x80\x80\x80\x80\x80\x80")

    def test_length_delimited_field_exceeding_message_bounds_rejected(self):
        # tag for field 1 wire-type 2, declared length 200, but no data
        with pytest.raises(ProtobufDecodeError):
            decode_message(b"\x0a\xc8\x01")

    def test_message_missing_required_fields_rejected_not_defaulted(self):
        # A syntactically-valid but semantically-empty message (just a
        # type field) must be rejected, never silently turned into a
        # fabricated event with empty/placeholder qname.
        with pytest.raises(ProtobufDecodeError):
            decode_message(b"\x08\x01")

    def test_truncated_message_at_the_socket_framing_layer(self):
        chunks = [b"\x00", b""]  # 2-byte length header itself never arrives

        def fake_recv(n):
            return chunks.pop(0) if chunks else b""

        assert read_framed_messages(fake_recv) == b""

    def test_connection_closed_mid_message_body_raises_not_silent(self):
        chunks = [b"\x00\x10", b"short", b""]  # declares 16 bytes, gets 5 then EOF

        def fake_recv(n):
            return chunks.pop(0) if chunks else b""

        with pytest.raises(ProtobufDecodeError, match="closed mid-message"):
            read_framed_messages(fake_recv)


def test_real_framing_round_trip_from_the_actual_captured_bytes():
    # Reconstruct the real 2-byte-length-prefixed wire stream exactly as
    # dnsdist sent it and prove read_framed_messages recovers the
    # identical message bytes.
    import struct

    body = bytes.fromhex(REAL_QUERY_HEX)
    stream = struct.pack(">H", len(body)) + body
    pos = [0]

    def fake_recv(n):
        chunk = stream[pos[0]:pos[0] + n]
        pos[0] += len(chunk)
        return chunk

    recovered = read_framed_messages(fake_recv)
    assert recovered == body
    decoded = decode_message(recovered)
    assert decoded.qname == "pbtest.example.com."


class TestClientIpDecode:
    def test_ipv4_four_raw_bytes(self):
        assert _client_ip(bytes([127, 0, 0, 1])) == "127.0.0.1"

    def test_ipv6_sixteen_raw_bytes(self):
        # Real defect-closing regression: previously only the IPv4 case
        # (4 raw bytes) had been independently verified against real
        # traffic; the IPv6 branch (16 raw bytes) was implemented per
        # PowerDNS's published schema but not confirmed against a real
        # query. Live-verified during the RC13 continuation (see
        # docs/v2/ipv6-client-decode-rc13.md): a real `dig -6 @::1`
        # query through the real installed package produced this exact
        # 16-byte wire encoding of "::1" (15 zero bytes then 0x01), and
        # the receiver's real analytics event showed `"client":"::1"`.
        raw = bytes([0] * 15 + [1])
        assert _client_ip(raw) == "::1"

    def test_unexpected_length_raises_not_silent(self):
        with pytest.raises(ProtobufDecodeError, match="unexpected 'from' address length"):
            _client_ip(b"\x01\x02\x03")
