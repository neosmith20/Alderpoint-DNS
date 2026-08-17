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
