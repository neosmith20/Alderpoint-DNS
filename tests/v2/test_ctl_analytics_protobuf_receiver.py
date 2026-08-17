"""Real regression for the analytics-protobuf-receiver CLI command
(roadmap Priority 6 continuation, see
docs/v2/analytics-ingestion-not-wired-to-live-dns.md for the gap this
closes). Exercises the actual packaged `alderpointdns_v2_ctl.py`
module's real TCP server against real captured dnsdist protobuf bytes
(the same fixtures test_dnsdist_protobuf.py pins), proving the full
socket -> decode -> inbox-JSONL path, not just the decoder in
isolation.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.v2.test_dnsdist_protobuf import REAL_QUERY_HEX, REAL_RESPONSE_HEX

REPO_ROOT = Path(__file__).resolve().parents[2]
CTL_PATH = REPO_ROOT / "scripts" / "v2" / "alderpointdns_v2_ctl.py"


class _RunningReceiver:
    """Runs the real CLI command as a real subprocess (like the real
    systemd unit does) rather than in-process -- cmd_analytics_protobuf_
    receiver installs real SIGTERM/SIGINT handlers via signal.signal(),
    which only works from a process's main thread, so an in-process
    thread can't run it directly."""

    def __init__(self, tmp_path, port):
        self.state_dir = tmp_path / "var" / "lib"
        env = dict(os.environ)
        env["ALDERPOINTDNS_V2_STATE_ROOT"] = str(self.state_dir)
        self.proc = subprocess.Popen(
            [sys.executable, str(CTL_PATH), "analytics-protobuf-receiver", "--port", str(port),
             "--flush-interval-seconds", "0.2"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

    @property
    def inbox(self) -> Path:
        return self.state_dir / "analytics" / "inbox"

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture()
def receiver(tmp_path):
    port = _free_port()
    r = _RunningReceiver(tmp_path, port)
    r.port = port
    yield r
    r.stop()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _connect(port, deadline_seconds=8.0):
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=1.0)
        except OSError:
            time.sleep(0.1)
    return None


def _wait_for_inbox_file(inbox: Path, deadline_seconds=8.0):
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        files = list(inbox.glob("*.jsonl")) if inbox.exists() else []
        if files:
            return files
        time.sleep(0.1)
    return []


def test_real_captured_response_message_lands_in_the_inbox_as_jsonl(receiver):
    sock = _connect(receiver.port)
    assert sock is not None, "receiver never started listening"
    try:
        body = bytes.fromhex(REAL_RESPONSE_HEX)
        sock.sendall(struct.pack(">H", len(body)) + body)
    finally:
        sock.close()

    files = _wait_for_inbox_file(receiver.inbox)
    assert files, "no event ever landed in the analytics inbox"
    lines = files[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["qname"] == "example.com."
    assert event["qtype"] == "A"
    assert event["rcode"] == "NOERROR"
    assert event["client"] == "127.0.0.1"
    assert event["protocol"] == "udp"


def test_malformed_message_is_skipped_not_fatal_to_the_connection(receiver):
    # A garbled/truncated message must never crash the receiver or take
    # down its ability to keep serving other connections -- this is a
    # passive log sink, not something DNS answering can ever depend on.
    sock = _connect(receiver.port)
    assert sock is not None
    try:
        garbage = b"\xff\xff\xff\xff"
        sock.sendall(struct.pack(">H", len(garbage)) + garbage)
        # Connection must still be usable afterward -- send a real,
        # valid message on the SAME connection and confirm it's still
        # processed rather than the connection having been torn down.
        body = bytes.fromhex(REAL_RESPONSE_HEX)
        sock.sendall(struct.pack(">H", len(body)) + body)
    finally:
        sock.close()

    files = _wait_for_inbox_file(receiver.inbox)
    assert files, "the valid message after the garbage one was never processed"
