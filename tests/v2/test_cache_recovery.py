"""Cache recovery benchmark / power-loss tests (Workstream 3 final
continuation, Priority 4, §31-33): cold cache vs. Tier B prewarm, using a
real isolated dnsdist instance with a real packet cache attached, and an
abrupt (SIGKILL, not graceful) process termination proving DNS restart
independence from any warm state.
"""

from __future__ import annotations

import shutil
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from app.v2.dnsdist_cache_policy import render_packet_cache_setup
from app.v2.tier_b_prewarm import WorkingSetIndex, flush, load, run_prewarm
from app.v2.tier_b_worker import make_udp_resolve_fn
from tests.v2._network_probe import network_reachable

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None

# Real round-trip probe, not just route existence -- see
# docs/v2/handoff-workstream-6-cc-session.md.
pytestmark = pytest.mark.skipif(
    not (DNSDIST_INSTALLED and network_reachable()),
    reason="requires installed dnsdist and outbound network reachability",
)

_WORKING_SET = ["example.com", "cloudflare.com", "one.one.one.one", "iana.org", "wikipedia.org"]


def _pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_dnsdist(tmp_path: Path, port: int) -> subprocess.Popen:
    pc_lines = render_packet_cache_setup([""])
    conf = "\n".join(
        [
            f'setLocal("127.0.0.1:{port}")',
            'addACL("127.0.0.1/32")',
            'newServer({address="1.1.1.1:53"})',
            *pc_lines,
        ]
    )
    conf_path = tmp_path / "recovery.conf"
    conf_path.write_text(conf)
    proc = subprocess.Popen(
        ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)
    return proc


def _query_is_fast(port: int, qname: str, threshold_ms: float = 3.0) -> bool:
    """A query answered in under threshold_ms is almost certainly a local
    packet-cache hit, not a real upstream round-trip (cold queries in this
    environment measured ~14-23ms; see docs/v2/cache-hit-latency-
    investigation.md) -- used here as the hit/miss proxy signal."""
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    t0 = time.perf_counter()
    s.sendto(pkt, ("127.0.0.1", port))
    s.recvfrom(4096)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    s.close()
    return elapsed_ms < threshold_ms


class TestColdCacheRecovery:
    def test_fresh_instance_has_no_warm_entries(self, tmp_path):
        port = _pick_port()
        proc = _start_dnsdist(tmp_path, port)
        try:
            hits = sum(1 for d in _WORKING_SET if _query_is_fast(port, d))
            # A genuinely cold cache should show ~0 fast hits on first pass
            # (every query is a real upstream round-trip).
            assert hits == 0
        finally:
            proc.terminate()
            proc.wait(timeout=5)


class TestTierBPrewarmRecovery:
    def test_prewarm_before_traffic_gives_immediate_hits(self, tmp_path):
        port = _pick_port()
        proc = _start_dnsdist(tmp_path, port)
        try:
            # Simulate a persisted Tier B working-set index from before a
            # restart (recency/frequency-ranked hot domains).
            index = WorkingSetIndex()
            for d in _WORKING_SET:
                for _ in range(3):
                    index.record_query(d, "A", "profile-1")

            resolve = make_udp_resolve_fn("127.0.0.1", port, timeout=3.0)
            stats = run_prewarm(index.top(10), resolve, max_names_per_second=20.0)
            assert stats.succeeded == len(_WORKING_SET)

            # Now real "client" traffic for the same working set should be
            # fast (packet-cache hits) immediately, unlike the cold case.
            hits = sum(1 for d in _WORKING_SET if _query_is_fast(port, d))
            assert hits == len(_WORKING_SET)
        finally:
            proc.terminate()
            proc.wait(timeout=5)

    def test_recovery_comparison_cold_vs_prewarmed(self, tmp_path):
        # A vs B in one test for a direct, reproducible comparison rather
        # than relying on two separate test runs' timing being comparable.
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        port_a = _pick_port()
        proc_a = _start_dnsdist(tmp_path / "a", port_a)
        port_b = _pick_port()
        proc_b = _start_dnsdist(tmp_path / "b", port_b)
        try:
            index = WorkingSetIndex()
            for d in _WORKING_SET:
                index.record_query(d, "A", "profile-1")
            resolve_b = make_udp_resolve_fn("127.0.0.1", port_b, timeout=3.0)
            run_prewarm(index.top(10), resolve_b, max_names_per_second=20.0)

            hits_cold = sum(1 for d in _WORKING_SET if _query_is_fast(port_a, d))
            hits_warm = sum(1 for d in _WORKING_SET if _query_is_fast(port_b, d))
            assert hits_warm > hits_cold
        finally:
            proc_a.terminate()
            proc_a.wait(timeout=5)
            proc_b.terminate()
            proc_b.wait(timeout=5)


class TestAbruptPowerLoss:
    def test_sigkill_then_fresh_instance_answers_independently(self, tmp_path):
        port = _pick_port()
        proc = _start_dnsdist(tmp_path, port)
        # Abrupt termination -- SIGKILL, not terminate()/SIGTERM -- no
        # graceful shutdown hook runs at all.
        proc.send_signal(signal.SIGKILL)
        proc.wait(timeout=5)

        # DNS availability must not depend on any prior warm state: a
        # freshly started instance (simulating the restarted service)
        # must answer immediately.
        new_port = _pick_port()
        new_proc = _start_dnsdist(tmp_path, new_port)
        try:
            header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            qparts = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split("."))
            pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3)
            s.sendto(pkt, ("127.0.0.1", new_port))
            data, _ = s.recvfrom(4096)
            s.close()
            assert len(data) > 0
        finally:
            new_proc.terminate()
            new_proc.wait(timeout=5)

    def test_corrupt_tier_b_snapshot_degrades_to_cold_not_a_crash(self, tmp_path):
        snapshot_path = tmp_path / "tier_b_snapshot.json"
        snapshot_path.write_bytes(b"\x00\x01 not valid json at all {{{")
        index = load(snapshot_path)  # must never raise
        assert len(index) == 0

    def test_missing_tier_b_snapshot_degrades_to_cold_no_startup_block(self, tmp_path):
        index = load(tmp_path / "does-not-exist.json")
        assert len(index) == 0

    def test_no_stale_direct_trust_after_kill_mid_snapshot_write(self, tmp_path):
        # Simulate "killed mid-write": a snapshot file left in a
        # half-written state (no valid trailing JSON) must not be trusted.
        snapshot_path = tmp_path / "tier_b_snapshot.json"
        index = WorkingSetIndex()
        index.record_query("example.com", "A", "p1")
        flush(index, snapshot_path)
        good_bytes = snapshot_path.read_bytes()
        truncated = good_bytes[: len(good_bytes) // 2]
        snapshot_path.write_bytes(truncated)
        reloaded = load(snapshot_path)
        assert len(reloaded) == 0  # truncated/invalid -> cold, not a crash, not stale-trusted
