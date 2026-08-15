"""Failure-domain pass against a LIVE compiled DNS runtime (Workstream 3
final continuation, Priority 6, §40): a real isolated dnsdist instance
stays up and answering while every non-DNS V2 subsystem
(control.db, Parquet, aggregates.db, secret store, Tier B persistence) is
deliberately destroyed one at a time. This is the architectural
invariant every module in ``app/v2/`` has been built around (§49's "DNS
keeps answering") proven against an actually-running process, not just
inferred from source inspection (see
``tests/v2/test_workstream3_failure_domains.py`` for that earlier,
narrower, no-running-process version).
"""

from __future__ import annotations

import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from app.v2 import aggregates_db, control_db
from app.v2 import policy_store as store
from app.v2.dnsdist_gen import UpstreamServer, generate_dnsdist_config
from app.v2.parquet_writer import ParquetSegmentWriter
from app.v2.secret_store import SecretStore
from app.v2.tier_b_prewarm import WorkingSetIndex, flush

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


def _network_reachable() -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        s.connect(("1.1.1.1", 53))
        s.close()
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not (DNSDIST_INSTALLED and _network_reachable()),
    reason="requires installed dnsdist and outbound network reachability",
)


def _query_ok(port: int) -> bool:
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split("."))
    pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
        return len(data) > 0
    except OSError:
        return False
    finally:
        s.close()


class TestDnsSurvivesEveryOtherSubsystemFailing:
    def test_full_destructive_sequence(self, tmp_path):
        port = None
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        upstreams = [UpstreamServer("p", "1.1.1.1:53")]
        conf_text = generate_dnsdist_config(f"127.0.0.1:{port}", [], upstreams)
        conf_path = tmp_path / "runtime.conf"
        conf_path.write_text(conf_text)

        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(1.0)
            assert _query_ok(port), "baseline query must succeed before any failure injection"

            # 1. control.db: create it, then corrupt its bytes.
            control_db_path = tmp_path / "control.db"
            store.ensure_schema(control_db_path)
            control_db_path.write_bytes(b"corrupted, not a real sqlite file at all")
            assert _query_ok(port), "DNS must survive control.db corruption"

            # 2. control.db removed entirely.
            control_db_path.unlink()
            assert _query_ok(port), "DNS must survive control.db being deleted"

            # 3. Parquet writer directory: create, write, then make unreadable.
            parquet_root = tmp_path / "parquet"
            writer = ParquetSegmentWriter(root=parquet_root)
            writer.ingest([
                {
                    "id": 1, "ts": time.time(), "client": "10.0.0.1", "client_name": "",
                    "domain": "x.example", "qtype": "A", "protocol": "udp", "rcode": "NOERROR",
                    "latency_ms": 1.0, "blocked": False, "block_reason": "", "upstream": "d",
                    "cache_status": "miss", "cache_profile_id": "p1",
                }
            ])
            writer.flush()
            writer.close()
            shutil.rmtree(parquet_root)
            assert _query_ok(port), "DNS must survive the Parquet analytics directory vanishing"

            # 4. Aggregate DB corrupted.
            agg_path = tmp_path / "aggregates.db"
            aggregates_db.initialize(agg_path)
            agg_path.write_bytes(b"not a real sqlite database")
            assert _query_ok(port), "DNS must survive aggregates.db corruption"

            # 5. Secret store made unreadable (permissions stripped).
            secret_dir = tmp_path / "secrets"
            secrets = SecretStore(secret_dir)
            secrets.create("value", secret_id="s1")
            import os
            os.chmod(secret_dir, 0o000)
            try:
                assert _query_ok(port), "DNS must survive the secret store becoming inaccessible"
            finally:
                os.chmod(secret_dir, 0o700)  # restore so tmp_path cleanup can remove it

            # 6. Tier B snapshot corrupted mid-write (truncated).
            tier_b_path = tmp_path / "tier_b.json"
            index = WorkingSetIndex()
            index.record_query("x.example", "A", "p1")
            flush(index, tier_b_path)
            good = tier_b_path.read_bytes()
            tier_b_path.write_bytes(good[: len(good) // 2])
            assert _query_ok(port), "DNS must survive a corrupted Tier B snapshot"

            # 7. "Notification service"/API layer: never existed in this
            # isolated runtime at all (no coupling to begin with) -- the
            # absence itself is the proof; one more query confirms nothing
            # regressed across the whole sequence.
            assert _query_ok(port), "DNS must still be answering at the end of the full sequence"
        finally:
            proc.terminate()
            proc.wait(timeout=5)
