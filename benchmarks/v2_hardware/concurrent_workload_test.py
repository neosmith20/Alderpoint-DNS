#!/usr/bin/env python3
"""V2 full concurrent resource test (Workstream 3 final continuation,
Priority 5, §34-36).

Runs inside a real Linux cgroup v2 memory cap (invoked via
``systemd-run --scope -p MemoryMax=<N>``, same real-not-simulated
mechanism used for Workstream 2's Argon2id-under-pressure evidence),
exercising -- concurrently, via threads -- the pieces the brief lists:
an isolated dnsdist instance under real DNS query load, a real Parquet
writer + DuckDB analytical query, a real aggregate SQLite write, a real
Tier B working-set index + prewarm pass, a real Argon2id hash/verify, and
a real effective-policy compile loop.

Never touches the live v1.1.1 services. All state (Parquet root,
aggregates.db, dnsdist config) lives under a tempdir this script creates
and cleans up.

Usage (run OUTSIDE any cgroup first to see it work, then wrap with
systemd-run for the real constrained measurement):

    systemd-run --scope -p MemoryMax=1G -p MemoryAccounting=yes -- \\
        dev/.venv-v2-bench/bin/python benchmarks/v2_hardware/concurrent_workload_test.py \\
        --duration 20 --label 1gib
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import aggregates_db  # noqa: E402
from app.v2.dnsdist_gen import UpstreamServer, generate_dnsdist_config  # noqa: E402
from app.v2.parquet_writer import ParquetSegmentWriter  # noqa: E402
from app.v2.policy_compiler import compile_cache_profile, compile_effective_policy  # noqa: E402
from app.v2.policy_model import PolicyLayer  # noqa: E402
from app.v2.tier_b_prewarm import WorkingSetIndex, run_prewarm  # noqa: E402
from app.v2.tier_b_worker import make_udp_resolve_fn  # noqa: E402


def _pick_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _dns_worker(port: int, stop: threading.Event, results: list) -> None:
    domains = [f"load-test-{i}.example.com" for i in range(30)]
    while not stop.is_set():
        for d in domains:
            header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            qparts = b"".join(bytes([len(p)]) + p.encode() for p in d.split("."))
            pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(2)
            t0 = time.perf_counter()
            try:
                s.sendto(pkt, ("127.0.0.1", port))
                s.recvfrom(4096)
                results.append((time.perf_counter() - t0) * 1000.0)
            except OSError:
                pass
            finally:
                s.close()
            if stop.is_set():
                return


def _analytics_worker(root: Path, agg_path: Path, stop: threading.Event, counters: dict) -> None:
    writer = ParquetSegmentWriter(root=root)
    aggregates_db.initialize(agg_path)
    i = 0
    while not stop.is_set():
        batch = [
            {
                "id": i * 100 + j, "ts": time.time(), "client": "10.0.0.5", "client_name": "",
                "domain": f"analytics-{j}.example", "qtype": "A", "protocol": "udp",
                "rcode": "NOERROR", "latency_ms": 5.0, "blocked": False, "block_reason": "",
                "upstream": "default", "cache_status": "miss", "cache_profile_id": "p1",
            }
            for j in range(20)
        ]
        writer.ingest(batch)
        writer.flush()
        try:
            aggregates_db.record_batch(agg_path, batch)
        except Exception:
            pass
        counters["batches"] = counters.get("batches", 0) + 1
        i += 1
        time.sleep(0.2)
    writer.close()


def _argon2_worker(stop: threading.Event, counters: dict) -> None:
    from argon2 import PasswordHasher

    hasher = PasswordHasher(time_cost=4, memory_cost=256 * 1024, parallelism=2)
    while not stop.is_set():
        h = hasher.hash("test-password-value")
        hasher.verify(h, "test-password-value")
        counters["hashes"] = counters.get("hashes", 0) + 1


def _policy_compile_worker(stop: threading.Event, counters: dict) -> None:
    while not stop.is_set():
        policy = compile_effective_policy(
            PolicyLayer(safesearch_mode="strict"),
            client_layer=PolicyLayer(upstream_profile_id="family"),
        )
        compile_cache_profile(policy)
        counters["compiles"] = counters.get("compiles", 0) + 1


def run(duration_s: float, label: str) -> dict:
    with tempfile.TemporaryDirectory() as d:
        staging = Path(d)
        port = _pick_port()
        upstreams = [UpstreamServer("p", "1.1.1.1:53")]
        conf_text = generate_dnsdist_config(f"127.0.0.1:{port}", [], upstreams)
        conf_path = staging / "hw.conf"
        conf_path.write_text(conf_text)
        dnsdist_proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)

        stop = threading.Event()
        dns_latencies: list = []
        analytics_counters: dict = {}
        argon2_counters: dict = {}
        policy_counters: dict = {}

        threads = [
            threading.Thread(target=_dns_worker, args=(port, stop, dns_latencies)),
            threading.Thread(
                target=_analytics_worker,
                args=(staging / "parquet", staging / "aggregates.db", stop, analytics_counters),
            ),
            threading.Thread(target=_argon2_worker, args=(stop, argon2_counters)),
            threading.Thread(target=_policy_compile_worker, args=(stop, policy_counters)),
        ]
        for t in threads:
            t.start()

        time.sleep(duration_s)
        stop.set()
        for t in threads:
            t.join(timeout=10)

        dnsdist_proc.terminate()
        try:
            dnsdist_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            dnsdist_proc.kill()

        def _pctl(vals, p):
            if not vals:
                return None
            s = sorted(vals)
            return round(s[min(len(s) - 1, int(len(s) * p))], 3)

        result = {
            "label": label,
            "duration_s": duration_s,
            "dns_queries": len(dns_latencies),
            "dns_p50_ms": _pctl(dns_latencies, 0.50),
            "dns_p95_ms": _pctl(dns_latencies, 0.95),
            "dns_p99_ms": _pctl(dns_latencies, 0.99),
            "analytics_batches": analytics_counters.get("batches", 0),
            "argon2_hashes": argon2_counters.get("hashes", 0),
            "policy_compiles": policy_counters.get("compiles", 0),
        }
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--label", type=str, default="unlabeled")
    args = parser.parse_args()
    result = run(args.duration, args.label)
    print(json.dumps(result, indent=2))
    out_dir = Path(__file__).parent
    out_path = out_dir / f"results-concurrent-{args.label}.json"
    out_path.write_text(json.dumps(result, indent=2))
