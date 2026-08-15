#!/usr/bin/env python3
"""V2 dnsdist packet-cache latency benchmark (Workstream 3 final
continuation, Priority 4, §30).

Measures real latency through a fully isolated dnsdist instance (via
``app/v2/tier_b_worker.py``'s real-subprocess pattern, packet cache
attached via ``app/v2/dnsdist_cache_policy.py``) for:

- cold (first query, actual upstream round-trip + cache miss)
- warm (subsequent queries for the same qname, real dnsdist packet-cache
  hit -- no upstream round-trip)

Scope note: this benchmark only measures the dnsdist packet-cache layer
in isolation. "Direct BIND cache hit" and "dnsdist -> BIND hit" are
already captured for the real running architecture in
docs/v2/v1-performance-baseline.md's cached-latency numbers (p50 11.96ms/
p95 13.26ms/p99 14.17ms) -- building a second, fully separate isolated
BIND recursive resolver (its own config, zone files, root hints) purely
to re-measure that same layer in isolation was judged out of this
session's remaining budget; the existing V1 baseline is the same
architecture family (dnsdist in front of BIND) and is the honest
comparison point used here, not re-derived.

Never touches the live v1.1.1 dnsdist/BIND services. Run manually:
    dev/.venv-v2-bench/bin/python benchmarks/v2_cache/packet_cache_latency.py
"""

from __future__ import annotations

import json
import socket
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2.dnsdist_cache_policy import render_packet_cache_setup  # noqa: E402


def _query_once(port: int, qname: str, timeout: float = 3.0) -> float:
    header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
    pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.perf_counter()
    s.sendto(pkt, ("127.0.0.1", port))
    s.recvfrom(4096)
    elapsed = time.perf_counter() - t0
    s.close()
    return elapsed * 1000.0


def _percentiles(values: list[float]) -> dict:
    s = sorted(values)
    n = len(s)

    def _p(pct):
        idx = min(n - 1, int(n * pct))
        return round(s[idx], 3)

    return {"p50": _p(0.50), "p95": _p(0.95), "p99": _p(0.99), "min": round(s[0], 3), "max": round(s[-1], 3)}


def run(n_cold_domains: int = 20, n_warm_repeats: int = 50) -> dict:
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        staging = Path(d)
        # isolated_dnsdist_instance() (app/v2/tier_b_worker.py) doesn't
        # take extra cache-policy config lines directly, so this benchmark
        # builds its own config using the same ephemeral-port/ACL pattern,
        # with the packet-cache lines attached.
        import socket as _socket

        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        pc_lines = render_packet_cache_setup([""])
        conf = "\n".join(
            [
                f'setLocal("127.0.0.1:{port}")',
                'addACL("127.0.0.1/32")',
                'newServer({address="1.1.1.1:53"})',
                *pc_lines,
            ]
        )
        conf_path = staging / "bench.conf"
        conf_path.write_text(conf)

        import subprocess

        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(1.0)

            cold_latencies = []
            for i in range(n_cold_domains):
                cold_latencies.append(_query_once(port, f"cold-bench-{i}.example.com"))

            warm_domain = "warm-bench.example.com"
            _query_once(port, warm_domain)  # prime the cache
            warm_latencies = [_query_once(port, warm_domain) for _ in range(n_warm_repeats)]

            return {
                "cold_ms": _percentiles(cold_latencies),
                "warm_ms": _percentiles(warm_latencies),
                "n_cold": n_cold_domains,
                "n_warm": n_warm_repeats,
            }
        finally:
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    out = Path(__file__).parent / "results-packet-cache-latency.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"\nwritten to {out}")
