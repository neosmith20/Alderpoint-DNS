#!/usr/bin/env python3
"""V1.1.1 runtime performance baseline capture (Workstream 2, §1).

Safe/bounded/local: queries only 127.0.0.1:53 (dnsdist's own listener), uses
small synthetic query counts, and does not touch any file under
/etc/alderpointdns or /var/lib/alderpointdns except read-only stat/size
checks. No config/service changes. Meant to be run once to produce
docs/v2/v1-performance-baseline.md's numbers, not as a load test.
"""
from __future__ import annotations

import json
import random
import socket
import statistics
import subprocess
import time
from pathlib import Path

RESOLVER = "127.0.0.1"


def _dig_query(name: str, qtype: str = "A") -> float | None:
    """One query via dig +time-only; returns latency in ms, or None on failure."""
    t0 = time.perf_counter()
    proc = subprocess.run(
        ["dig", f"@{RESOLVER}", name, qtype, "+timeout=2", "+tries=1", "+noall", "+stats"],
        capture_output=True, text=True, timeout=5,
    )
    t1 = time.perf_counter()
    if proc.returncode != 0:
        return None
    return (t1 - t0) * 1000.0


def _percentiles(values: list[float]) -> dict:
    if not values:
        return {}
    s = sorted(values)
    def pct(p):
        idx = min(len(s) - 1, int(len(s) * p))
        return round(s[idx], 3)
    return {
        "min": round(s[0], 3), "p50": pct(0.50), "p95": pct(0.95),
        "p99": pct(0.99), "max": round(s[-1], 3),
        "mean": round(statistics.mean(s), 3),
    }


def measure_uncached(n: int = 100) -> dict:
    # Unique random subdomains under a real, resolvable domain so each query
    # is genuinely a cache miss requiring upstream recursion, without hitting
    # a nonexistent-domain (NXDOMAIN-fast-path) shortcut.
    latencies = []
    for _ in range(n):
        label = f"baseline-{random.randint(0, 10**9)}.wikipedia.org"
        lat = _dig_query(label, "A")
        if lat is not None:
            latencies.append(lat)
    return {"n_ok": len(latencies), "n_requested": n, **_percentiles(latencies)}


def measure_cached(n: int = 100, domain: str = "example.com") -> dict:
    # Prime the cache, then measure repeated lookups of the same name.
    _dig_query(domain, "A")
    time.sleep(0.05)
    latencies = []
    for _ in range(n):
        lat = _dig_query(domain, "A")
        if lat is not None:
            latencies.append(lat)
    return {"n_ok": len(latencies), "n_requested": n, "domain": domain, **_percentiles(latencies)}


def measure_qps(duration_s: float = 5.0, domain: str = "example.com") -> dict:
    # Bounded single-process synthetic QPS via raw UDP queries (dnspython not
    # assumed present) — a simple hand-rolled A-record query is enough to
    # measure the transport+cache path without an extra dependency.
    import struct

    def build_query(qname: str, qid: int) -> bytes:
        header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
        qparts = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
        question = qparts + b"\x00" + struct.pack(">HH", 1, 1)  # A, IN
        return header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    sent = 0
    received = 0
    t_end = time.perf_counter() + duration_s
    qid = 0
    while time.perf_counter() < t_end:
        qid = (qid + 1) % 65536
        pkt = build_query(domain, qid)
        sock.sendto(pkt, (RESOLVER, 53))
        sent += 1
        try:
            sock.recvfrom(4096)
            received += 1
        except socket.timeout:
            pass
    sock.close()
    elapsed = duration_s
    return {
        "sent": sent, "received": received,
        "qps_sent": round(sent / elapsed, 1),
        "qps_received": round(received / elapsed, 1),
    }


def measure_resources() -> dict:
    out = {}
    for svc in ["alderpointdns.service", "alderpointdns-analytics.service", "dnsdist.service", "bind9.service", "named.service"]:
        proc = subprocess.run(
            ["systemctl", "show", svc, "-p", "MainPID", "-p", "MemoryCurrent", "-p", "ActiveState"],
            capture_output=True, text=True,
        )
        d = dict(line.split("=", 1) for line in proc.stdout.strip().splitlines() if "=" in line)
        out[svc] = d
    ps = subprocess.run(
        ["ps", "-eo", "pid,rss,pcpu,comm"], capture_output=True, text=True
    ).stdout
    interesting = [l for l in ps.splitlines() if any(k in l for k in ("named", "dnsdist", "uvicorn", "python3"))]
    out["ps_snapshot"] = interesting
    mem = subprocess.run(["free", "-b"], capture_output=True, text=True).stdout
    out["free"] = mem
    return out


def measure_storage() -> dict:
    out = {}
    db = Path("/var/lib/alderpointdns/alderpointdns.db")
    if db.exists():
        out["db_bytes"] = db.stat().st_size
    for suffix in ("-wal", "-shm"):
        p = Path(str(db) + suffix)
        if p.exists():
            out[f"db{suffix}_bytes"] = p.stat().st_size
    du = subprocess.run(["du", "-sb", "/var/lib/alderpointdns"], capture_output=True, text=True).stdout
    out["var_lib_alderpointdns_du"] = du.strip()
    df = subprocess.run(["df", "-B1", "/"], capture_output=True, text=True).stdout
    out["disk_df"] = df.strip()
    return out


def measure_db_analytics() -> dict:
    """Read-only sqlite queries for row counts / representative query latency."""
    import sqlite3
    out = {}
    uri = "file:/var/lib/alderpointdns/alderpointdns.db?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        for table in ("query_events", "analytics_events"):
            try:
                t0 = time.perf_counter()
                row = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
                t1 = time.perf_counter()
                out[f"{table}_count"] = row[0]
                out[f"{table}_count_query_ms"] = round((t1 - t0) * 1000, 2)
            except sqlite3.OperationalError as exc:
                out[f"{table}_error"] = str(exc)
        # representative "recent page" style query, if the table exists
        try:
            t0 = time.perf_counter()
            conn.execute(
                "SELECT * FROM query_events ORDER BY id DESC LIMIT 50"
            ).fetchall()
            t1 = time.perf_counter()
            out["recent_page_query_ms"] = round((t1 - t0) * 1000, 2)
        except sqlite3.OperationalError as exc:
            out["recent_page_error"] = str(exc)
        conn.close()
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
    return out


def main() -> None:
    result = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "dns_uncached": measure_uncached(80),
        "dns_cached": measure_cached(80),
        "dns_qps_5s": measure_qps(5.0),
        "resources": measure_resources(),
        "storage": measure_storage(),
        "db_analytics": measure_db_analytics(),
    }
    out_path = Path(__file__).resolve().parent / "baseline-result.json"
    out_path.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
