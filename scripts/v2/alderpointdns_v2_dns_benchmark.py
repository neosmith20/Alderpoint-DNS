#!/usr/bin/env python3
"""Safe DNS performance benchmark for Alderpoint DNS V2."""

from __future__ import annotations

import argparse
import sqlite3
import time
from pathlib import Path

from app.v2.dns_performance import BenchmarkCase, REPORT_PATH, run_benchmark, save_report


def _first_local_dns(control_db: Path) -> str:
    try:
        conn = sqlite3.connect(control_db)
        row = conn.execute("SELECT name FROM local_dns_records WHERE enabled=1 ORDER BY updated_at DESC LIMIT 1").fetchone()
        if row and row[0]:
            return str(row[0]).rstrip(".") + "."
    except sqlite3.Error:
        pass
    return "localhost."


def _first_blocked(compiled_root: Path) -> str:
    for path in sorted((compiled_root / "compiled" / "blocked-domains").glob("*.txt")):
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                value = line.strip().strip(".")
                if value and len(value) < 180 and " " not in value:
                    return value + "."
        except OSError:
            continue
    return "0--0.info."


def build_cases(args: argparse.Namespace) -> list[BenchmarkCase]:
    state = Path(args.state_root)
    control_db = state / "control.db"
    local_domain = args.local_domain or _first_local_dns(control_db)
    blocked_domain = args.blocked_domain or _first_blocked(state)
    unique = f"apdns-cold-{int(time.time())}.example.com."
    q = max(1, int(args.queries))
    hot = max(1, int(args.hot_queries))
    encrypted = max(1, int(args.encrypted_queries))
    return [
        BenchmarkCase("Local DNS answer", "alderpoint-controlled", args.server, args.port, local_domain, 1, "udp", q),
        BenchmarkCase("Local DNS answer TCP", "alderpoint-controlled", args.server, args.port, local_domain, 1, "tcp", q),
        BenchmarkCase("Filtering/block answer", "alderpoint-controlled", args.server, args.port, blocked_domain, 1, "udp", q),
        BenchmarkCase("Filtering/block answer TCP", "alderpoint-controlled", args.server, args.port, blocked_domain, 1, "tcp", q),
        BenchmarkCase("dnsdist/BIND hot A response", "hot-cache/client-observed", args.server, args.port, args.hot_domain, 1, "udp", hot),
        BenchmarkCase("dnsdist/BIND hot AAAA response", "hot-cache/client-observed", args.server, args.port, args.hot_domain, 28, "udp", hot),
        BenchmarkCase("BIND direct hot A response", "backend-cache/direct-bind", args.bind_server, args.bind_port, args.hot_domain, 1, "udp", hot, 0.2),
        BenchmarkCase("NXDOMAIN negative-cache hit", "hot-cache/client-observed", args.server, args.port, args.nxdomain, 1, "udp", hot),
        BenchmarkCase("DNSSEC-valid response", "external-or-cache/client-observed", args.server, args.port, args.dnssec_domain, 1, "udp", max(10, q // 2)),
        BenchmarkCase("Large response TCP", "external-or-cache/client-observed", args.server, args.port, args.large_domain, 16, "tcp", max(10, q // 5)),
        BenchmarkCase("DoT initial TLS query", "encrypted-dns/initial-handshake", args.server, args.dot_port, args.hot_domain, 1, "dot", max(10, encrypted // 10)),
        BenchmarkCase("DoT established query", "encrypted-dns/established-connection", args.server, args.dot_port, args.hot_domain, 1, "dot-established", encrypted),
        BenchmarkCase("DoH initial TLS query", "encrypted-dns/initial-handshake", args.server, args.doh_port, args.hot_domain, 1, "doh", max(10, encrypted // 10), 2.0, args.doh_path),
        BenchmarkCase("DoH established query", "encrypted-dns/established-connection", args.server, args.doh_port, args.hot_domain, 1, "doh-established", encrypted, 2.0, args.doh_path),
        BenchmarkCase("Cold unique forwarded lookup", "cold-external/client-observed", args.server, args.port, unique, 1, "udp", max(3, int(args.cold_queries))),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--bind-server", default="127.0.0.1")
    parser.add_argument("--bind-port", type=int, default=5453)
    parser.add_argument("--state-root", default="/var/lib/alderpointdns-v2")
    parser.add_argument("--output", default=str(REPORT_PATH))
    parser.add_argument("--dot-port", type=int, default=853)
    parser.add_argument("--doh-port", type=int, default=9443)
    parser.add_argument("--doh-path", default="/dns-query")
    parser.add_argument("--queries", type=int, default=10000)
    parser.add_argument("--hot-queries", type=int, default=10000)
    parser.add_argument("--encrypted-queries", type=int, default=1000)
    parser.add_argument("--cold-queries", type=int, default=10)
    parser.add_argument("--local-domain", default="")
    parser.add_argument("--blocked-domain", default="")
    parser.add_argument("--hot-domain", default="example.com.")
    parser.add_argument("--nxdomain", default="definitely-nx-apdns.invalid.")
    parser.add_argument("--dnssec-domain", default="cloudflare.com.")
    parser.add_argument("--large-domain", default="org.")
    args = parser.parse_args()
    report = run_benchmark(build_cases(args))
    save_report(report, Path(args.output))
    print(Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
