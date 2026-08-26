#!/usr/bin/env python3
"""Writes one real, valid Parquet segment (same schema/compression as
app/v2/parquet_writer.py -- id/ts/client/client_name/domain/qtype/
protocol/rcode/latency_ms/blocked/block_reason/upstream/cache_status/
cache_profile_id, Zstandard-compressed) into the
YYYY/MM/DD/HH-<segment>.parquet layout enumerate_partition_files expects,
for a real (not mocked) end-to-end test of internal/rawquerylog against
actual production-shaped data.

Requires pyarrow -- run under dev/.venv-v2-bench, matching every other
Parquet-touching test in this repo (see app/v2/parquet_writer.py's own
doc comment: "Tests that exercise this module must run under the dev
benchmark venv").

Usage: dev/.venv-v2-bench/bin/python3 go/tests/fixtures/make_query_log_fixture.py <root-dir>
"""
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

_SCHEMA = pa.schema([
    ("id", pa.int64()),
    ("ts", pa.float64()),
    ("client", pa.string()),
    ("client_name", pa.string()),
    ("domain", pa.string()),
    ("qtype", pa.string()),
    ("protocol", pa.string()),
    ("rcode", pa.string()),
    ("latency_ms", pa.float64()),
    ("blocked", pa.bool_()),
    ("block_reason", pa.string()),
    ("upstream", pa.string()),
    ("cache_status", pa.string()),
    ("cache_profile_id", pa.string()),
])


def main():
    root = Path(sys.argv[1])
    now = datetime.now(timezone.utc)
    now_ts = time.time()

    rows = [
        {"id": 1, "ts": now_ts - 30, "client": "10.10.10.5", "client_name": "laptop", "domain": "acceptance-blocked.example.com.", "qtype": "A", "protocol": "udp", "rcode": "NXDOMAIN", "latency_ms": 0.8, "blocked": True, "block_reason": "test-list", "upstream": "acceptance-upstream", "cache_status": "miss", "cache_profile_id": "p1"},
        {"id": 2, "ts": now_ts - 20, "client": "10.10.10.6", "client_name": "phone", "domain": "acceptance-allowed.example.com.", "qtype": "AAAA", "protocol": "udp", "rcode": "NOERROR", "latency_ms": 1.5, "blocked": False, "block_reason": None, "upstream": "acceptance-upstream", "cache_status": "hit", "cache_profile_id": "p1"},
        {"id": 3, "ts": now_ts - 10, "client": "10.10.10.5", "client_name": "laptop", "domain": "acceptance-blocked.example.com.", "qtype": "A", "protocol": "tcp", "rcode": "NXDOMAIN", "latency_ms": 0.6, "blocked": True, "block_reason": "test-list", "upstream": "acceptance-upstream", "cache_status": "miss", "cache_profile_id": "p1"},
    ]
    table = pa.Table.from_pylist(rows, schema=_SCHEMA)

    day_dir = root / now.strftime("%Y") / now.strftime("%m") / now.strftime("%d")
    day_dir.mkdir(parents=True, exist_ok=True)
    out_path = day_dir / f"{now.strftime('%H')}-acceptance-fixture.parquet"
    pq.write_table(table, out_path, compression="zstd", compression_level=6)
    print(f"wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
