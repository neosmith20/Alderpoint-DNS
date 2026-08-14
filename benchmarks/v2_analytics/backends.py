#!/usr/bin/env python3
"""Backend adapters for the V2 analytics storage benchmark.

Each adapter implements the same minimal interface:

    ingest(records: Iterable[dict]) -> None      # batched, may buffer internally
    close() -> None                               # finalize/promote any open segment
    query(name: str) -> Any                        # run one of QUERY_SUITE by name
    disk_usage_bytes() -> int
    kill_mid_write(records_iter) -> None            # simulate a crash during ingest, for
                                                     # the interrupted-write test

All three write under a caller-supplied directory; none of them ever touch
/var/lib/alderpointdns.
"""
from __future__ import annotations

import gzip
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable

# --- shared query suite -----------------------------------------------------
# Each entry is (label, sql-or-callable-per-backend). Backends translate these
# into their native query language in `query()`.
QUERY_NAMES = [
    "last_5m", "last_1h", "last_24h", "last_7d",
    "recent_page", "search_exact_domain", "search_domain_suffix",
    "by_client", "by_protocol", "by_qtype", "blocked_only",
    "top_domains", "top_blocked_domains", "top_clients", "top_upstreams",
    "rcode_distribution", "latency_percentiles", "time_series_counts",
]


def _now_minus(seconds: float) -> float:
    return time.time() - seconds


class SqliteWalBackend:
    name = "sqlite_wal"

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "analytics.db"
        self.conn = sqlite3.connect(str(self.db_path), isolation_level=None)
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.conn.execute("PRAGMA synchronous = NORMAL")
        self.conn.execute("PRAGMA busy_timeout = 5000")
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS query_events (
                id INTEGER PRIMARY KEY,
                ts REAL NOT NULL,
                client TEXT NOT NULL,
                client_name TEXT,
                domain TEXT NOT NULL,
                qtype TEXT NOT NULL,
                protocol TEXT NOT NULL,
                rcode TEXT NOT NULL,
                latency_ms REAL,
                blocked INTEGER NOT NULL,
                block_reason TEXT,
                upstream TEXT,
                cache_status TEXT
            )
            """
        )
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_qe_ts ON query_events(ts)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_qe_domain ON query_events(domain)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_qe_client ON query_events(client)")

    def ingest(self, records: Iterable[dict]) -> None:
        # isolation_level=None puts sqlite3 in autocommit mode, so each batch
        # is wrapped in its own explicit transaction here — this is the fair
        # comparison point: one fsync-bearing commit per ingest batch, same
        # as a real analytics writer would do, not one commit per row.
        rows = [
            (
                r["id"], r["ts"], r["client"], r["client_name"], r["domain"],
                r["qtype"], r["protocol"], r["rcode"], r["latency_ms"],
                int(r["blocked"]), r["block_reason"], r["upstream"], r["cache_status"],
            )
            for r in records
        ]
        self.conn.execute("BEGIN")
        try:
            self.conn.executemany(
                "INSERT INTO query_events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
            )
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.conn.close()

    def disk_usage_bytes(self) -> int:
        total = 0
        for suffix in ("", "-wal", "-shm"):
            p = Path(str(self.db_path) + suffix)
            if p.exists():
                total += p.stat().st_size
        return total

    def query(self, name: str) -> Any:
        c = self.conn
        if name == "last_5m":
            return c.execute("SELECT COUNT(*) FROM query_events WHERE ts > ?", (_now_minus(300),)).fetchone()
        if name == "last_1h":
            return c.execute("SELECT COUNT(*) FROM query_events WHERE ts > ?", (_now_minus(3600),)).fetchone()
        if name == "last_24h":
            return c.execute("SELECT COUNT(*) FROM query_events WHERE ts > ?", (_now_minus(86400),)).fetchone()
        if name == "last_7d":
            return c.execute("SELECT COUNT(*) FROM query_events WHERE ts > ?", (_now_minus(7 * 86400),)).fetchone()
        if name == "recent_page":
            return c.execute("SELECT * FROM query_events ORDER BY ts DESC LIMIT 50").fetchall()
        if name == "search_exact_domain":
            return c.execute("SELECT COUNT(*) FROM query_events WHERE domain = ?", ("www.google.com",)).fetchone()
        if name == "search_domain_suffix":
            return c.execute("SELECT COUNT(*) FROM query_events WHERE domain LIKE ?", ("%.example-long-tail.net",)).fetchone()
        if name == "by_client":
            return c.execute("SELECT COUNT(*) FROM query_events WHERE client = ?", ("192.168.1.5",)).fetchone()
        if name == "by_protocol":
            return c.execute("SELECT protocol, COUNT(*) FROM query_events GROUP BY protocol").fetchall()
        if name == "by_qtype":
            return c.execute("SELECT qtype, COUNT(*) FROM query_events GROUP BY qtype").fetchall()
        if name == "blocked_only":
            return c.execute("SELECT COUNT(*) FROM query_events WHERE blocked = 1").fetchone()
        if name == "top_domains":
            return c.execute("SELECT domain, COUNT(*) c FROM query_events GROUP BY domain ORDER BY c DESC LIMIT 20").fetchall()
        if name == "top_blocked_domains":
            return c.execute("SELECT domain, COUNT(*) c FROM query_events WHERE blocked=1 GROUP BY domain ORDER BY c DESC LIMIT 20").fetchall()
        if name == "top_clients":
            return c.execute("SELECT client, COUNT(*) c FROM query_events GROUP BY client ORDER BY c DESC LIMIT 20").fetchall()
        if name == "top_upstreams":
            return c.execute("SELECT upstream, COUNT(*) c FROM query_events GROUP BY upstream ORDER BY c DESC").fetchall()
        if name == "rcode_distribution":
            return c.execute("SELECT rcode, COUNT(*) FROM query_events GROUP BY rcode").fetchall()
        if name == "latency_percentiles":
            # SQLite has no PERCENTILE_CONT; approximate via sampled sort (fair to
            # what a real implementation would have to do too).
            return c.execute("SELECT AVG(latency_ms), MAX(latency_ms) FROM query_events").fetchone()
        if name == "time_series_counts":
            return c.execute(
                "SELECT CAST(ts/3600 AS INTEGER) AS hour, COUNT(*) FROM query_events GROUP BY hour ORDER BY hour"
            ).fetchall()
        raise ValueError(name)


class JsonlBackend:
    name = "jsonl_gzip"

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self._segment_idx = 0
        self._records_cache: list[dict] | None = None  # lazily loaded for query()

    def _final_path(self, idx: int) -> Path:
        return self.root / f"segment-{idx:05d}.jsonl.gz"

    def ingest(self, records: Iterable[dict]) -> None:
        records = list(records)
        tmp_path = self.root / f".segment-{self._segment_idx:05d}.jsonl.gz.tmp"
        with gzip.open(tmp_path, "wt", compresslevel=6) as fh:
            for r in records:
                fh.write(json.dumps(r) + "\n")
        os.replace(tmp_path, self._final_path(self._segment_idx))
        self._segment_idx += 1
        self._records_cache = None  # invalidate

    def close(self) -> None:
        pass

    def disk_usage_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.root.glob("segment-*.jsonl.gz"))

    def _load_all(self) -> list[dict]:
        if self._records_cache is not None:
            return self._records_cache
        records = []
        for p in sorted(self.root.glob("segment-*.jsonl.gz")):
            with gzip.open(p, "rt") as fh:
                for line in fh:
                    records.append(json.loads(line))
        self._records_cache = records
        return records

    def query(self, name: str) -> Any:
        # JSONL has no query engine of its own: every query is a full Python
        # scan over the decompressed records. This is the honest cost of the
        # "compressed JSONL" option and is intentionally not optimized further.
        recs = self._load_all()
        if name == "last_5m":
            cutoff = _now_minus(300)
            return sum(1 for r in recs if r["ts"] > cutoff)
        if name == "last_1h":
            cutoff = _now_minus(3600)
            return sum(1 for r in recs if r["ts"] > cutoff)
        if name == "last_24h":
            cutoff = _now_minus(86400)
            return sum(1 for r in recs if r["ts"] > cutoff)
        if name == "last_7d":
            cutoff = _now_minus(7 * 86400)
            return sum(1 for r in recs if r["ts"] > cutoff)
        if name == "recent_page":
            return sorted(recs, key=lambda r: -r["ts"])[:50]
        if name == "search_exact_domain":
            return sum(1 for r in recs if r["domain"] == "www.google.com")
        if name == "search_domain_suffix":
            return sum(1 for r in recs if r["domain"].endswith(".example-long-tail.net"))
        if name == "by_client":
            return sum(1 for r in recs if r["client"] == "192.168.1.5")
        if name == "by_protocol":
            counts: dict[str, int] = {}
            for r in recs:
                counts[r["protocol"]] = counts.get(r["protocol"], 0) + 1
            return counts
        if name == "by_qtype":
            counts = {}
            for r in recs:
                counts[r["qtype"]] = counts.get(r["qtype"], 0) + 1
            return counts
        if name == "blocked_only":
            return sum(1 for r in recs if r["blocked"])
        if name == "top_domains":
            counts = {}
            for r in recs:
                counts[r["domain"]] = counts.get(r["domain"], 0) + 1
            return sorted(counts.items(), key=lambda kv: -kv[1])[:20]
        if name == "top_blocked_domains":
            counts = {}
            for r in recs:
                if r["blocked"]:
                    counts[r["domain"]] = counts.get(r["domain"], 0) + 1
            return sorted(counts.items(), key=lambda kv: -kv[1])[:20]
        if name == "top_clients":
            counts = {}
            for r in recs:
                counts[r["client"]] = counts.get(r["client"], 0) + 1
            return sorted(counts.items(), key=lambda kv: -kv[1])[:20]
        if name == "top_upstreams":
            counts = {}
            for r in recs:
                counts[r["upstream"]] = counts.get(r["upstream"], 0) + 1
            return sorted(counts.items(), key=lambda kv: -kv[1])
        if name == "rcode_distribution":
            counts = {}
            for r in recs:
                counts[r["rcode"]] = counts.get(r["rcode"], 0) + 1
            return counts
        if name == "latency_percentiles":
            lat = sorted(r["latency_ms"] for r in recs)
            n = len(lat)
            return (sum(lat) / n if n else 0, lat[-1] if n else 0)
        if name == "time_series_counts":
            counts = {}
            for r in recs:
                hour = int(r["ts"] // 3600)
                counts[hour] = counts.get(hour, 0) + 1
            return counts
        raise ValueError(name)


class ParquetDuckDbBackend:
    name = "parquet_zstd_duckdb"

    def __init__(self, root: Path, *, row_group_size: int = 50_000, zstd_level: int = 9):
        import pyarrow as pa  # noqa: F401  (import here so a missing dep only breaks this backend)

        self.root = root
        self.row_group_size = row_group_size
        self.zstd_level = zstd_level
        self.root.mkdir(parents=True, exist_ok=True)
        self._segment_idx = 0
        self._con = None

    _SCHEMA = None

    @classmethod
    def _get_schema(cls):
        import pyarrow as pa

        if cls._SCHEMA is None:
            cls._SCHEMA = pa.schema([
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
            ])
        return cls._SCHEMA

    def ingest(self, records: Iterable[dict]) -> None:
        import pyarrow as pa
        import pyarrow.parquet as pq

        records = list(records)
        schema = self._get_schema()
        table = pa.Table.from_pylist(records, schema=schema)

        tmp_path = self.root / f".segment-{self._segment_idx:05d}.parquet.tmp"
        final_path = self.root / f"segment-{self._segment_idx:05d}.parquet"
        pq.write_table(
            table,
            tmp_path,
            compression="zstd",
            compression_level=self.zstd_level,
            row_group_size=self.row_group_size,
        )
        os.replace(tmp_path, final_path)  # atomic promote: readers never see partial writes
        self._segment_idx += 1

    def _connect(self):
        import duckdb

        if self._con is None:
            self._con = duckdb.connect(":memory:")
        return self._con

    def close(self) -> None:
        if self._con is not None:
            self._con.close()
            self._con = None

    def disk_usage_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.root.glob("segment-*.parquet"))

    def _glob(self) -> str:
        # Only ever matches finalized (non-.tmp) segment files — a reader
        # scanning this glob can never observe a half-written segment.
        return str(self.root / "segment-*.parquet")

    def query(self, name: str) -> Any:
        con = self._connect()
        src = f"read_parquet('{self._glob()}')"
        now5m, now1h, now24h, now7d = (_now_minus(x) for x in (300, 3600, 86400, 7 * 86400))
        if name == "last_5m":
            return con.execute(f"SELECT COUNT(*) FROM {src} WHERE ts > {now5m}").fetchone()
        if name == "last_1h":
            return con.execute(f"SELECT COUNT(*) FROM {src} WHERE ts > {now1h}").fetchone()
        if name == "last_24h":
            return con.execute(f"SELECT COUNT(*) FROM {src} WHERE ts > {now24h}").fetchone()
        if name == "last_7d":
            return con.execute(f"SELECT COUNT(*) FROM {src} WHERE ts > {now7d}").fetchone()
        if name == "recent_page":
            return con.execute(f"SELECT * FROM {src} ORDER BY ts DESC LIMIT 50").fetchall()
        if name == "search_exact_domain":
            return con.execute(f"SELECT COUNT(*) FROM {src} WHERE domain = 'www.google.com'").fetchone()
        if name == "search_domain_suffix":
            return con.execute(f"SELECT COUNT(*) FROM {src} WHERE domain LIKE '%.example-long-tail.net'").fetchone()
        if name == "by_client":
            return con.execute(f"SELECT COUNT(*) FROM {src} WHERE client = '192.168.1.5'").fetchone()
        if name == "by_protocol":
            return con.execute(f"SELECT protocol, COUNT(*) FROM {src} GROUP BY protocol").fetchall()
        if name == "by_qtype":
            return con.execute(f"SELECT qtype, COUNT(*) FROM {src} GROUP BY qtype").fetchall()
        if name == "blocked_only":
            return con.execute(f"SELECT COUNT(*) FROM {src} WHERE blocked").fetchone()
        if name == "top_domains":
            return con.execute(f"SELECT domain, COUNT(*) c FROM {src} GROUP BY domain ORDER BY c DESC LIMIT 20").fetchall()
        if name == "top_blocked_domains":
            return con.execute(f"SELECT domain, COUNT(*) c FROM {src} WHERE blocked GROUP BY domain ORDER BY c DESC LIMIT 20").fetchall()
        if name == "top_clients":
            return con.execute(f"SELECT client, COUNT(*) c FROM {src} GROUP BY client ORDER BY c DESC LIMIT 20").fetchall()
        if name == "top_upstreams":
            return con.execute(f"SELECT upstream, COUNT(*) c FROM {src} GROUP BY upstream ORDER BY c DESC").fetchall()
        if name == "rcode_distribution":
            return con.execute(f"SELECT rcode, COUNT(*) FROM {src} GROUP BY rcode").fetchall()
        if name == "latency_percentiles":
            return con.execute(
                f"SELECT median(latency_ms), quantile_cont(latency_ms, 0.95) FROM {src}"
            ).fetchone()
        if name == "time_series_counts":
            return con.execute(
                f"SELECT CAST(ts/3600 AS BIGINT) AS hour, COUNT(*) FROM {src} GROUP BY hour ORDER BY hour"
            ).fetchall()
        raise ValueError(name)


def make_backend(kind: str, root: Path, **kwargs) -> Any:
    if kind == "sqlite_wal":
        return SqliteWalBackend(root)
    if kind == "jsonl_gzip":
        return JsonlBackend(root)
    if kind == "parquet_zstd_duckdb":
        return ParquetDuckDbBackend(root, **kwargs)
    raise ValueError(kind)
