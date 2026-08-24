"""V2 aggregate analytics runtime: dedicated bounded SQLite WAL store
(Workstream 2, §7).

Frozen architecture (``docs/v2/architecture-map.md`` "Storage ownership"):
minute/hour/day dashboard rollups live in their own SQLite WAL file,
separate from both ``control.db`` and the raw Parquet history — never
unbounded per-query rows, always rebuildable from raw history where
practical.

Proposed path (not yet pinned by the roadmap, see
``docs/v2/architecture-map.md`` "Open items"):
``/var/lib/alderpointdns/analytics/aggregates.db``. This module never opens
that path implicitly — callers always pass a path in, and this workstream's
own usage only points it at disposable dev/test paths.

Schema is two bounded tables:

- ``time_buckets``: one row per (bucket_start, granularity) with the
  headline totals (query count, blocked count, cache hit/miss).
- ``dimension_counts``: one row per (bucket_start, granularity, dimension,
  value) — e.g. ("...", "hour", "protocol", "udp") -> count. This is how
  "top domains this hour" style dashboard queries stay O(distinct values),
  not O(raw query count).

Both tables are bounded by construction: a fixed number of buckets exist per
unit time (86400/granularity_seconds buckets/day), and ``delete_old_buckets``
provides the retention half of "bounded" for long-running deployments.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

_GRANULARITY_SECONDS = {"minute": 60, "hour": 3600, "day": 86400}

_DIMENSIONS = ("protocol", "qtype", "client", "rcode", "upstream", "domain")

_SCHEMA_STATEMENTS: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS schema_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS time_buckets (
        bucket_start INTEGER NOT NULL,
        granularity TEXT NOT NULL CHECK(granularity IN ('minute','hour','day')),
        total_queries INTEGER NOT NULL DEFAULT 0,
        blocked_queries INTEGER NOT NULL DEFAULT 0,
        cache_hits INTEGER NOT NULL DEFAULT 0,
        cache_misses INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_start, granularity)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS dimension_counts (
        bucket_start INTEGER NOT NULL,
        granularity TEXT NOT NULL CHECK(granularity IN ('minute','hour','day')),
        dimension TEXT NOT NULL,
        value TEXT NOT NULL,
        count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (bucket_start, granularity, dimension, value)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_dim_lookup ON dimension_counts(granularity, dimension, bucket_start)",
    """
    CREATE TABLE IF NOT EXISTS live_buckets (
        bucket_start INTEGER PRIMARY KEY,
        total_queries INTEGER NOT NULL DEFAULT 0,
        blocked_queries INTEGER NOT NULL DEFAULT 0,
        cache_hits INTEGER NOT NULL DEFAULT 0,
        cache_misses INTEGER NOT NULL DEFAULT 0,
        updated_at REAL NOT NULL
    )
    """,
)

AGGREGATE_SCHEMA_VERSION = 1


@contextmanager
def connect(path: str | Path) -> Iterator[sqlite3.Connection]:
    """Own connection, own WAL, own busy_timeout — completely independent of
    control.db's connection lifecycle (isolation requirement: a lock/corrupt
    aggregate DB must never block or fail a control.db operation, and vice
    versa)."""
    conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        yield conn
    finally:
        conn.close()


def initialize(path: str | Path) -> None:
    with connect(path) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute("BEGIN")
            try:
                for stmt in _SCHEMA_STATEMENTS:
                    cur.execute(stmt)
                cur.execute(
                    "INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('version', ?)",
                    (str(AGGREGATE_SCHEMA_VERSION),),
                )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"aggregates.db integrity_check failed: {integrity}")


def _bucket_start(ts: float, granularity: str) -> int:
    step = _GRANULARITY_SECONDS[granularity]
    return int(ts // step) * step


def record_batch(
    path: str | Path, records: Iterable[dict], *, granularity: str = "hour",
) -> None:
    """Transactionally roll up a batch of raw-query-shaped dicts (same shape
    as app/v2/parquet_writer.py's records) into the bucketed counters. One
    transaction per call — matches the batched-writer pattern used
    elsewhere, so an aggregate-writer failure mid-batch rolls back cleanly
    rather than leaving half-updated counters."""
    records = list(records)
    if not records:
        return
    if granularity not in _GRANULARITY_SECONDS:
        raise ValueError(f"unsupported granularity: {granularity!r}")

    bucket_totals: dict[int, list[int]] = {}  # bucket -> [total, blocked, hits, misses]
    dim_counts: dict[tuple[int, str, str], int] = {}

    for rec in records:
        bucket = _bucket_start(rec["ts"], granularity)
        totals = bucket_totals.setdefault(bucket, [0, 0, 0, 0])
        totals[0] += 1
        if rec.get("blocked"):
            totals[1] += 1
        cache_status = rec.get("cache_status")
        if cache_status == "hit":
            totals[2] += 1
        elif cache_status == "miss":
            totals[3] += 1
        for dim in _DIMENSIONS:
            value = rec.get(dim)
            if value is None:
                continue
            key = (bucket, dim, str(value))
            dim_counts[key] = dim_counts.get(key, 0) + 1

    with connect(path) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute("BEGIN")
            try:
                for bucket, (total, blocked, hits, misses) in bucket_totals.items():
                    cur.execute(
                        """
                        INSERT INTO time_buckets
                            (bucket_start, granularity, total_queries, blocked_queries, cache_hits, cache_misses)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(bucket_start, granularity) DO UPDATE SET
                            total_queries = total_queries + excluded.total_queries,
                            blocked_queries = blocked_queries + excluded.blocked_queries,
                            cache_hits = cache_hits + excluded.cache_hits,
                            cache_misses = cache_misses + excluded.cache_misses
                        """,
                        (bucket, granularity, total, blocked, hits, misses),
                    )
                for (bucket, dim, value), count in dim_counts.items():
                    cur.execute(
                        """
                        INSERT INTO dimension_counts (bucket_start, granularity, dimension, value, count)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(bucket_start, granularity, dimension, value) DO UPDATE SET
                            count = count + excluded.count
                        """,
                        (bucket, granularity, dim, value, count),
                    )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise


def query_totals(
    path: str | Path, start_ts: float, end_ts: float, *, granularity: str = "hour",
) -> list[tuple]:
    with connect(path) as conn:
        return conn.execute(
            """
            SELECT bucket_start, total_queries, blocked_queries, cache_hits, cache_misses
            FROM time_buckets WHERE granularity = ? AND bucket_start >= ? AND bucket_start < ?
            ORDER BY bucket_start
            """,
            (granularity, _bucket_start(start_ts, granularity), int(end_ts)),
        ).fetchall()


def query_dimension_top(
    path: str | Path, dimension: str, start_ts: float, end_ts: float, *,
    granularity: str = "hour", limit: int = 20,
) -> list[tuple]:
    if dimension not in _DIMENSIONS:
        raise ValueError(f"unsupported dimension: {dimension!r}")
    limit = max(1, min(limit, 1000))
    with connect(path) as conn:
        return conn.execute(
            f"""
            SELECT value, SUM(count) c FROM dimension_counts
            WHERE granularity = ? AND dimension = ? AND bucket_start >= ? AND bucket_start < ?
            GROUP BY value ORDER BY c DESC LIMIT {limit}
            """,
            (granularity, dimension, _bucket_start(start_ts, granularity), int(end_ts)),
        ).fetchall()


def delete_old_buckets(
    path: str | Path, *, granularity: str, max_age_seconds: float, now: float | None = None,
) -> int:
    """Retention for the aggregate store itself — bounded, not unbounded
    growth over a long-running deployment. Ordinary DELETE is fine here
    (unlike raw Parquet history) because bucket rows are few relative to raw
    query volume by design."""
    import time as _time

    now = now if now is not None else _time.time()
    cutoff = _bucket_start(now - max_age_seconds, granularity)
    with connect(path) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute("BEGIN")
            try:
                cur.execute(
                    "DELETE FROM time_buckets WHERE granularity = ? AND bucket_start < ?",
                    (granularity, cutoff),
                )
                n = cur.rowcount
                cur.execute(
                    "DELETE FROM dimension_counts WHERE granularity = ? AND bucket_start < ?",
                    (granularity, cutoff),
                )
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise
    return n


def record_live_batch(path: str | Path, records: Iterable[dict], *, now: float | None = None, retention_seconds: int = 600) -> None:
    """Record recent live activity as real one-second buckets.

    This is intentionally separate from minute/hour/day dashboard
    aggregates. It is bounded, updated in batches by the analytics worker,
    and never receives a SQLite write from the DNS hot path.
    """
    import time as _time

    records = list(records)
    if not records:
        return
    now = now if now is not None else _time.time()
    cutoff = int(now) - max(60, int(retention_seconds))
    bucket_totals: dict[int, list[int]] = {}
    for rec in records:
        bucket = int(float(rec["ts"]))
        totals = bucket_totals.setdefault(bucket, [0, 0, 0, 0])
        totals[0] += 1
        if rec.get("blocked"):
            totals[1] += 1
        cache_status = rec.get("cache_status")
        if cache_status == "hit":
            totals[2] += 1
        elif cache_status == "miss":
            totals[3] += 1
    with connect(path) as conn:
        with closing(conn.cursor()) as cur:
            cur.execute("BEGIN")
            try:
                for bucket, (total, blocked, hits, misses) in bucket_totals.items():
                    cur.execute(
                        """
                        INSERT INTO live_buckets
                            (bucket_start, total_queries, blocked_queries, cache_hits, cache_misses, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(bucket_start) DO UPDATE SET
                            total_queries = total_queries + excluded.total_queries,
                            blocked_queries = blocked_queries + excluded.blocked_queries,
                            cache_hits = cache_hits + excluded.cache_hits,
                            cache_misses = cache_misses + excluded.cache_misses,
                            updated_at = excluded.updated_at
                        """,
                        (bucket, total, blocked, hits, misses, now),
                    )
                cur.execute("DELETE FROM live_buckets WHERE bucket_start < ?", (cutoff,))
                cur.execute("COMMIT")
            except BaseException:
                cur.execute("ROLLBACK")
                raise


def query_live_buckets(path: str | Path, start_ts: float, end_ts: float) -> list[tuple]:
    start_bucket = int(start_ts)
    end_bucket = int(end_ts)
    with connect(path) as conn:
        return conn.execute(
            """
            SELECT bucket_start, total_queries, blocked_queries, cache_hits, cache_misses
            FROM live_buckets
            WHERE bucket_start >= ? AND bucket_start <= ?
            ORDER BY bucket_start
            """,
            (start_bucket, end_bucket),
        ).fetchall()


def rebuild_range_from_reader(
    aggregates_path: str | Path, reader, start_ts: float, end_ts: float, *,
    granularity: str = "hour", chunk_seconds: float = 3600.0,
) -> int:
    """Rebuild aggregate buckets for [start_ts, end_ts) from a
    ``app.v2.analytics_query.PartitionPruningReader`` (or any object exposing
    ``query_time_window``) over raw Parquet history — the "rebuildable from
    raw history where practical" requirement. Idempotent: re-running over
    the same range double-counts unless the caller first clears those
    buckets (rebuild is a recompute operation, not an incremental merge —
    callers doing a true rebuild should delete the target bucket range
    first; this function does not do that implicitly so it stays safe to use
    for incremental catch-up too).
    """
    total_rows = 0
    t = start_ts
    while t < end_ts:
        chunk_end = min(t + chunk_seconds, end_ts)
        result = reader.query_time_window(
            t, chunk_end,
            columns=["ts", "protocol", "qtype", "client", "rcode", "upstream", "domain", "blocked", "cache_status"],
            sort_column=None, limit=1_000_000,
        )
        if result.rows:
            records = [
                dict(zip(
                    ["ts", "protocol", "qtype", "client", "rcode", "upstream", "domain", "blocked", "cache_status"],
                    row,
                ))
                for row in result.rows
            ]
            record_batch(aggregates_path, records, granularity=granularity)
            total_rows += len(records)
        t = chunk_end
    return total_rows
