"""Tests for app/v2/aggregates_db.py (Workstream 2, §7, §33 AGGREGATES)."""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from app.v2 import aggregates_db as agg


def _rec(ts, **overrides):
    base = dict(
        ts=ts, protocol="udp", qtype="A", client="10.0.0.5", rcode="NOERROR",
        upstream="1.1.1.1", domain="example.com", blocked=False, cache_status="miss",
    )
    base.update(overrides)
    return base


def test_initialize_creates_bounded_schema(tmp_path):
    db = tmp_path / "aggregates.db"
    agg.initialize(db)
    with agg.connect(db) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"time_buckets", "dimension_counts", "schema_meta"} <= tables


def test_record_batch_updates_totals(tmp_path):
    db = tmp_path / "aggregates.db"
    agg.initialize(db)
    now = time.time()
    agg.record_batch(db, [
        _rec(now, blocked=False, cache_status="hit"),
        _rec(now, blocked=True, cache_status="miss"),
        _rec(now, blocked=False, cache_status="hit"),
    ], granularity="hour")
    rows = agg.query_totals(db, now - 10, now + 10, granularity="hour")
    assert len(rows) == 1
    _, total, blocked, hits, misses = rows[0]
    assert total == 3
    assert blocked == 1
    assert hits == 2
    assert misses == 1


def test_record_batch_accumulates_across_calls(tmp_path):
    db = tmp_path / "aggregates.db"
    agg.initialize(db)
    now = time.time()
    agg.record_batch(db, [_rec(now)], granularity="hour")
    agg.record_batch(db, [_rec(now), _rec(now)], granularity="hour")
    rows = agg.query_totals(db, now - 10, now + 10, granularity="hour")
    assert rows[0][1] == 3  # total_queries accumulated, not overwritten


def test_dimension_counts_top_n(tmp_path):
    db = tmp_path / "aggregates.db"
    agg.initialize(db)
    now = time.time()
    agg.record_batch(db, [
        _rec(now, domain="a.com"), _rec(now, domain="a.com"), _rec(now, domain="b.com"),
    ], granularity="hour")
    top = agg.query_dimension_top(db, "domain", now - 10, now + 10, granularity="hour")
    assert top[0] == ("a.com", 2)


def test_unsupported_dimension_rejected(tmp_path):
    db = tmp_path / "aggregates.db"
    agg.initialize(db)
    with pytest.raises(ValueError):
        agg.query_dimension_top(db, "not_a_real_dimension", 0, 1)


def test_unsupported_granularity_rejected(tmp_path):
    db = tmp_path / "aggregates.db"
    agg.initialize(db)
    with pytest.raises(ValueError):
        agg.record_batch(db, [_rec(time.time())], granularity="fortnight")


def test_bounded_retention_deletes_old_buckets(tmp_path):
    db = tmp_path / "aggregates.db"
    agg.initialize(db)
    now = time.time()
    old_ts = now - 100 * 3600  # 100 hours ago
    agg.record_batch(db, [_rec(old_ts)], granularity="hour")
    agg.record_batch(db, [_rec(now)], granularity="hour")
    deleted = agg.delete_old_buckets(db, granularity="hour", max_age_seconds=50 * 3600, now=now)
    assert deleted == 1
    rows = agg.query_totals(db, 0, now + 3600, granularity="hour")
    assert len(rows) == 1


def test_isolated_file_from_control_db(tmp_path):
    """Corruption/lock isolation: aggregates.db and control.db are entirely
    separate files/connections — corrupting one must not affect the other."""
    agg_db = tmp_path / "aggregates.db"
    control_db = tmp_path / "control.db"
    agg.initialize(agg_db)

    from app.v2 import control_db as cdb
    cdb.initialize(control_db)

    # Corrupt the aggregate DB file directly.
    agg_db.write_bytes(b"not a sqlite file at all")

    # control.db must remain fully usable.
    assert cdb.schema_version(control_db) == cdb.CONTROL_SCHEMA_VERSION

    # aggregates.db failure is isolated (raises, but doesn't touch control.db).
    with pytest.raises(sqlite3.DatabaseError):
        agg.query_totals(agg_db, 0, time.time(), granularity="hour")


def test_rebuild_from_reader(tmp_path):
    pytest.importorskip("pyarrow")
    pytest.importorskip("duckdb")
    from app.v2.parquet_writer import ParquetSegmentWriter
    from app.v2.analytics_query import PartitionPruningReader

    raw_root = tmp_path / "raw"
    agg_db = tmp_path / "aggregates.db"
    agg.initialize(agg_db)

    now = time.time()
    w = ParquetSegmentWriter(raw_root, max_rows_per_segment=1000)
    w.ingest([
        dict(id=i, ts=now, client="c", client_name="c", domain="d.example.com", qtype="A",
             protocol="udp", rcode="NOERROR", latency_ms=1.0, blocked=(i % 2 == 0),
             block_reason=None, upstream="1.1.1.1", cache_status="hit", cache_profile_id="p")
        for i in range(10)
    ])
    w.close()

    reader = PartitionPruningReader(raw_root)
    n = agg.rebuild_range_from_reader(agg_db, reader, now - 60, now + 60, granularity="hour")
    reader.close()
    assert n == 10
    rows = agg.query_totals(agg_db, now - 3600, now + 3600, granularity="hour")
    assert rows[0][1] == 10
    assert rows[0][2] == 5  # blocked count
