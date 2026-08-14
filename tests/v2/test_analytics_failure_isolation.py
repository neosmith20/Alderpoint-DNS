"""Adversarial analytics failure-isolation tests (Workstream 2, §8, §33).

Required invariant under every scenario here: the failure is caught,
recorded/observable, and bounded — it never raises out into a caller that
stands in for the DNS-answering path. Some individual failure modes are
already covered by test_parquet_writer.py / test_retention.py /
test_analytics_query.py / test_aggregates_db.py (crash-mid-write, corrupt
segment, retention racing writer/reader, delete errors) — this file is the
places those don't reach: disk-full-style OSError, a read-only analytics
path, DuckDB query errors from an all-corrupt directory, aggregate-DB
locked/corrupt, bounded-queue overflow, and worker-restart-after-crash
continuity.
"""
from __future__ import annotations

import os
import sqlite3
import stat
import time
from pathlib import Path

import pytest

pytest.importorskip("pyarrow")

from app.v2.parquet_writer import ParquetSegmentWriter  # noqa: E402
from app.v2.analytics_ingest import BoundedQueue  # noqa: E402
from app.v2 import aggregates_db as agg  # noqa: E402


def _rec(i, ts):
    return dict(
        id=i, ts=ts, client="c", client_name="c", domain="d.example.com", qtype="A",
        protocol="udp", rcode="NOERROR", latency_ms=1.0, blocked=False,
        block_reason=None, upstream="1.1.1.1", cache_status="hit", cache_profile_id="p",
    )


def test_disk_full_during_write_is_isolated(tmp_path, monkeypatch):
    """OSError(ENOSPC) mid-write must be caught at the writer boundary."""
    import pyarrow.parquet as pq

    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=1000)

    def _boom(*a, **kw):
        raise OSError(28, "No space left on device")  # errno.ENOSPC

    monkeypatch.setattr(pq, "write_table", _boom)
    w.ingest([_rec(1, time.time())])
    w.close()  # must not raise
    assert w.stats.flush_failures == 1
    assert "No space left on device" in w.stats.last_error
    assert w.stats.dropped_count == 1


def test_readonly_analytics_directory_is_isolated(tmp_path):
    """Parent directory not writable (e.g. misconfigured permissions, or a
    read-only remount under disk-pressure recovery) must not raise out of
    ingest/close."""
    root = tmp_path / "readonly_root"
    root.mkdir()
    w = ParquetSegmentWriter(root, max_rows_per_segment=1000)
    w.ingest([_rec(1, time.time())])
    # Make the (already-created) root read-only *after* the writer's own
    # mkdir, to simulate an operator/automation change mid-run rather than a
    # constructor-time failure.
    os.chmod(root, stat.S_IREAD | stat.S_IEXEC)
    try:
        w.close()  # must not raise, even though the flush will fail to write
        assert w.stats.flush_failures >= 1 or w.stats.segments_written == 1
    finally:
        os.chmod(root, stat.S_IRWXU)  # restore so tmp_path cleanup can remove it


def test_all_segments_corrupt_query_returns_empty_not_crash(tmp_path):
    """If every segment in a query's time range is corrupt, the reader must
    degrade to an empty (or partial) result set, never propagate a DuckDB
    read error to the caller."""
    pytest.importorskip("duckdb")
    from app.v2.analytics_query import PartitionPruningReader

    now = time.time()
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=5)
    w.ingest([_rec(i, now) for i in range(5)])
    w.close()
    seg = next(tmp_path.rglob("*.parquet"))
    seg.write_bytes(b"corrupted after close")

    reader = PartitionPruningReader(tmp_path)
    result = reader.query_recent(minutes=5, now=now)  # must not raise
    reader.close()
    assert result.rows == []
    assert result.files_considered == 0


def test_one_corrupt_segment_among_valid_ones_still_returns_valid_rows(tmp_path):
    pytest.importorskip("duckdb")
    from app.v2.analytics_query import PartitionPruningReader

    now = time.time()
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=5)
    w.ingest([_rec(i, now - 1) for i in range(5)])
    w.flush()
    w.ingest([_rec(i, now - 1) for i in range(5, 10)])
    w.close()
    segs = sorted(tmp_path.rglob("*.parquet"))
    assert len(segs) == 2
    segs[0].write_bytes(b"corrupted")

    reader = PartitionPruningReader(tmp_path)
    result = reader.query_recent(minutes=5, now=now)
    reader.close()
    assert result.files_considered == 1
    assert len(result.rows) == 5


def test_aggregate_db_locked_by_external_writer_times_out_not_hangs(tmp_path):
    """A long-held external lock (busy_timeout exceeded) must raise a
    catchable sqlite3 error, not hang the caller indefinitely — the
    dashboard is expected to degrade/error in this case, per the frozen
    contract, not stall."""
    db = tmp_path / "aggregates.db"
    agg.initialize(db)

    blocker = sqlite3.connect(str(db), timeout=1.0)
    blocker.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(sqlite3.OperationalError):
            agg.record_batch(db, [_rec(1, time.time())], granularity="hour")
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()


def test_aggregate_db_corrupt_file_raises_catchable_error_not_silent_bad_data(tmp_path):
    db = tmp_path / "aggregates.db"
    agg.initialize(db)
    db.write_bytes(b"corrupted, not a real sqlite database")
    with pytest.raises(sqlite3.DatabaseError):
        agg.query_totals(db, 0, time.time(), granularity="hour")


def test_bounded_queue_overflow_drops_oldest_and_counts_it():
    q = BoundedQueue(capacity=3)
    for i in range(5):
        q.push({"i": i})
    assert len(q) == 3
    assert q.dropped_count == 2
    drained = q.drain()
    assert [r["i"] for r in drained] == [2, 3, 4]  # oldest (0, 1) were dropped


def test_worker_restart_after_crash_continues_with_new_segment_index(tmp_path):
    """Simulate an analytics-writer process restart: a fresh
    ParquetSegmentWriter instance (as a restarted process would construct)
    must not collide segment filenames with a prior instance's already
    on-disk output — the new writer seeds its segment index from whatever
    already exists in the partition directory, so history is appended to,
    never silently overwritten."""
    now = time.time()
    w1 = ParquetSegmentWriter(tmp_path, max_rows_per_segment=5)
    w1.ingest([_rec(i, now) for i in range(5)])
    w1.close()
    before = sorted(tmp_path.rglob("*.parquet"))
    assert len(before) == 1
    before_content = before[0].read_bytes()

    # "Restart": a brand new writer instance, same root — must not collide.
    w2 = ParquetSegmentWriter(tmp_path, max_rows_per_segment=5)
    w2.ingest([_rec(i, now) for i in range(5, 10)])
    w2.close()
    after = sorted(tmp_path.rglob("*.parquet"))
    assert len(after) == 2
    assert after[0].read_bytes() == before_content  # first segment untouched
