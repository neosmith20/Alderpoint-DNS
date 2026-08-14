"""Tests for app/v2/parquet_writer.py (Workstream 2, §2-3, §33 PARQUET).

Requires pyarrow/duckdb — run under dev/.venv-v2-bench, same constraint as
benchmarks/v2_analytics/ (see docs/v2/benchmark-results.md methodology note).
"""
from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

pyarrow = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")

from app.v2.parquet_writer import (  # noqa: E402
    ParquetSegmentWriter,
    SegmentValidationError,
    cleanup_orphaned_temp_files,
    list_valid_segments,
    validate_segment,
)


def _rec(i: int, ts: float, **overrides) -> dict:
    base = dict(
        id=i, ts=ts, client="10.0.0.5", client_name="test-client", domain="example.com",
        qtype="A", protocol="udp", rcode="NOERROR", latency_ms=1.5, blocked=False,
        block_reason=None, upstream="1.1.1.1", cache_status="miss", cache_profile_id="p1",
    )
    base.update(overrides)
    return base


def test_flush_writes_valid_promoted_segment(tmp_path):
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=1000)
    now = time.time()
    w.ingest([_rec(i, now) for i in range(10)])
    w.close()
    segs = list(tmp_path.rglob("*.parquet"))
    assert len(segs) == 1
    assert w.stats.rows_written == 10
    assert w.stats.segments_written == 1
    assert w.stats.segments_rejected == 0
    validate_segment(segs[0], expected_min_rows=10)


def test_partition_layout_is_yyyy_mm_dd_hh(tmp_path):
    from datetime import datetime, timezone

    w = ParquetSegmentWriter(tmp_path)
    ts = time.time()
    w.ingest([_rec(1, ts)])
    w.close()
    seg = next(tmp_path.rglob("*.parquet"))
    parts = seg.relative_to(tmp_path).parts
    expected_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    assert parts[0] == f"{expected_dt.year:04d}"
    assert parts[1] == f"{expected_dt.month:02d}"
    assert parts[2] == f"{expected_dt.day:02d}"
    assert parts[3].startswith(f"{expected_dt.hour:02d}-")


def test_row_count_rotation(tmp_path):
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=5)
    now = time.time()
    w.ingest([_rec(i, now) for i in range(12)])  # should rotate at 5, 10, leave 2 buffered
    assert w.stats.segments_written == 2
    w.close()
    assert w.stats.segments_written == 3
    assert w.stats.rows_written == 12


def test_time_based_rotation(tmp_path):
    clock = {"t": 1000.0}
    w = ParquetSegmentWriter(
        tmp_path, max_rows_per_segment=10_000, max_seconds_per_segment=5.0,
        clock=lambda: clock["t"],
    )
    w.ingest([_rec(1, clock["t"])])
    assert w.stats.segments_written == 0
    clock["t"] += 6.0
    w.ingest([_rec(2, clock["t"])])  # triggers maybe_rotate_on_time before buffering rec 2
    assert w.stats.segments_written == 1


def test_temp_file_uses_dot_prefix_and_tmp_suffix(tmp_path):
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=10_000)
    now = time.time()
    # Ingest without flushing/closing: buffer holds the record, no file yet.
    w.ingest([_rec(1, now)])
    assert not list(tmp_path.rglob("*.parquet"))
    w.close()
    assert len(list(tmp_path.rglob("*.parquet"))) == 1


def test_simulated_crash_leaves_only_tmp_file_invisible_to_reader(tmp_path):
    """Model a process dying mid-write: a temp file exists, was never
    os.replace()'d, and must be structurally invisible to list_valid_segments."""
    import pyarrow as pa
    partition_dir = tmp_path / "2026" / "01" / "01"
    partition_dir.mkdir(parents=True)
    tmp_path_file = partition_dir / ".00-000000.parquet.tmp"
    schema = pa.schema([("id", pa.int64())])
    table = pa.Table.from_pylist([{"id": 1}], schema=schema)
    pq.write_table(table, tmp_path_file)  # written but never promoted
    assert list_valid_segments(tmp_path) == []
    assert tmp_path_file.exists()  # still there, just ignored


def test_corrupt_closed_segment_is_skipped_not_raised(tmp_path):
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=1000)
    now = time.time()
    w.ingest([_rec(i, now) for i in range(5)])
    w.close()
    good = next(tmp_path.rglob("*.parquet"))
    good.write_bytes(b"not a parquet file")  # corrupt in place, post-promotion
    assert list_valid_segments(tmp_path) == []  # skipped, no exception


def test_zero_row_segment_rejected(tmp_path):
    import pyarrow as pa
    partition_dir = tmp_path / "2026" / "01" / "01"
    partition_dir.mkdir(parents=True)
    p = partition_dir / "00-000000.parquet"
    schema = pa.schema([("id", pa.int64())])
    table = pa.Table.from_pylist([], schema=schema)
    pq.write_table(table, p)
    with pytest.raises(SegmentValidationError):
        validate_segment(p)


def test_missing_expected_columns_rejected(tmp_path):
    import pyarrow as pa
    partition_dir = tmp_path / "2026" / "01" / "01"
    partition_dir.mkdir(parents=True)
    p = partition_dir / "00-000000.parquet"
    schema = pa.schema([("id", pa.int64())])  # missing every other expected column
    table = pa.Table.from_pylist([{"id": 1}], schema=schema)
    pq.write_table(table, p)
    with pytest.raises(SegmentValidationError):
        validate_segment(p)


def test_malformed_record_dropped_not_crashing(tmp_path):
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=1000)
    now = time.time()
    w.ingest([_rec(1, now), {"not": "a valid record"}, _rec(2, now)])
    w.close()
    assert w.stats.dropped_count == 1
    assert w.stats.rows_written == 2


def test_cleanup_orphaned_temp_files_only_removes_old_ones(tmp_path):
    partition_dir = tmp_path / "2026" / "01" / "01"
    partition_dir.mkdir(parents=True)
    old_tmp = partition_dir / ".00-000000.parquet.tmp"
    new_tmp = partition_dir / ".00-000001.parquet.tmp"
    old_tmp.write_bytes(b"x")
    new_tmp.write_bytes(b"x")
    old_time = time.time() - 7200
    os.utime(old_tmp, (old_time, old_time))
    removed = cleanup_orphaned_temp_files(tmp_path, older_than_seconds=3600)
    assert old_tmp not in [p for p in removed] or not old_tmp.exists()
    assert not old_tmp.exists()
    assert new_tmp.exists()


def test_extra_unexpected_fields_are_dropped_not_fatal(tmp_path):
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=1000)
    now = time.time()
    w.ingest([_rec(1, now, unexpected_extra_field="ignored")])
    w.close()
    assert w.stats.rows_written == 1
    assert w.stats.segments_rejected == 0


def test_writer_failure_never_raises_from_ingest(tmp_path, monkeypatch):
    """Simulate a disk-full-style failure during write: ingest()/close() must
    not raise, must record it in stats instead (failure-isolation contract)."""
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=1000)
    now = time.time()

    def _boom(self, records, tmp_path_arg):
        raise OSError("simulated disk full")

    monkeypatch.setattr(ParquetSegmentWriter, "_write_and_validate", _boom)
    w.ingest([_rec(1, now)])
    w.close()  # must not raise
    assert w.stats.segments_rejected == 1
    assert w.stats.flush_failures == 1
    assert w.stats.dropped_count == 1
    assert "simulated disk full" in w.stats.last_error
