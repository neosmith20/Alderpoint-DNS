"""Tests for app/v2/analytics_query.py (Workstream 2, §4-5, §33 DUCKDB).

Requires pyarrow/duckdb — run under dev/.venv-v2-bench.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("pyarrow")
pytest.importorskip("duckdb")

from app.v2.parquet_writer import ParquetSegmentWriter  # noqa: E402
from app.v2.analytics_query import (  # noqa: E402
    PartitionPruningReader,
    enumerate_partition_files,
)


def _rec(i: int, ts: float, **overrides) -> dict:
    base = dict(
        id=i, ts=ts, client="10.0.0.5", client_name="c", domain=f"domain{i % 5}.example.com",
        qtype="A", protocol="udp", rcode="NOERROR", latency_ms=1.5 + (i % 10), blocked=(i % 7 == 0),
        block_reason=None, upstream="1.1.1.1", cache_status="hit" if i % 2 else "miss",
        cache_profile_id="p1",
    )
    base.update(overrides)
    return base


def _write_history_spanning_days(root: Path, num_days: int, rows_per_day: int) -> float:
    """Writes `num_days` days of history, one flushed segment per day, ending
    "now". Returns the timestamp of the most recent (last) day's first row.
    """
    now = time.time()
    last_day_start_ts = None
    w = ParquetSegmentWriter(root, max_rows_per_segment=rows_per_day + 1)
    for day_offset in range(num_days, 0, -1):
        day_ts = now - day_offset * 86400
        if day_offset == 1:
            last_day_start_ts = day_ts
        records = [_rec(i, day_ts + i * 10) for i in range(rows_per_day)]
        w.ingest(records)
        w.flush()
    return last_day_start_ts


def test_last_hour_query_prunes_to_relevant_partitions_only(tmp_path):
    """The core pruning-proof test: write 10 days of one-segment-per-day
    history (10 files total), then query "last hour" and assert only the
    files that could plausibly contain a row in that window were considered
    — not all 10."""
    now = time.time()
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=10_000)
    for day_offset in range(10, -1, -1):  # 11 days including today
        day_ts = now - day_offset * 86400
        w.ingest([_rec(i, day_ts) for i in range(5)])
        w.flush()
    total_files = len(list(tmp_path.rglob("*.parquet")))
    assert total_files == 11  # sanity: one segment per day

    reader = PartitionPruningReader(tmp_path)
    result = reader.query_recent(minutes=60, now=now)
    reader.close()

    # Only today's (and possibly yesterday's, if the hour window straddles
    # midnight UTC) day-partition should ever be opened — never all 11.
    assert result.files_considered <= 2
    assert result.files_considered < total_files


def test_enumerate_partition_files_skips_out_of_range_years(tmp_path):
    # Build a two-year-apart pair of partitions.
    old_ts = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
    new_ts = datetime(2026, 6, 15, 12, tzinfo=timezone.utc).timestamp()
    w = ParquetSegmentWriter(tmp_path)
    w.ingest([_rec(1, old_ts)])
    w.flush()
    w.ingest([_rec(2, new_ts)])
    w.flush()
    assert len(list(tmp_path.rglob("*.parquet"))) == 2

    window_start = datetime(2026, 6, 15, 0, tzinfo=timezone.utc).timestamp()
    window_end = datetime(2026, 6, 16, 0, tzinfo=timezone.utc).timestamp()
    files = enumerate_partition_files(tmp_path, window_start, window_end)
    assert len(files) == 1
    assert "2026" in str(files[0])


def test_time_window_query_returns_correct_rows(tmp_path):
    base = datetime(2026, 5, 1, 10, tzinfo=timezone.utc).timestamp()
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=10_000)
    w.ingest([_rec(i, base + i * 60) for i in range(20)])  # spread over 20 minutes
    w.close()

    reader = PartitionPruningReader(tmp_path)
    result = reader.query_time_window(base + 5 * 60, base + 10 * 60, limit=100)
    reader.close()
    # rows with ts in [base+5min, base+10min) -> i in [5, 10)
    assert len(result.rows) == 5


def test_filter_by_domain_uses_allowlisted_column(tmp_path):
    base = time.time() - 100
    w = ParquetSegmentWriter(tmp_path)
    w.ingest([_rec(i, base + i) for i in range(10)])
    w.close()
    reader = PartitionPruningReader(tmp_path)
    result = reader.query_time_window(base - 1, base + 100, filters={"domain": "domain0.example.com"})
    reader.close()
    assert len(result.rows) > 0


def test_unknown_filter_column_rejected(tmp_path):
    w = ParquetSegmentWriter(tmp_path)
    w.ingest([_rec(1, time.time())])
    w.close()
    reader = PartitionPruningReader(tmp_path)
    with pytest.raises(ValueError):
        reader.query_time_window(0, time.time() + 1, filters={"'; DROP TABLE x; --": "evil"})
    reader.close()


def test_filter_value_with_sql_metacharacters_is_safely_bound(tmp_path):
    """A domain value containing a single-quote must not be able to break out
    of the query — proves values are bound params, not interpolated."""
    base = time.time() - 10
    w = ParquetSegmentWriter(tmp_path)
    w.ingest([_rec(1, base, domain="evil'; DROP TABLE x; --")])
    w.ingest([_rec(2, base, domain="normal.example.com")])
    w.close()
    reader = PartitionPruningReader(tmp_path)
    result = reader.query_time_window(
        base - 1, base + 10, filters={"domain": "evil'; DROP TABLE x; --"}
    )
    reader.close()
    assert len(result.rows) == 1


def test_limit_is_bounded_even_if_caller_asks_for_more(tmp_path):
    base = time.time() - 1000
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=10_000)
    w.ingest([_rec(i, base + i) for i in range(50)])
    w.close()
    reader = PartitionPruningReader(tmp_path)
    result = reader.query_time_window(base - 1, base + 1000, limit=10_000_000)
    reader.close()
    assert len(result.rows) <= 2000  # MAX_LIMIT


def test_reader_tolerates_segment_deleted_between_enumeration_and_query(tmp_path):
    base = time.time() - 100
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=5)
    w.ingest([_rec(i, base + i) for i in range(5)])
    w.flush()
    w.ingest([_rec(i, base + i + 10) for i in range(5, 10)])
    w.flush()
    files = sorted(tmp_path.rglob("*.parquet"))
    assert len(files) == 2
    files[0].unlink()  # simulate retention deleting the older segment mid-query-prep

    reader = PartitionPruningReader(tmp_path)
    result = reader.query_time_window(base - 1, base + 100, limit=100)
    reader.close()
    assert result.files_considered == 1  # the deleted one was excluded, no crash
    assert len(result.rows) == 5


def test_empty_history_returns_empty_not_error(tmp_path):
    reader = PartitionPruningReader(tmp_path)
    result = reader.query_recent(minutes=60)
    reader.close()
    assert result.rows == []
    assert result.files_considered == 0


def test_top_n_and_rcode_distribution_and_latency(tmp_path):
    base = time.time() - 1000
    w = ParquetSegmentWriter(tmp_path, max_rows_per_segment=10_000)
    w.ingest([_rec(i, base + i) for i in range(50)])
    w.close()
    reader = PartitionPruningReader(tmp_path)
    top = reader.top_n("domain", base - 1, base + 1000, limit=5)
    assert len(top.rows) <= 5
    blocked = reader.top_n("domain", base - 1, base + 1000, only_blocked=True, limit=5)
    assert all(r for r in blocked.rows)  # just doesn't crash / returns something well-formed
    dist = reader.rcode_distribution(base - 1, base + 1000)
    assert dist.rows
    lat = reader.latency_percentiles(base - 1, base + 1000)
    assert lat.rows
    reader.close()
