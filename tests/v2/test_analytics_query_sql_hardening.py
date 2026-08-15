"""Gate #2 MEDIUM: analytics_query.py's query_time_window() must never
accept a raw SQL fragment for columns/sort -- only allowlisted column
names and an explicit sort-direction enum.
"""

from __future__ import annotations

import time

import pytest

from app.v2.analytics_query import PartitionPruningReader
from app.v2.parquet_writer import ParquetSegmentWriter


def _rec(i, ts, **overrides):
    base = dict(
        id=i, ts=ts, client="10.0.0.1", client_name="", domain=f"host{i}.example",
        qtype="A", protocol="udp", rcode="NOERROR", latency_ms=5.0, blocked=False,
        block_reason="", upstream="default", cache_status="miss", cache_profile_id="p1",
    )
    base.update(overrides)
    return base


@pytest.fixture()
def reader(tmp_path):
    w = ParquetSegmentWriter(root=tmp_path)
    base = time.time() - 10
    w.ingest([_rec(1, base), _rec(2, base + 1)])
    w.close()
    r = PartitionPruningReader(tmp_path)
    yield r, base
    r.close()


class TestColumnsAllowlist:
    def test_valid_columns_accepted(self, reader):
        r, base = reader
        result = r.query_time_window(base - 1, base + 100, columns=["ts", "domain"])
        assert len(result.rows) == 2
        assert len(result.rows[0]) == 2

    def test_sql_injection_via_columns_rejected(self, reader):
        r, base = reader
        with pytest.raises(ValueError):
            r.query_time_window(
                base - 1, base + 100,
                columns=["ts; DROP TABLE x; --"],
            )

    def test_subquery_injection_via_columns_rejected(self, reader):
        r, base = reader
        with pytest.raises(ValueError):
            r.query_time_window(
                base - 1, base + 100,
                columns=["(SELECT sqlite_version())"],
            )

    def test_empty_columns_list_rejected(self, reader):
        r, base = reader
        with pytest.raises(ValueError):
            r.query_time_window(base - 1, base + 100, columns=[])

    def test_unknown_but_syntactically_clean_column_rejected(self, reader):
        r, base = reader
        with pytest.raises(ValueError):
            r.query_time_window(base - 1, base + 100, columns=["not_a_real_column"])


class TestSortColumnAllowlist:
    def test_valid_sort_column_accepted(self, reader):
        r, base = reader
        result = r.query_time_window(base - 1, base + 100, sort_column="domain", sort_direction="ASC")
        assert len(result.rows) == 2

    def test_sql_injection_via_sort_column_rejected(self, reader):
        r, base = reader
        with pytest.raises(ValueError):
            r.query_time_window(base - 1, base + 100, sort_column="ts; DROP TABLE x; --")

    def test_none_sort_column_means_unsorted_and_is_allowed(self, reader):
        r, base = reader
        result = r.query_time_window(base - 1, base + 100, sort_column=None)
        assert len(result.rows) == 2


class TestSortDirectionEnum:
    def test_invalid_sort_direction_rejected(self, reader):
        r, base = reader
        with pytest.raises(ValueError):
            r.query_time_window(base - 1, base + 100, sort_direction="ASC; DROP TABLE x; --")

    def test_lowercase_direction_rejected_not_silently_normalized(self, reader):
        # Explicit enum, not case-insensitive coercion -- avoids a class of
        # bypass where an unexpected casing sneaks through unchecked.
        r, base = reader
        with pytest.raises(ValueError):
            r.query_time_window(base - 1, base + 100, sort_direction="desc")


class TestFilterFieldsStillHardened:
    """Regression: the pre-existing filters allowlist must still work
    after this refactor."""

    def test_filter_injection_still_rejected(self, reader):
        r, base = reader
        with pytest.raises(ValueError):
            r.query_time_window(base - 1, base + 100, filters={"domain; DROP TABLE x; --": "x"})

    def test_valid_filter_still_works(self, reader):
        r, base = reader
        result = r.query_time_window(base - 1, base + 100, filters={"domain": "host1.example"})
        assert len(result.rows) == 1


class TestLimitStillBounded:
    def test_huge_limit_clamped(self, reader):
        r, base = reader
        result = r.query_time_window(base - 1, base + 100, limit=10_000_000)
        assert len(result.rows) == 2  # only 2 rows exist regardless of requested limit
