"""Beta-rescue regression: independent execution against RC42 found the
analytics backend returning positional rows (plain tuples/arrays) with
``"columns": []`` while the UI derived column identity via
``Object.keys(row)`` -- correct for real objects, but producing literal
"0", "1", "2", ... headers against a positional row once real data
existed. Reproduced here with real, populated query-history data written
through the real Parquet segment writer, exactly as the beta-rescue brief
requires ("Reproduce using real query-history data").
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

pytest.importorskip("pyarrow")
pytest.importorskip("duckdb")

from app.v2.parquet_writer import ParquetSegmentWriter, _COLUMN_NAMES  # noqa: E402
from app.v2.analytics_query import PartitionPruningReader  # noqa: E402
from app.v2.analytics_service import AnalyticsService  # noqa: E402


def _write_real_rows(root: Path, n: int = 5) -> float:
    w = ParquetSegmentWriter(root, max_rows_per_segment=n + 1)
    now = time.time()
    for i in range(n):
        w.ingest([{
            "id": i, "ts": now - i, "client": "192.168.32.56", "client_name": "",
            "domain": "blocked.example" if i % 2 == 0 else "ok.example",
            "qtype": "AAAA", "protocol": "doh", "rcode": "NXDOMAIN" if i % 2 == 0 else "NOERROR",
            "latency_ms": 2.5, "blocked": i % 2 == 0, "block_reason": "security" if i % 2 == 0 else None,
            "upstream": "1.1.1.1", "cache_status": "miss", "cache_profile_id": "p1",
        }])
    w.flush()
    return now


class TestAnalyticsApiContractHasRealNamedColumns:
    def test_recent_query_log_returns_named_columns_matching_row_order(self, tmp_path):
        root = tmp_path / "parquet"
        _write_real_rows(root)
        reader = PartitionPruningReader(root)
        try:
            result = reader.query_recent(minutes=60)
        finally:
            reader.close()
        assert result.rows, "fixture didn't actually write real rows"
        assert result.columns == list(_COLUMN_NAMES), (
            "API contract regression: recent query-log rows must carry the "
            "same explicit named-column list the frontend renders against, "
            "not an empty columns list next to positional rows"
        )
        blocked_idx = result.columns.index("blocked")
        domain_idx = result.columns.index("domain")
        # Real typed field, not a string search over the row.
        for row in result.rows:
            if row[domain_idx] == "blocked.example":
                assert row[blocked_idx] is True

    def test_top_domains_returns_named_columns(self, tmp_path):
        root = tmp_path / "parquet"
        now = _write_real_rows(root)
        svc = AnalyticsService(parquet_root=root, aggregates_path=tmp_path / "agg.db")
        try:
            result = svc.top_domains(now - 3600, now + 1)
        finally:
            svc.close()
        assert result.columns == ["domain", "count"]
        assert result.rows

    def test_empty_range_still_returns_named_columns_not_bare_empty_list(self, tmp_path):
        root = tmp_path / "parquet"
        reader = PartitionPruningReader(root)
        try:
            result = reader.query_time_window(0, 1, columns=["ts", "domain"])
        finally:
            reader.close()
        assert result.rows == []
        assert result.columns == ["ts", "domain"]
