"""V2 analytics query service (Workstream 3 continuation, §15).

Thin, bounded, named orchestration layer over Workstream 2's two real
analytics backends -- ``app/v2/analytics_query.py`` (partition-pruned
DuckDB reader over raw Parquet history, for detail views) and
``app/v2/aggregates_db.py`` (bounded SQLite rollups, for cheap dashboard
summaries) -- so a management/API caller has one set of named, bounded
methods instead of hand-rolling SQL against either backend directly. Every
method here is still a bounded read; nothing writes, and nothing is on the
DNS hot path.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from app.v2 import aggregates_db
from app.v2.analytics_query import PartitionPruningReader, QueryResult

DEFAULT_TOP_N = 20


@dataclass
class AnalyticsService:
    parquet_root: Path
    aggregates_path: Path

    def __post_init__(self) -> None:
        self._reader = PartitionPruningReader(self.parquet_root)

    def close(self) -> None:
        self._reader.close()

    # --- detail views (Parquet, partition-pruned) ---------------------------

    def recent_query_log(
        self, *, minutes: float = 60.0, filters: Optional[dict[str, Any]] = None,
        limit: int = 200, now: Optional[float] = None,
    ) -> QueryResult:
        return self._reader.query_recent(minutes=minutes, filters=filters, limit=limit, now=now)

    def search(
        self, start_ts: float, end_ts: float, *, domain: Optional[str] = None,
        client: Optional[str] = None, blocked_only: bool = False, limit: int = 200,
    ) -> QueryResult:
        filters: dict[str, Any] = {}
        if domain is not None:
            filters["domain"] = domain
        if client is not None:
            filters["client"] = client
        if blocked_only:
            filters["blocked"] = True
        return self._reader.query_time_window(start_ts, end_ts, filters=filters, limit=limit)

    def top_domains(self, start_ts: float, end_ts: float, *, limit: int = DEFAULT_TOP_N) -> QueryResult:
        return self._reader.top_n("domain", start_ts, end_ts, limit=limit)

    def top_blocked_domains(self, start_ts: float, end_ts: float, *, limit: int = DEFAULT_TOP_N) -> QueryResult:
        return self._reader.top_n("domain", start_ts, end_ts, only_blocked=True, limit=limit)

    def top_clients(self, start_ts: float, end_ts: float, *, limit: int = DEFAULT_TOP_N) -> QueryResult:
        return self._reader.top_n("client", start_ts, end_ts, limit=limit)

    def top_upstreams(self, start_ts: float, end_ts: float, *, limit: int = DEFAULT_TOP_N) -> QueryResult:
        return self._reader.top_n("upstream", start_ts, end_ts, limit=limit)

    def protocol_distribution(self, start_ts: float, end_ts: float, *, limit: int = DEFAULT_TOP_N) -> QueryResult:
        return self._reader.top_n("protocol", start_ts, end_ts, limit=limit)

    def qtype_distribution(self, start_ts: float, end_ts: float, *, limit: int = DEFAULT_TOP_N) -> QueryResult:
        return self._reader.top_n("qtype", start_ts, end_ts, limit=limit)

    def rcode_distribution(self, start_ts: float, end_ts: float) -> QueryResult:
        return self._reader.rcode_distribution(start_ts, end_ts)

    def cache_status_distribution(self, start_ts: float, end_ts: float, *, limit: int = DEFAULT_TOP_N) -> QueryResult:
        return self._reader.top_n("cache_status", start_ts, end_ts, limit=limit)

    def latency_percentiles(self, start_ts: float, end_ts: float) -> QueryResult:
        return self._reader.latency_percentiles(start_ts, end_ts)

    # --- cheap dashboard summaries (aggregate SQLite, bucketed) --------------

    def time_series_totals(
        self, start_ts: float, end_ts: float, *, granularity: str = "hour",
    ) -> list[tuple]:
        """Bucketed (total, blocked, cache_hits, cache_misses) rows --
        cheap enough for a dashboard chart, deliberately not backed by a
        Parquet scan."""
        return aggregates_db.query_totals(
            self.aggregates_path, start_ts, end_ts, granularity=granularity
        )

    def top_dimension_from_aggregates(
        self, dimension: str, start_ts: float, end_ts: float, *,
        granularity: str = "hour", limit: int = DEFAULT_TOP_N,
    ) -> list[tuple]:
        return aggregates_db.query_dimension_top(
            self.aggregates_path, dimension, start_ts, end_ts,
            granularity=granularity, limit=limit,
        )
