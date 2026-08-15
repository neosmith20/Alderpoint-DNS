"""V2 partition-aware DuckDB query layer for raw Parquet query history
(Workstream 2, §4-5).

Workstream 1's benchmark (`benchmarks/v2_analytics/`) used flat per-batch
segment files in one directory — it proved storage-format performance, not
that a real time-bounded query against the production
``YYYY/MM/DD/HH-<segment>.parquet`` layout actually skips irrelevant
partitions. This was explicitly tracked as a Workstream 2 gate
(``docs/v2/handoff-workstream-2.md`` gate 1).

This module closes that gap: ``enumerate_partition_files`` walks the
directory tree and prunes whole year/month/day branches that fall outside a
query's time range *before* any file is opened or handed to DuckDB, and
every query helper reports how many files it actually considered
(``QueryResult.files_considered``) so a test can assert a "last hour" query
touches a small, bounded file set rather than the entire history tree —
see ``tests/v2/test_analytics_query.py::test_last_hour_query_prunes_to_relevant_partitions_only``.

DuckDB is only ever pointed at the pre-pruned file list (via
``read_parquet([...])`` with an explicit array of paths), never a recursive
glob (``**/*.parquet``) — a recursive glob would still make DuckDB open
metadata for every file on disk before its own row-group statistics pruning
could help, defeating the purpose.

User-supplied filter values (domain, client, qtype, ...) are always passed
as DuckDB bound parameters (``?`` placeholders), never string-interpolated
into SQL — this is the SQL-injection-safety requirement from Workstream 2
§5/§33.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DEFAULT_LIMIT = 200
MAX_LIMIT = 2000

# Columns a caller may filter on. Deliberately a fixed allowlist — filter
# keys are used to build column references in SQL, so only ever accepting a
# name from this set (never an arbitrary caller-supplied string) is what
# makes that safe, independent of the fact that *values* are bound params.
_FILTERABLE_COLUMNS = frozenset({
    "client", "domain", "qtype", "protocol", "rcode", "blocked", "upstream",
    "cache_status", "cache_profile_id",
})

# Gate #2 MEDIUM finding: query_time_window() previously accepted a raw
# ``columns: str`` SQL projection fragment and a raw ``order_by: str`` SQL
# clause, interpolated directly into the generated query. Nothing in this
# codebase currently feeds user content into either (AnalyticsService's
# public methods never pass non-default values; the one internal caller,
# aggregates_db.rebuild_range_from_reader, only ever passes a fixed
# hardcoded string), but accepting arbitrary SQL fragments at all is a
# needless future injection surface -- removed in favor of an explicit
# allowlisted projection + a sort-column/sort-direction enum below, per
# the real Parquet segment schema (app/v2/parquet_writer.py's
# _COLUMN_NAMES).
_PROJECTABLE_COLUMNS = frozenset({
    "id", "ts", "client", "client_name", "domain", "qtype", "protocol",
    "rcode", "latency_ms", "blocked", "block_reason", "upstream",
    "cache_status", "cache_profile_id",
})
_SORTABLE_COLUMNS = frozenset({"ts", "latency_ms", "domain", "client"})
_SORT_DIRECTIONS = frozenset({"ASC", "DESC"})


@dataclass
class QueryResult:
    rows: list[tuple]
    files_considered: int
    columns: list[str] = field(default_factory=list)
    # Gate #2 Blocker 3C: True when this result is empty because the
    # DuckDB backend itself is unavailable, not because there's
    # legitimately no matching data -- callers (AnalyticsService, an
    # eventual UI) must be able to tell these apart rather than both
    # rendering as "no results."
    degraded: bool = False
    degraded_reason: str = ""


def enumerate_partition_files(root: Path, start_ts: float, end_ts: float) -> list[Path]:
    """Return only the segment files that can possibly contain a row with
    ``start_ts <= ts < end_ts``, by pruning at the directory-name level —
    never opening or even listing a day directory outside the range.

    Partition layout (written by app/v2/parquet_writer.py):
    ``root/YYYY/MM/DD/HH-<segment>.parquet`` (UTC).
    """
    root = Path(root)
    if not root.exists():
        return []

    start_dt = datetime.fromtimestamp(start_ts, tz=timezone.utc)
    end_dt = datetime.fromtimestamp(end_ts, tz=timezone.utc)
    start_date = start_dt.date()
    end_date = end_dt.date()

    files: list[Path] = []
    # Only descend into year dirs that are numeric and within range.
    for year_dir in sorted(root.iterdir()):
        if not year_dir.is_dir() or not year_dir.name.isdigit():
            continue
        year = int(year_dir.name)
        if year < start_date.year or year > end_date.year:
            continue
        for month_dir in sorted(year_dir.iterdir()):
            if not month_dir.is_dir() or not month_dir.name.isdigit():
                continue
            month = int(month_dir.name)
            # Prune months outside range for boundary years.
            if year == start_date.year and month < start_date.month:
                continue
            if year == end_date.year and month > end_date.month:
                continue
            for day_dir in sorted(month_dir.iterdir()):
                if not day_dir.is_dir() or not day_dir.name.isdigit():
                    continue
                day = int(day_dir.name)
                try:
                    this_date = datetime(year, month, day, tzinfo=timezone.utc).date()
                except ValueError:
                    continue
                if this_date < start_date or this_date > end_date:
                    continue
                is_start_boundary = this_date == start_date
                is_end_boundary = this_date == end_date
                for f in sorted(day_dir.glob("*.parquet")):
                    if not is_start_boundary and not is_end_boundary:
                        # Fully interior day: every hour is in range.
                        files.append(f)
                        continue
                    try:
                        hour = int(f.name.split("-", 1)[0])
                    except (ValueError, IndexError):
                        # Unrecognized filename shape — include it rather
                        # than silently drop possibly-relevant data; DuckDB's
                        # own predicate on `ts` still filters it correctly.
                        files.append(f)
                        continue
                    file_hour_start = datetime(year, month, day, hour, tzinfo=timezone.utc)
                    file_hour_end = file_hour_start + timedelta(hours=1)
                    if file_hour_end.timestamp() <= start_ts or file_hour_start.timestamp() >= end_ts:
                        continue  # this specific hour segment is outside the range
                    files.append(f)
    return files


class PartitionPruningReader:
    """DuckDB-backed reader over a Parquet raw-history tree. One instance may
    be reused across queries (keeps a single in-memory DuckDB connection);
    ``close()`` releases it. Tolerates segment deletion happening
    concurrently (retention) between enumeration and query — a file that
    vanishes between ``enumerate_partition_files`` and the DuckDB scan is
    just skipped by re-filtering the list against current existence
    immediately before querying (§5's "readers tolerate segment deletion
    during retention" requirement).
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self._con = None

    def _connect(self):
        from app.v2.analytics_deps import ensure_on_path

        ensure_on_path()
        import duckdb

        if self._con is None:
            self._con = duckdb.connect(":memory:")
        return self._con

    def close(self) -> None:
        if self._con is not None:
            self._con.close()
            self._con = None

    def _files_for_range(self, start_ts: float, end_ts: float) -> list[Path]:
        candidates = enumerate_partition_files(self.root, start_ts, end_ts)
        # Re-check existence right before use: retention may have deleted a
        # segment between enumeration and query. Also validate each
        # candidate (cheap metadata-only open) so a corrupted closed segment
        # is silently excluded here rather than raising out of DuckDB later
        # — one bad segment must never break a query over the rest of
        # history (§8/§33 failure-isolation requirement).
        from app.v2.parquet_writer import validate_segment, SegmentValidationError

        good = []
        for f in candidates:
            if not f.exists():
                continue
            try:
                validate_segment(f)
                good.append(f)
            except SegmentValidationError:
                continue
        return good

    def _scan_source(self, files: list[Path]) -> str | None:
        if not files:
            return None
        escaped = ", ".join("'" + str(f).replace("'", "''") + "'" for f in files)
        return f"read_parquet([{escaped}])"

    def query_time_window(
        self,
        start_ts: float,
        end_ts: float,
        *,
        filters: dict[str, Any] | None = None,
        columns: list[str] | None = None,
        sort_column: str | None = "ts",
        sort_direction: str = "DESC",
        limit: int = DEFAULT_LIMIT,
        offset: int = 0,
    ) -> QueryResult:
        """Bounded, parameterized time-window query with optional equality
        filters. ``filters`` keys must be in ``_FILTERABLE_COLUMNS``, and
        ``columns``/``sort_column``/``sort_direction`` must be in
        ``_PROJECTABLE_COLUMNS``/``_SORTABLE_COLUMNS``/``_SORT_DIRECTIONS``
        respectively (fixed allowlists/enums, never caller-controlled raw
        SQL fragments) — anything else raises ValueError rather than being
        silently ignored or interpolated. ``columns=None`` means every
        column (``SELECT *``); ``sort_column=None`` means unsorted.
        """
        limit = max(1, min(limit, MAX_LIMIT))
        offset = max(0, min(int(offset), 100_000))

        if columns is None:
            projection = "*"
        else:
            invalid = [c for c in columns if c not in _PROJECTABLE_COLUMNS]
            if invalid:
                raise ValueError(f"unsupported projection column(s): {invalid}")
            if not columns:
                raise ValueError("columns, if given, must not be empty")
            projection = ", ".join(columns)

        if sort_direction not in _SORT_DIRECTIONS:
            raise ValueError(f"sort_direction must be one of {sorted(_SORT_DIRECTIONS)}")
        if sort_column is not None and sort_column not in _SORTABLE_COLUMNS:
            raise ValueError(f"unsupported sort_column: {sort_column!r}")

        files = self._files_for_range(start_ts, end_ts)
        if not files:
            return QueryResult(rows=[], files_considered=0)

        con = self._connect()
        src = self._scan_source(files)
        params: list[Any] = [start_ts, end_ts]
        where = ["ts >= ?", "ts < ?"]
        for key, value in (filters or {}).items():
            if key not in _FILTERABLE_COLUMNS:
                raise ValueError(f"unsupported filter column: {key!r}")
            where.append(f"{key} = ?")
            params.append(value)
        sql = f"SELECT {projection} FROM {src} WHERE " + " AND ".join(where)
        if sort_column is not None:
            sql += f" ORDER BY {sort_column} {sort_direction}"
        sql += f" LIMIT {limit} OFFSET {offset}"
        rows = con.execute(sql, params).fetchall()
        return QueryResult(rows=rows, files_considered=len(files))

    def query_recent(
        self, *, minutes: float, filters: dict[str, Any] | None = None,
        limit: int = DEFAULT_LIMIT, offset: int = 0, now: float | None = None,
    ) -> QueryResult:
        import time as _time

        now = now if now is not None else _time.time()
        return self.query_time_window(now - minutes * 60, now, filters=filters, limit=limit, offset=offset)

    def top_n(
        self, column: str, start_ts: float, end_ts: float, *,
        only_blocked: bool = False, limit: int = 20,
    ) -> QueryResult:
        if column not in _FILTERABLE_COLUMNS:
            raise ValueError(f"unsupported column: {column!r}")
        limit = max(1, min(limit, MAX_LIMIT))
        files = self._files_for_range(start_ts, end_ts)
        if not files:
            return QueryResult(rows=[], files_considered=0)
        con = self._connect()
        src = self._scan_source(files)
        where = "ts >= ? AND ts < ?"
        params: list[Any] = [start_ts, end_ts]
        if only_blocked:
            where += " AND blocked"
        sql = (
            f"SELECT {column}, COUNT(*) c FROM {src} WHERE {where} "
            f"GROUP BY {column} ORDER BY c DESC LIMIT {limit}"
        )
        rows = con.execute(sql, params).fetchall()
        return QueryResult(rows=rows, files_considered=len(files))

    def rcode_distribution(self, start_ts: float, end_ts: float) -> QueryResult:
        files = self._files_for_range(start_ts, end_ts)
        if not files:
            return QueryResult(rows=[], files_considered=0)
        con = self._connect()
        src = self._scan_source(files)
        sql = f"SELECT rcode, COUNT(*) FROM {src} WHERE ts >= ? AND ts < ? GROUP BY rcode"
        rows = con.execute(sql, [start_ts, end_ts]).fetchall()
        return QueryResult(rows=rows, files_considered=len(files))

    def latency_percentiles(self, start_ts: float, end_ts: float) -> QueryResult:
        files = self._files_for_range(start_ts, end_ts)
        if not files:
            return QueryResult(rows=[], files_considered=0)
        con = self._connect()
        src = self._scan_source(files)
        sql = (
            f"SELECT median(latency_ms), quantile_cont(latency_ms, 0.95), "
            f"quantile_cont(latency_ms, 0.99) FROM {src} WHERE ts >= ? AND ts < ?"
        )
        rows = con.execute(sql, [start_ts, end_ts]).fetchall()
        return QueryResult(rows=rows, files_considered=len(files))
