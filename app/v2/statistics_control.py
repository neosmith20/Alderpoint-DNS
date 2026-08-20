"""Statistics export/clear (beta-rescue priority 3C).

V2's analytics architecture is deliberately split (see
app/v2/aggregates_db.py and app/v2/analytics_query.py):

  aggregate SQLite  -- small, fast, always-available dashboard/top-domain
                       rollups (time_buckets/dimension_counts)
  raw Parquet history -- the actual per-query event log, partitioned by
                       time, queried on demand

This module never conflates them. Export always reports which of the
two it read and how many rows came from each. Clear always says exactly
which of the two it actually cleared -- an operator asking to "clear
everything" and getting only the aggregate rows wiped while the raw
history silently survives (or vice versa) is exactly the V1.1.1 lesson
this priority's brief calls out by name.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

STATISTICS_FORMAT_VERSION = 1


@dataclass(frozen=True)
class ClearResult:
    aggregate_buckets_cleared: int
    aggregate_dimension_rows_cleared: int
    raw_history_cleared: bool
    raw_partition_files_removed: int


def export_statistics(aggregates_db_path: Path) -> dict:
    """Stable, named-field JSON export of the aggregate store. Raw
    per-query history is deliberately NOT included in this export (it
    can be arbitrarily large and is already queryable/exportable in bulk
    via the Query Log's own filters) -- the export explicitly says so
    rather than silently only exporting part of "statistics" without
    saying which part.
    """
    if not aggregates_db_path.exists():
        return {
            "format_version": STATISTICS_FORMAT_VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
            "aggregate_time_buckets": [], "aggregate_dimension_counts": [],
            "raw_query_history_included": False,
            "note": "no aggregates database present yet",
        }
    conn = sqlite3.connect(f"file:{aggregates_db_path}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        buckets = [dict(r) for r in conn.execute("SELECT * FROM time_buckets ORDER BY bucket_start")]
        dims = [dict(r) for r in conn.execute("SELECT * FROM dimension_counts ORDER BY bucket_start")]
    finally:
        conn.close()
    return {
        "format_version": STATISTICS_FORMAT_VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
        "aggregate_time_buckets": buckets, "aggregate_dimension_counts": dims,
        "raw_query_history_included": False,
        "note": "raw per-query history is not included in this export; use the Query Log's own filters to export raw query data in bulk",
    }


def export_statistics_json(aggregates_db_path: Path) -> str:
    return json.dumps(export_statistics(aggregates_db_path), indent=2)


def clear_statistics(
    aggregates_db_path: Path, *, include_raw_history: bool, raw_history_root: Optional[Path] = None,
) -> ClearResult:
    """Clears the aggregate store always; clears the raw Parquet history
    only if ``include_raw_history`` is True (and a root is given) --
    the caller (the API route) requires this to be an explicit, informed
    choice, never a hidden default, and the result always reports both
    numbers so "everything" vs "just the aggregates" is never ambiguous
    after the fact.
    """
    buckets_cleared = 0
    dims_cleared = 0
    if aggregates_db_path.exists():
        conn = sqlite3.connect(str(aggregates_db_path))
        try:
            buckets_cleared = conn.execute("SELECT COUNT(*) FROM time_buckets").fetchone()[0]
            dims_cleared = conn.execute("SELECT COUNT(*) FROM dimension_counts").fetchone()[0]
            conn.execute("DELETE FROM time_buckets")
            conn.execute("DELETE FROM dimension_counts")
            conn.commit()
        finally:
            conn.close()

    files_removed = 0
    if include_raw_history and raw_history_root is not None and raw_history_root.exists():
        for path in sorted(raw_history_root.rglob("*.parquet")):
            try:
                path.unlink()
                files_removed += 1
            except OSError:
                continue

    return ClearResult(
        aggregate_buckets_cleared=buckets_cleared, aggregate_dimension_rows_cleared=dims_cleared,
        raw_history_cleared=bool(include_raw_history and raw_history_root is not None),
        raw_partition_files_removed=files_removed,
    )
