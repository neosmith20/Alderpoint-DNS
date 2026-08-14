"""V2 real Parquet raw-query-history writer (Workstream 2, §2-3).

Replaces the Workstream 1 JSONL-prototype writer (``app/v2/analytics_ingest.py``,
kept unmodified as the documented ingestion-boundary reference) with the
frozen production storage decision from ``docs/v2/architecture-map.md``:
Parquet + Zstandard (level 6 default) + DuckDB, partitioned
``YYYY/MM/DD/HH-<segment>.parquet``.

Design constraints carried over from the failure-domain contract
(``docs/v2/failure-domains.md``):

- Bounded, batched ingestion — no synchronous per-query disk write, no
  unbounded in-memory accumulation (a segment rotates on row count OR
  elapsed time, whichever comes first).
- Every segment is written to a temp name and only exposed to readers via
  ``os.replace`` once fully written *and* independently re-opened and
  schema/row-count validated — a reader globbing ``*.parquet`` can never
  observe a partially-written or corrupt segment.
- A writer failure (disk full, permission error, corrupt intermediate state)
  is caught at this boundary and recorded in ``WriterStats``, never raised
  into the caller feeding the queue — matching the pattern already
  established by ``analytics_ingest.SegmentWriter.flush_batch``.
- ``pyarrow`` is imported lazily (function/method-local) so importing this
  module doesn't require the dependency unless a Parquet segment is actually
  being written/read — consistent with
  ``benchmarks/v2_analytics/backends.py``. Tests that exercise this module
  must run under the dev benchmark venv (``dev/.venv-v2-bench``), which is
  the same constraint already documented for the Workstream 1 benchmark
  harness.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# --- schema ------------------------------------------------------------------

# Column set matches the benchmark harness (benchmarks/v2_analytics/backends.py
# ParquetDuckDbBackend) plus one addition: cache_profile_id, so a query-history
# row can record which effective cache profile (app/v2/cache_profile.py)
# produced the answer — useful for later cache-behavior analysis without
# forcing every existing field to change shape.
_COLUMN_NAMES: tuple[str, ...] = (
    "id", "ts", "client", "client_name", "domain", "qtype", "protocol",
    "rcode", "latency_ms", "blocked", "block_reason", "upstream",
    "cache_status", "cache_profile_id",
)


def _pa_schema():
    import pyarrow as pa

    return pa.schema([
        ("id", pa.int64()),
        ("ts", pa.float64()),
        ("client", pa.string()),
        ("client_name", pa.string()),
        ("domain", pa.string()),
        ("qtype", pa.string()),
        ("protocol", pa.string()),
        ("rcode", pa.string()),
        ("latency_ms", pa.float64()),
        ("blocked", pa.bool_()),
        ("block_reason", pa.string()),
        ("upstream", pa.string()),
        ("cache_status", pa.string()),
        ("cache_profile_id", pa.string()),
    ])


class SegmentValidationError(RuntimeError):
    """Raised internally when a just-written temp segment fails validation.
    Always caught inside this module — never propagates to ingest() callers.
    """


@dataclass
class WriterStats:
    segments_written: int = 0
    segments_rejected: int = 0
    rows_written: int = 0
    dropped_count: int = 0
    flush_failures: int = 0
    last_error: str | None = None


def _partition_dir(root: Path, ts: float) -> Path:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return root / f"{dt.year:04d}" / f"{dt.month:02d}" / f"{dt.day:02d}"


def _partition_hour(ts: float) -> int:
    return datetime.fromtimestamp(ts, tz=timezone.utc).hour


class ParquetSegmentWriter:
    """Batches records into partitioned, Zstd-compressed Parquet segments.

    One writer instance owns one logical stream of raw query-history rows.
    Records are buffered in memory only up to ``max_rows_per_segment`` (or
    until ``max_seconds_per_segment`` elapses since the first buffered
    record), so memory use is bounded by that config, not by ingest volume.
    """

    def __init__(
        self,
        root: Path,
        *,
        max_rows_per_segment: int = 50_000,
        max_seconds_per_segment: float = 3600.0,
        row_group_size: int = 50_000,
        zstd_level: int = 6,
        clock=time.time,
    ):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.max_rows_per_segment = max_rows_per_segment
        self.max_seconds_per_segment = max_seconds_per_segment
        self.row_group_size = row_group_size
        self.zstd_level = zstd_level
        self._clock = clock
        self._buffer: list[dict] = []
        self._buffer_started_at: float | None = None
        self._segment_counters: dict[Path, int] = {}  # per-partition-dir next index
        self.stats = WriterStats()

    def ingest(self, records: Iterable[dict]) -> None:
        """Queue records for writing. Never raises — a malformed record is
        dropped and counted, not allowed to crash the ingestion path (the
        DNS-answering path must never depend on this call succeeding)."""
        for rec in records:
            if not isinstance(rec, dict) or "ts" not in rec:
                self.stats.dropped_count += 1
                continue
            if self._buffer_started_at is None:
                self._buffer_started_at = self._clock()
            self._buffer.append(rec)
            if len(self._buffer) >= self.max_rows_per_segment:
                self.flush()
        self.maybe_rotate_on_time()

    def maybe_rotate_on_time(self) -> None:
        if (
            self._buffer
            and self._buffer_started_at is not None
            and (self._clock() - self._buffer_started_at) >= self.max_seconds_per_segment
        ):
            self.flush()

    def flush(self) -> bool:
        """Write the current buffer as one closed segment. Returns True on
        success (including the no-op case of an empty buffer). Never raises.
        """
        if not self._buffer:
            return True
        records = self._buffer
        self._buffer = []
        self._buffer_started_at = None

        # Partition by the first record's timestamp — a segment's own rows
        # may span a boundary in rare cases (buffer flushed right at an hour
        # rollover); that's acceptable, the partition is a query-pruning
        # optimization, not a correctness requirement enforced per-row.
        partition_ts = records[0]["ts"]
        partition_dir = _partition_dir(self.root, partition_ts)
        hour = _partition_hour(partition_ts)

        try:
            partition_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._record_failure(records, exc)
            return False

        if partition_dir not in self._segment_counters:
            self._segment_counters[partition_dir] = self._next_index_for(partition_dir, hour)
        idx = self._segment_counters[partition_dir]
        tmp_path = partition_dir / f".{hour:02d}-{idx:06d}.parquet.tmp"
        final_path = partition_dir / f"{hour:02d}-{idx:06d}.parquet"

        try:
            self._write_and_validate(records, tmp_path)
            os.replace(tmp_path, final_path)  # atomic promote
            self._segment_counters[partition_dir] = idx + 1
            self.stats.segments_written += 1
            self.stats.rows_written += len(records)
            return True
        except Exception as exc:  # noqa: BLE001 — isolation boundary, must not propagate
            self.stats.segments_rejected += 1
            self._record_failure(records, exc)
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            return False

    def _next_index_for(self, partition_dir: Path, hour: int) -> int:
        """Seed the segment index for a partition directory from whatever
        finalized segments already exist there — a fresh writer instance
        (e.g. a restarted process, or the first flush into a directory an
        earlier process already wrote to) must never reuse an existing
        segment's filename, which would silently overwrite finalized
        history instead of appending to it."""
        if not partition_dir.exists():
            return 0
        prefix = f"{hour:02d}-"
        existing = [
            p.name for p in partition_dir.glob(f"{prefix}*.parquet")
        ]
        if not existing:
            return 0
        indices = []
        for name in existing:
            try:
                indices.append(int(name[len(prefix):].split(".")[0]))
            except ValueError:
                continue
        return (max(indices) + 1) if indices else 0

    def _record_failure(self, records: list[dict], exc: Exception) -> None:
        self.stats.flush_failures += 1
        self.stats.last_error = str(exc)
        self.stats.dropped_count += len(records)

    def _write_and_validate(self, records: list[dict], tmp_path: Path) -> None:
        import pyarrow as pa
        import pyarrow.parquet as pq

        # Normalize each record to exactly the expected columns — extra keys
        # are dropped, missing keys become None, rather than letting
        # pa.Table.from_pylist raise on the first malformed row and lose the
        # whole batch. cache_profile_id is optional (Workstream 1-era callers
        # won't have it yet).
        normalized = [
            {col: rec.get(col) for col in _COLUMN_NAMES} for rec in records
        ]
        schema = _pa_schema()
        table = pa.Table.from_pylist(normalized, schema=schema)
        pq.write_table(
            table,
            tmp_path,
            compression="zstd",
            compression_level=self.zstd_level,
            row_group_size=self.row_group_size,
        )
        validate_segment(tmp_path, expected_min_rows=len(records))

    def close(self) -> None:
        self.flush()


def validate_segment(path: Path, *, expected_min_rows: int | None = None) -> None:
    """Re-open a just-written (or existing) Parquet file and verify it's
    structurally sound before it's trusted as valid history. Raises
    SegmentValidationError on any problem; callers decide what to do with
    that (writer: reject and count; reader: skip and count, see
    ``app/v2/analytics_query.py``).
    """
    import pyarrow.parquet as pq

    try:
        pf = pq.ParquetFile(str(path))
    except Exception as exc:  # noqa: BLE001
        raise SegmentValidationError(f"unreadable parquet file: {exc}") from exc

    file_schema_names = set(pf.schema_arrow.names)
    expected = set(_COLUMN_NAMES)
    if not expected.issubset(file_schema_names):
        missing = expected - file_schema_names
        raise SegmentValidationError(f"missing expected columns: {sorted(missing)}")

    num_rows = pf.metadata.num_rows
    if expected_min_rows is not None and num_rows < expected_min_rows:
        raise SegmentValidationError(
            f"row count {num_rows} below expected minimum {expected_min_rows}"
        )
    if num_rows == 0:
        raise SegmentValidationError("segment has zero rows")


def cleanup_orphaned_temp_files(root: Path, *, older_than_seconds: float = 3600.0) -> list[Path]:
    """Restart-safety sweep: a ``.HH-NNNNNN.parquet.tmp`` file left behind by
    a process that died mid-write is never picked up by any reader (readers
    only glob ``*.parquet``), but it wastes disk indefinitely if never
    cleaned. Only removes temp files older than ``older_than_seconds`` so an
    actively-writing process's own in-progress temp file is never touched by
    a concurrent cleanup pass.
    """
    removed = []
    cutoff = time.time() - older_than_seconds
    for tmp in Path(root).rglob(".*.parquet.tmp"):
        try:
            if tmp.stat().st_mtime < cutoff:
                tmp.unlink()
                removed.append(tmp)
        except OSError:
            pass
    return removed


def list_valid_segments(root: Path) -> list[Path]:
    """All finalized (non-temp) segment files under root, validated. Segments
    that fail validation (e.g. corrupted after being closed — disk
    corruption, truncated copy) are skipped, not raised — a single bad
    segment must never take down a reader over the rest of history."""
    valid = []
    for p in sorted(Path(root).rglob("*.parquet")):
        try:
            validate_segment(p)
            valid.append(p)
        except SegmentValidationError:
            continue
    return valid
