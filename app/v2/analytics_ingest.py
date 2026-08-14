"""V2 analytics ingestion boundary prototype.

Scope (V2 Workstream 1): implements the failure-isolation contract from
``docs/v2/failure-domains.md`` — a bounded in-memory queue feeding batched,
atomically-promoted segment files, with an explicit overflow-drop policy.
This is a prototype used to validate the design and drive
``docs/v2/benchmark-results.md``; it is not wired into the live
``alderpointdns-analytics.service``.

Design:
- ``BoundedQueue`` is a fixed-capacity ring buffer. On overflow it drops the
  oldest queued record and increments ``dropped_count`` (oldest-first drop,
  matching "DNS continuity preferred over analytics completeness").
- ``SegmentWriter`` batches queued records into a segment file, written to a
  temp name in the target directory and atomically promoted (``os.replace``)
  to its final name only once fully written — a reader can never observe a
  half-written segment because it only globs the final naming pattern.
- Any exception raised while flushing a batch is caught at the writer
  boundary and recorded, never propagated to the caller feeding the queue
  (which stands in for the dnsdist protobuf receiver in the real pipeline).
"""

from __future__ import annotations

import gzip
import json
import os
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class BoundedQueue:
    """Fixed-capacity, oldest-first-drop queue for analytics records."""

    capacity: int
    _items: deque = field(default_factory=deque, repr=False)
    dropped_count: int = 0

    def __post_init__(self) -> None:
        if self.capacity <= 0:
            raise ValueError("capacity must be positive")

    def push(self, record: dict) -> None:
        if len(self._items) >= self.capacity:
            self._items.popleft()  # drop oldest, not newest — keep recent data
            self.dropped_count += 1
        self._items.append(record)

    def drain(self, max_items: int | None = None) -> list[dict]:
        n = len(self._items) if max_items is None else min(max_items, len(self._items))
        return [self._items.popleft() for _ in range(n)]

    def __len__(self) -> int:
        return len(self._items)


@dataclass
class WriterStats:
    segments_written: int = 0
    flush_failures: int = 0
    last_error: str | None = None


class SegmentWriter:
    """Batches records into gzip-JSONL segments with atomic temp->final promotion.

    (JSONL chosen for this prototype for zero extra dependencies; the real
    V2 raw-history backend is decided in docs/v2/benchmark-results.md and may
    differ — this class only demonstrates/tests the ingestion boundary
    pattern, not the storage-format decision.)
    """

    def __init__(self, root: Path, *, clock: Callable[[], float] = time.time):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._segment_idx = 0
        self.stats = WriterStats()

    def _tmp_path(self) -> Path:
        return self.root / f".segment-{self._segment_idx:06d}.jsonl.gz.tmp"

    def _final_path(self, idx: int) -> Path:
        return self.root / f"segment-{idx:06d}.jsonl.gz"

    def flush_batch(self, records: list[dict]) -> bool:
        """Write one segment. Returns True on success. Never raises — a
        writer failure must not propagate into the caller (the ingestion
        queue / dnsdist receiver stand-in), per the failure-domain contract.
        """
        if not records:
            return True
        idx = self._segment_idx
        tmp_path = self._tmp_path()
        try:
            with gzip.open(tmp_path, "wt") as fh:
                for rec in records:
                    fh.write(json.dumps(rec) + "\n")
            os.replace(tmp_path, self._final_path(idx))
            self._segment_idx += 1
            self.stats.segments_written += 1
            return True
        except Exception as exc:  # noqa: BLE001 - intentional catch-all at the isolation boundary
            self.stats.flush_failures += 1
            self.stats.last_error = str(exc)
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            return False

    def simulate_crash_mid_write(self, records: list[dict]) -> None:
        """Test helper: write a temp segment and leave it in place (as if the
        process died before the rename). Used to verify readers ignore it.
        """
        tmp_path = self._tmp_path()
        with gzip.open(tmp_path, "wt") as fh:
            for rec in records:
                fh.write(json.dumps(rec) + "\n")
            fh.flush()
        # deliberately no os.replace() — this models a mid-write crash
        self._segment_idx += 1


def read_complete_segments(root: Path) -> list[dict]:
    """Reader: only ever globs finalized ``segment-*.jsonl.gz`` names, so an
    in-progress ``.segment-*.jsonl.gz.tmp`` file is structurally invisible to
    it — no partially-written history is ever exposed as valid.
    """
    records: list[dict] = []
    for p in sorted(Path(root).glob("segment-*.jsonl.gz")):
        with gzip.open(p, "rt") as fh:
            for line in fh:
                records.append(json.loads(line))
    return records


def delete_oldest_closed_segments(root: Path, *, keep_newest: int) -> list[Path]:
    """Retention: delete oldest closed segments, always preserving the
    ``keep_newest`` most recent ones (the writer's current/most-recent
    segment must never be the one deleted out from under an active writer —
    callers should pass keep_newest >= 1 whenever a writer may still be
    active). Never touches ``.tmp`` files — those aren't matched by the glob.
    """
    segments = sorted(Path(root).glob("segment-*.jsonl.gz"))
    to_delete = segments[:-keep_newest] if keep_newest > 0 else segments
    for p in to_delete:
        p.unlink()
    return to_delete
