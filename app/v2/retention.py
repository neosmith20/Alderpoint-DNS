"""V2 raw-history retention: real Parquet implementation (Workstream 2, §6).

Bounded retention against real segment files written by
``app/v2/parquet_writer.py``. Both policies are cheap filesystem deletion —
no DELETE/VACUUM against a database, matching the frozen architecture
(``docs/v2/architecture-map.md``: "no million-row DELETE operations",
"no VACUUM required").

Safety properties:

- Only ever globs ``*.parquet`` (finalized segments) — an in-progress
  ``.HH-NNNNNN.parquet.tmp`` file can never match this pattern, so retention
  structurally cannot delete a writer's in-flight file.
- ``protect_most_recent`` always keeps the N most-recently-modified segments
  regardless of age/size policy, as defense in depth against a retention run
  racing a writer that just promoted a segment moments ago.
- Orphaned temp files (writer crashed mid-write, never called
  ``os.replace``) are handled separately by
  ``app.v2.parquet_writer.cleanup_orphaned_temp_files`` — retention does not
  touch them at all, by construction (glob pattern), so the two concerns
  stay cleanly separated.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RetentionResult:
    deleted: list[Path] = field(default_factory=list)
    deleted_bytes: int = 0
    kept_count: int = 0
    errors: list[str] = field(default_factory=list)


def _all_segments_by_age(root: Path) -> list[Path]:
    """Finalized segments, oldest (by mtime) first. mtime is used rather than
    the partition-path-encoded date because it reflects when the file was
    actually promoted on this filesystem, which is what "oldest" should mean
    for a deletion policy — robust to a segment being copied/restored with a
    path that encodes an old date but a fresh mtime, or vice versa."""
    # Sort by path first so that mtime ties (same-second writes, or a test
    # deliberately setting equal mtimes) break in filename order — segment
    # filenames are zero-padded incrementing indices, so path order matches
    # write order whenever mtime resolution can't distinguish them.
    segments = sorted(root.rglob("*.parquet"))
    segments.sort(key=lambda p: p.stat().st_mtime)
    return segments


def _delete_paths(paths: list[Path]) -> RetentionResult:
    result = RetentionResult()
    for p in paths:
        try:
            size = p.stat().st_size
            p.unlink()
            result.deleted.append(p)
            result.deleted_bytes += size
        except OSError as exc:
            result.errors.append(f"{p}: {exc}")
    return result


def delete_by_age(
    root: Path, *, max_age_seconds: float, now: float | None = None,
    protect_most_recent: int = 1,
) -> RetentionResult:
    """Delete closed segments older than ``max_age_seconds``, oldest first,
    always keeping the ``protect_most_recent`` newest segments no matter how
    old the policy would otherwise call for."""
    now = now if now is not None else time.time()
    segments = _all_segments_by_age(root)
    if protect_most_recent > 0:
        protected = set(segments[-protect_most_recent:])
    else:
        protected = set()
    cutoff = now - max_age_seconds
    to_delete = [
        p for p in segments
        if p not in protected and p.stat().st_mtime < cutoff
    ]
    result = _delete_paths(to_delete)
    result.kept_count = len(segments) - len(result.deleted)
    return result


def delete_by_size_cap(
    root: Path, *, max_total_bytes: int, protect_most_recent: int = 1,
) -> RetentionResult:
    """Delete oldest closed segments until total size is at or under
    ``max_total_bytes``, always keeping the ``protect_most_recent`` newest
    segments even if that leaves the tree over the cap (a cap is a target,
    not a hard guarantee that overrides "never delete the writer's most
    recent output")."""
    segments = _all_segments_by_age(root)
    sizes = {p: p.stat().st_size for p in segments}
    total = sum(sizes.values())
    if protect_most_recent > 0:
        protected = set(segments[-protect_most_recent:])
    else:
        protected = set()

    to_delete: list[Path] = []
    for p in segments:  # oldest first
        if total <= max_total_bytes:
            break
        if p in protected:
            continue
        to_delete.append(p)
        total -= sizes[p]

    result = _delete_paths(to_delete)
    result.kept_count = len(segments) - len(result.deleted)
    return result


def run_retention(
    root: Path,
    *,
    max_age_seconds: float | None = None,
    max_total_bytes: int | None = None,
    protect_most_recent: int = 1,
    now: float | None = None,
) -> RetentionResult:
    """Apply age policy then size policy (if both configured), combining
    results. Either policy alone is a valid call (pass only one bound)."""
    combined = RetentionResult()
    if max_age_seconds is not None:
        r = delete_by_age(
            root, max_age_seconds=max_age_seconds, now=now,
            protect_most_recent=protect_most_recent,
        )
        combined.deleted.extend(r.deleted)
        combined.deleted_bytes += r.deleted_bytes
        combined.errors.extend(r.errors)
    if max_total_bytes is not None:
        r = delete_by_size_cap(
            root, max_total_bytes=max_total_bytes,
            protect_most_recent=protect_most_recent,
        )
        combined.deleted.extend(r.deleted)
        combined.deleted_bytes += r.deleted_bytes
        combined.errors.extend(r.errors)
    remaining = len(list(root.rglob("*.parquet"))) if root.exists() else 0
    combined.kept_count = remaining
    return combined
