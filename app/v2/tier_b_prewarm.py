"""Tier B — popularity-based DNS cache prewarm (Workstream 2, §24-25;
frozen design, see ``docs/v2/architecture-map.md`` "DNS cache architecture").

Tier B is the mandatory-baseline persistent warm-start mechanism (Tier A —
direct restore — is optional, see ``app/v2/tier_a_feasibility.py``). It
persists a bounded index of *which names were popular*, not trusted old DNS
answers: after restart, the planner replays the hottest recent names through
the normal resolution path (via an injected ``resolve_fn`` — this module
never resolves DNS itself) to obtain fresh TTLs, current DNSSEC validation,
and the current effective cache profile.

Properties implemented here:

- **Bounded**: ``WorkingSetIndex`` evicts the coldest entry once
  ``max_entries`` is exceeded — never grows without limit.
- **Coalesced/batched persistence, no per-query fsync**: ``record_query``
  only mutates an in-memory dict; disk I/O happens exclusively in
  ``flush()``, which a caller invokes periodically (e.g. every N seconds or
  every N records), not on every query.
- **Crash tolerant / corrupted state ignored safely**: ``load()`` returns an
  empty index (cold start) on any read/parse failure — a corrupt or missing
  snapshot degrades to "start from nothing", never raises into a caller on
  the DNS-availability path.
- **Rate-limited, bounded, non-blocking startup replay**:
  ``run_prewarm`` enforces names-per-second, a total-name cap, and a
  max-duration cap, so a cold start can never turn into an uncontrolled
  burst against upstream resolvers.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

DEFAULT_MAX_ENTRIES = 10_000


@dataclass
class WorkingSetEntry:
    qname: str
    qtype: str
    cache_profile_id: str
    last_seen_ts: float
    hit_count: int = 1

    def score(self, now: float) -> float:
        """Recency-weighted popularity: recent + frequent ranks highest.
        Deliberately simple (no ML, no tuning knobs) — a half-life decay
        applied to hit_count, so a name popular yesterday but silent since
        naturally loses ranking without an explicit sweep/expiry pass."""
        age_hours = max(0.0, (now - self.last_seen_ts) / 3600.0)
        half_life_hours = 6.0
        decay = 0.5 ** (age_hours / half_life_hours)
        return self.hit_count * decay


@dataclass
class WorkingSetIndex:
    """Bounded in-memory popularity index with atomic snapshot persistence."""

    max_entries: int = DEFAULT_MAX_ENTRIES
    _entries: dict[tuple[str, str, str], WorkingSetEntry] = field(default_factory=dict)

    def record_query(
        self, qname: str, qtype: str, cache_profile_id: str, *, ts: float | None = None,
    ) -> None:
        ts = ts if ts is not None else time.time()
        key = (qname, qtype, cache_profile_id)
        existing = self._entries.get(key)
        if existing is not None:
            existing.hit_count += 1
            existing.last_seen_ts = ts
        else:
            self._entries[key] = WorkingSetEntry(
                qname=qname, qtype=qtype, cache_profile_id=cache_profile_id,
                last_seen_ts=ts, hit_count=1,
            )
            if len(self._entries) > self.max_entries:
                self._evict_coldest(ts)

    def _evict_coldest(self, now: float) -> None:
        coldest_key = min(self._entries, key=lambda k: self._entries[k].score(now))
        del self._entries[coldest_key]

    def __len__(self) -> int:
        return len(self._entries)

    def top(self, n: int, *, now: float | None = None) -> list[WorkingSetEntry]:
        now = now if now is not None else time.time()
        ranked = sorted(self._entries.values(), key=lambda e: e.score(now), reverse=True)
        return ranked[:n]

    def to_snapshot_dict(self) -> dict:
        return {
            "max_entries": self.max_entries,
            "entries": [
                {
                    "qname": e.qname, "qtype": e.qtype, "cache_profile_id": e.cache_profile_id,
                    "last_seen_ts": e.last_seen_ts, "hit_count": e.hit_count,
                }
                for e in self._entries.values()
            ],
        }

    @classmethod
    def from_snapshot_dict(cls, data: dict) -> "WorkingSetIndex":
        idx = cls(max_entries=data.get("max_entries", DEFAULT_MAX_ENTRIES))
        for row in data.get("entries", []):
            key = (row["qname"], row["qtype"], row["cache_profile_id"])
            idx._entries[key] = WorkingSetEntry(
                qname=row["qname"], qtype=row["qtype"], cache_profile_id=row["cache_profile_id"],
                last_seen_ts=row["last_seen_ts"], hit_count=row["hit_count"],
            )
        return idx


def flush(index: WorkingSetIndex, path: str | os.PathLike) -> None:
    """Atomically snapshot the index to ``path`` — temp file + fsync +
    os.replace, same pattern used throughout this codebase. Callers should
    invoke this periodically/coalesced (e.g. every 30s or every N mutations
    from a background worker), never once per DNS query."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(index.to_snapshot_dict())
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            tmp.write(text)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise
    dir_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def load(path: str | os.PathLike, *, max_entries: int = DEFAULT_MAX_ENTRIES) -> WorkingSetIndex:
    """Load a snapshot, or return a fresh empty index on any problem
    (missing file, truncated/corrupt JSON, unexpected shape) — this is the
    "corrupted state degrades to cold cache" contract. Never raises."""
    path = Path(path)
    if not path.exists():
        return WorkingSetIndex(max_entries=max_entries)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return WorkingSetIndex.from_snapshot_dict(data)
    except (json.JSONDecodeError, KeyError, TypeError, OSError):
        return WorkingSetIndex(max_entries=max_entries)


@dataclass
class PrewarmStats:
    attempted: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped_rate_cap: int = 0
    skipped_total_cap: int = 0
    stopped_on_duration_cap: bool = False
    stopped_on_pressure: bool = False


def run_prewarm(
    entries: list[WorkingSetEntry],
    resolve_fn: Callable[[WorkingSetEntry], bool],
    *,
    max_names_per_second: float = 20.0,
    max_total_names: int = 2000,
    max_duration_seconds: float = 60.0,
    should_pause: Callable[[], bool] | None = None,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
) -> PrewarmStats:
    """Replay the hottest entries through ``resolve_fn`` (the caller's real
    "resolve through the normal Alderpoint path" implementation — this
    module has no DNS-resolution logic of its own), rate-limited and
    bounded. ``should_pause`` lets a caller signal CPU/memory pressure (§25
    "stop/slow if system under resource pressure") — checked before each
    attempt; if it returns True, prewarm stops immediately without treating
    remaining entries as failures.

    DNS availability is never gated on this function — by construction,
    nothing here can be called before the normal DNS path is already up,
    because ``resolve_fn`` *is* the normal DNS path.
    """
    stats = PrewarmStats()
    start = clock()
    min_interval = 1.0 / max_names_per_second if max_names_per_second > 0 else 0.0
    last_attempt_time: float | None = None

    for entry in entries:
        if stats.attempted >= max_total_names:
            stats.skipped_total_cap += len(entries) - stats.attempted
            break
        if clock() - start >= max_duration_seconds:
            stats.stopped_on_duration_cap = True
            break
        if should_pause is not None and should_pause():
            stats.stopped_on_pressure = True
            break

        if last_attempt_time is not None and min_interval > 0:
            elapsed = clock() - last_attempt_time
            if elapsed < min_interval:
                sleep(min_interval - elapsed)

        stats.attempted += 1
        last_attempt_time = clock()
        try:
            ok = resolve_fn(entry)
        except Exception:  # noqa: BLE001 — a single resolve failure must not abort the whole prewarm
            ok = False
        if ok:
            stats.succeeded += 1
        else:
            stats.failed += 1

    return stats
