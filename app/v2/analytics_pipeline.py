"""V2 real analytics ingestion pipeline (Workstream 3 continuation, §13,
§16, §23).

Wires ``app/v2/query_event.py``'s single normalized event shape into
Workstream 2's real Parquet writer, aggregate rollup store, and Tier B
popularity index, in one place, so normalization never happens more than
once (§13). This is still a prototype in the sense that nothing calls
``ingest()`` from a live DNS path yet — no such path exists in this
workstream — but the pipeline itself (bounded queue, batching, per-sink
failure isolation, exclusion semantics) is production-shaped and only
needs a real event source wired in front of it.

Isolation guarantee: a failure writing to any one sink (Parquet, aggregates,
Tier B) is caught and counted, never allowed to raise out of ``flush()`` or
block the other sinks — matching §49's "DNS keeps answering" failure-domain
requirement one level up (here: "one analytics sink's failure doesn't stop
the others" plus "analytics as a whole never blocks the caller").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.v2 import aggregates_db
from app.v2.analytics_ingest import BoundedQueue
from app.v2.parquet_writer import ParquetSegmentWriter
from app.v2.query_event import NormalizedQueryEvent
from app.v2.tier_b_prewarm import WorkingSetIndex


@dataclass
class PipelineStats:
    ingested: int = 0
    dropped_by_queue: int = 0
    excluded_from_log: int = 0
    excluded_from_stats: int = 0
    parquet_failures: int = 0
    aggregate_failures: int = 0
    tier_b_failures: int = 0
    last_parquet_error: Optional[str] = None
    last_aggregate_error: Optional[str] = None
    last_tier_b_error: Optional[str] = None


class AnalyticsPipeline:
    """Owns one bounded queue plus references to the three downstream
    sinks. Callers push events with ``submit()`` (cheap, memory-only, no
    synchronous disk I/O — matches the DNS-hot-path invariant); a separate
    ``flush()`` call (driven by a timer/size threshold in a real deployment,
    driven explicitly by tests here) drains the queue and does the actual
    (isolated, per-sink) I/O.
    """

    def __init__(
        self,
        parquet_root: Path,
        aggregates_path: Path,
        tier_b_index: WorkingSetIndex,
        queue_capacity: int = 10_000,
        parquet_writer: Optional[ParquetSegmentWriter] = None,
    ):
        self.queue = BoundedQueue(capacity=queue_capacity)
        self.parquet_writer = parquet_writer or ParquetSegmentWriter(root=parquet_root)
        self.aggregates_path = Path(aggregates_path)
        aggregates_db.initialize(self.aggregates_path)
        self.tier_b_index = tier_b_index
        self.stats = PipelineStats()

    def submit(self, event: NormalizedQueryEvent) -> None:
        before = self.queue.dropped_count
        self.queue.push({"event": event})
        if self.queue.dropped_count != before:
            self.stats.dropped_by_queue += 1
        self.stats.ingested += 1

    def flush(self, max_items: Optional[int] = None) -> int:
        """Drains up to ``max_items`` queued events (all of them by
        default) and fans them out to the three sinks. Returns the number
        of events processed. Each sink's failure is isolated: an exception
        from one does not prevent the others from running or propagate to
        the caller.
        """
        items = self.queue.drain(max_items)
        if not items:
            return 0
        events: list[NormalizedQueryEvent] = [i["event"] for i in items]

        raw_records = []
        for e in events:
            if not e.query_log_enabled:
                self.stats.excluded_from_log += 1
                continue
            raw_records.append(e.to_raw_record())
        if raw_records:
            try:
                self.parquet_writer.ingest(raw_records)
            except Exception as exc:  # noqa: BLE001 - isolation boundary, never propagate
                self.stats.parquet_failures += 1
                self.stats.last_parquet_error = str(exc)

        agg_records = []
        for e in events:
            if not e.statistics_enabled:
                self.stats.excluded_from_stats += 1
                continue
            agg_records.append(e.to_raw_record())
        if agg_records:
            try:
                aggregates_db.record_batch(self.aggregates_path, agg_records)
            except Exception as exc:  # noqa: BLE001
                self.stats.aggregate_failures += 1
                self.stats.last_aggregate_error = str(exc)

        for e in events:
            # Tier B observation is independent of the log/stats exclusion
            # toggles -- it's neither a retained query log nor a reported
            # statistic, just an ephemeral in-memory popularity signal that
            # never leaves the process except via its own coalesced
            # snapshot (app/v2/tier_b_prewarm.py), so it isn't gated by
            # either exclusion flag.
            try:
                self.tier_b_index.record_query(
                    e.qname, e.qtype, e.effective_cache_profile_id, ts=e.ts
                )
            except Exception as exc:  # noqa: BLE001
                self.stats.tier_b_failures += 1
                self.stats.last_tier_b_error = str(exc)

        return len(events)

    def close(self) -> None:
        self.parquet_writer.close()
