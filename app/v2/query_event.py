"""V2 normalized query event (Workstream 3 continuation, §14).

One event shape, produced once per DNS query, consumed by every downstream
V2 analytics/cache-observation system (Parquet raw history, aggregate
rollups, Tier B popularity tracking) — normalization happens exactly once
here, not separately in each consumer, per §13's explicit "do not duplicate
parsing/normalization across raw and aggregate writers" instruction.

Field selection follows §14: enough for future UI/policy diagnostics
without secrets or unbounded blobs. ``policy_reason`` is a short string
(e.g. a service_id or category), never a full policy body.
"""

from __future__ import annotations

import itertools
from dataclasses import asdict, dataclass, field
from typing import Optional

QUERY_EVENT_SCHEMA_VERSION = 1

_id_counter = itertools.count(1)


def next_event_id() -> int:
    """Process-local monotonic counter — good enough for the in-memory
    ``id`` column Workstream 2's Parquet schema already has; a real
    ingestion service would use a proper sequence, but nothing downstream
    depends on global uniqueness across processes for this prototype.
    """
    return next(_id_counter)


@dataclass(frozen=True)
class NormalizedQueryEvent:
    ts: float
    qname: str
    qtype: str
    protocol: str  # "udp" | "tcp" | "dot" | "doh" | "doq"
    client: str  # source IP or stable client identifier, never a raw secret
    client_name: str = ""
    network_id: Optional[str] = None
    group_ids: tuple[str, ...] = field(default_factory=tuple)
    client_id: Optional[str] = None
    effective_cache_profile_id: str = ""
    action: str = "allowed"  # "allowed" | "blocked" | "rewritten"
    block_reason: str = ""  # e.g. a service_id/category, never a full policy body
    rcode: str = "NOERROR"
    upstream_profile_id: str = ""
    latency_ms: float = 0.0
    cache_status: str = "miss"  # "hit" | "miss" | "prewarm"
    encrypted_transport: bool = False
    query_log_enabled: bool = True
    statistics_enabled: bool = True

    def __post_init__(self) -> None:
        if not self.qname:
            raise ValueError("qname must not be empty")
        if self.protocol not in ("udp", "tcp", "dot", "doh", "doq"):
            raise ValueError(f"invalid protocol: {self.protocol!r}")
        if self.action not in ("allowed", "blocked", "rewritten"):
            raise ValueError(f"invalid action: {self.action!r}")
        if self.cache_status not in ("hit", "miss", "prewarm"):
            raise ValueError(f"invalid cache_status: {self.cache_status!r}")

    def to_raw_record(self, event_id: Optional[int] = None) -> dict:
        """Shape expected by ``app/v2/parquet_writer.py`` /
        ``app/v2/aggregates_db.py`` (same record dict, per the
        no-duplicate-normalization rule) — only emitted when
        ``statistics_enabled``/``query_log_enabled`` allow it; callers
        decide which sinks a given event is eligible for, this method only
        shapes the payload.
        """
        return {
            "id": event_id if event_id is not None else next_event_id(),
            "ts": self.ts,
            "client": self.client,
            "client_name": self.client_name,
            "domain": self.qname,
            "qtype": self.qtype,
            "protocol": self.protocol,
            "rcode": self.rcode,
            "latency_ms": self.latency_ms,
            "blocked": self.action == "blocked",
            "block_reason": self.block_reason,
            "upstream": self.upstream_profile_id,
            "cache_status": self.cache_status,
            "cache_profile_id": self.effective_cache_profile_id,
        }
