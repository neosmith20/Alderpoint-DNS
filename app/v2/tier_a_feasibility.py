"""Tier A — safe direct cache restore: feasibility/correctness prototype
(Workstream 2, §26-27; frozen design, ``docs/v2/architecture-map.md`` "DNS
cache architecture").

Tier A is OPTIONAL. This module exists to answer one question concretely:
*can restore-time validity be proven correctly*, not to argue it should ship.
It implements the pure validity-decision function only — no disk I/O, no
DNS resolution, no BIND/dnsdist integration. See
``docs/v2/tier-a-feasibility.md`` for the resulting keep/reject/defer
recommendation and its reasoning.

The one property this module exists to prove, mechanically, not just by
description: **a reboot never resets TTL**. ``evaluate_restore`` always
computes remaining TTL as ``absolute_expiration_ts - now``, never reads or
trusts any "original TTL" field as if it still applied — there is no such
field in ``CachedAnswerRecord`` at all, so there is nothing to accidentally
reuse.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DnssecState(str, Enum):
    SECURE = "secure"
    INSECURE = "insecure"  # validly proven "no DNSSEC for this zone" — still trustworthy
    BOGUS = "bogus"
    UNKNOWN = "unknown"


_TRUSTWORTHY_DNSSEC_STATES = frozenset({DnssecState.SECURE, DnssecState.INSECURE})


@dataclass(frozen=True)
class CachedAnswerRecord:
    """Everything Tier A needs to have captured about a cached answer at the
    time it was cached, in order to later decide whether restoring it is
    safe. Deliberately has no "original TTL" field — only the absolute
    expiration timestamp, which is what makes "TTL never resets" true by
    construction rather than by a runtime check that could be bypassed.
    """

    qname: str
    qtype: str
    cache_profile_id: str
    absolute_expiration_ts: float
    dnssec_state: DnssecState
    resolver_upstream_profile_id: str
    domain_routing_context_id: str
    is_negative: bool = False  # NXDOMAIN/NODATA cache entry
    ecs_context: str | None = None


@dataclass(frozen=True)
class RestoreDecision:
    allowed: bool
    remaining_ttl_seconds: float | None
    reason: str


def evaluate_restore(
    record: CachedAnswerRecord,
    *,
    now: float,
    current_cache_profile_id: str,
    current_upstream_profile_id: str,
    current_domain_routing_context_id: str,
    current_ecs_context: str | None = None,
) -> RestoreDecision:
    """The one function this module is built around. Every rejection reason
    is checked explicitly and independently (not short-circuited into a
    single boolean) so a caller/test can see exactly which validity
    dimension failed.
    """
    remaining_ttl = record.absolute_expiration_ts - now

    if remaining_ttl <= 0:
        return RestoreDecision(allowed=False, remaining_ttl_seconds=None, reason="expired")

    if record.dnssec_state not in _TRUSTWORTHY_DNSSEC_STATES:
        return RestoreDecision(
            allowed=False, remaining_ttl_seconds=None,
            reason=f"dnssec state {record.dnssec_state.value!r} not provably valid",
        )

    if record.cache_profile_id != current_cache_profile_id:
        return RestoreDecision(
            allowed=False, remaining_ttl_seconds=None, reason="effective cache profile mismatch",
        )

    if record.resolver_upstream_profile_id != current_upstream_profile_id:
        return RestoreDecision(
            allowed=False, remaining_ttl_seconds=None, reason="resolver/upstream context mismatch",
        )

    if record.domain_routing_context_id != current_domain_routing_context_id:
        return RestoreDecision(
            allowed=False, remaining_ttl_seconds=None, reason="domain-routing context mismatch",
        )

    if record.ecs_context != current_ecs_context:
        return RestoreDecision(
            allowed=False, remaining_ttl_seconds=None, reason="ECS context mismatch",
        )

    return RestoreDecision(allowed=True, remaining_ttl_seconds=remaining_ttl, reason="valid")
