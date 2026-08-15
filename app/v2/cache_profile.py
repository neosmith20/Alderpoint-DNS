"""V2 effective cache profile: first-class compiled runtime concept
(Workstream 2, §15-16; frozen requirement, see
``docs/v2/architecture-map.md`` "DNS cache architecture").

An "effective cache profile" represents answer-producing policy
compatibility: two clients may share a cached DNS answer only when every
policy dimension that could change the returned answer is identical between
them. This module compiles a fixed set of answer-affecting policy
dimensions into a deterministic, collision-resistant, cheap-to-compare
string identity — never a database lookup, and never dependent on anything
that isn't already known at policy-compile time (§17's "no synchronous
cache lookup may require... control.db").

Design principle enforced by construction: ``CachePolicyDimensions`` only
has fields for properties that can change a DNS answer. Anything that
can't — a client's display name, its creation timestamp, UI notes — simply
has no field here, so it structurally cannot affect the computed profile
ID. This is what makes "altering a client's display name should not
invalidate the DNS cache, but altering SafeSearch should" true without extra
bookkeeping: the display name was never an input to the hash in the first
place.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field

# Bumped only when the *shape* of what's considered answer-affecting
# changes (a new dimension is added, or the encoding changes) — not when any
# particular client's policy changes. Including it in the hash means a
# schema change invalidates every previously-cached profile ID at once,
# which is the correct behavior: old profile IDs computed under a different
# dimension set are not comparable to new ones.
# Bumped to 2 in Workstream 3's "final continuation" pass: added
# `security_policy_id` as its own answer-affecting dimension, separate from
# `parental_policy_id`, so malware/phishing protection and parental/adult
# protection are independently-toggleable, independently-identified
# categories rather than sharing one ruleset field (see
# app/v2/filtering_decision.py for the full rationale — this was a
# self-identified review risk from the prior pass, fixed here rather than
# left for Dex to find). The version bump means every previously-computed
# profile id is invalidated, which is correct: the dimension set genuinely
# changed shape.
CACHE_PROFILE_SCHEMA_VERSION = 2


@dataclass(frozen=True)
class CachePolicyDimensions:
    """Every field here is answer-affecting by definition — do not add a
    field for something that can't change what DNS answer a client gets.
    Values are treated as opaque identifiers/enums (e.g. a filtering
    profile's own stable ID), not full policy bodies — the caller is
    responsible for giving two clients the same value here whenever (and
    only whenever) their compiled policy would actually produce the same
    answer.
    """

    filtering_profile_id: str = "default"
    safesearch_mode: str = "off"
    parental_policy_id: str = "none"
    security_policy_id: str = "none"
    service_blocking_ruleset_id: str = "none"
    blocking_response_mode: str = "nxdomain"
    upstream_profile_id: str = "default"
    fallback_strategy: str = "none"
    ecs_mode: str = "disabled"
    domain_routing_ruleset_id: str = "none"

    def canonical_json(self) -> str:
        # sort_keys makes this independent of dataclass field declaration
        # order; separators strip incidental whitespace so the same logical
        # content always serializes byte-identically.
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class EffectiveCacheProfile:
    profile_id: str
    dimensions: CachePolicyDimensions


def compile_profile(dimensions: CachePolicyDimensions) -> EffectiveCacheProfile:
    """Deterministic, schema-versioned, collision-resistant ID from policy
    dimensions. Cheap: one JSON serialization + one SHA-256 over a typically
    tiny (<300 byte) payload — safe to call on every policy compile, not
    just lazily.
    """
    payload = f"v{CACHE_PROFILE_SCHEMA_VERSION}:{dimensions.canonical_json()}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]
    return EffectiveCacheProfile(profile_id=digest, dimensions=dimensions)


def is_compatible(a: EffectiveCacheProfile, b: EffectiveCacheProfile) -> bool:
    """Cheap (O(1) string compare) cache-sharing compatibility check —
    exactly the comparison a hot-path cache-key lookup would do."""
    return a.profile_id == b.profile_id


@dataclass
class CacheProfileRegistry:
    """Tracks distinct compiled profiles currently in use, so multiple
    clients with equivalent policy can be assigned the *same* profile object
    (and therefore share cache entries) rather than each compiling their own
    equal-but-distinct instance. This is what turns "N clients, M distinct
    policy combinations" into M cache partitions instead of N — the
    no-per-client-cache requirement from §15.
    """

    _profiles: dict[str, EffectiveCacheProfile] = field(default_factory=dict)

    def get_or_compile(self, dimensions: CachePolicyDimensions) -> EffectiveCacheProfile:
        candidate = compile_profile(dimensions)
        existing = self._profiles.get(candidate.profile_id)
        if existing is not None:
            return existing
        self._profiles[candidate.profile_id] = candidate
        return candidate

    def distinct_profile_count(self) -> int:
        return len(self._profiles)

    def profile_ids(self) -> list[str]:
        return sorted(self._profiles)
