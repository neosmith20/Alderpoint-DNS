"""V2 real filtering decision logic (Workstream 3 continuation, §4A-4D).

Ties the effective-policy compiler's filtering-related fields
(``safesearch_mode``, ``parental_policy_id``, ``service_blocking_ruleset_id``)
to real domain-set data (``app/v2/policy_store.py``'s service/ruleset
tables, ``app/v2/safesearch.py``'s provider table) and produces one
concrete decision per qname, with a diagnostic reason (§47's "why was this
blocked" requirement).

Design choice made under the locked architecture (§52 "resolve normal
design details from locked architecture"): parental/adult and malware/
phishing protection reuse the SAME curated service/ruleset mechanism as
service blocking, distinguished by the ruleset's ``category`` -- per §4B/4C's
own instruction to "prefer curated category/source integration rather than
a parallel ad-hoc engine." ``PolicyLayer.parental_policy_id`` names a
ruleset_id (built with ``policy_store.create_service_ruleset``, its member
services tagged with a category like ``"adult"``); malware/phishing
protection, which Workstream 2's cache-profile dimension set has no
dedicated field for, is expected to live in the same
``service_blocking_ruleset_id`` ruleset with services tagged
``category="security"`` -- adding a new answer-affecting dimension to
``CachePolicyDimensions`` would be a schema-version bump affecting every
already-compiled profile id, which this session treats as out of scope for
a design detail resolvable this way instead.

Precedence (deterministic, tested): explicit allow > SafeSearch rewrite >
parental block > service/malware block > allowed. Explicit allow is
checked first specifically so it overrides every block category, matching
§12/§13's "explicit allow override behavior."
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Optional

from app.v2 import policy_store as store
from app.v2 import safesearch
from app.v2.policy_compiler import EffectivePolicy


@dataclass(frozen=True)
class FilterDecision:
    action: str  # "allowed" | "blocked" | "rewritten"
    reason: str
    category: str = ""
    cname_target: Optional[str] = None


def _normalize(qname: str) -> str:
    return qname.strip(".").lower()


def evaluate_filtering(
    conn: sqlite3.Connection,
    policy: EffectivePolicy,
    qname: str,
    allowed_domains: frozenset[str] = frozenset(),
) -> FilterDecision:
    qname = _normalize(qname)

    if qname in allowed_domains:
        return FilterDecision(action="allowed", reason="explicit_allow")

    if policy.safesearch_mode != "off":
        for provider in safesearch.SUPPORTED_PROVIDERS:
            for rewrite in safesearch.rewrites_for_providers([provider]):
                if qname == rewrite.domain:
                    return FilterDecision(
                        action="rewritten",
                        reason=f"safesearch:{provider}",
                        category="safesearch",
                        cname_target=rewrite.cname_target,
                    )

    if policy.parental_policy_id not in ("none", None):
        service_id = store.is_domain_service_blocked(conn, policy.parental_policy_id, qname)
        if service_id is not None:
            return FilterDecision(action="blocked", reason=service_id, category="parental")

    if policy.service_blocking_ruleset_id not in ("none", None):
        service_id = store.is_domain_service_blocked(
            conn, policy.service_blocking_ruleset_id, qname
        )
        if service_id is not None:
            return FilterDecision(action="blocked", reason=service_id, category="service_or_security")

    return FilterDecision(action="allowed", reason="no_match")
