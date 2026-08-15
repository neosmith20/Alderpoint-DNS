"""V2 real filtering decision logic (Workstream 3, §4A-4D; category
separation fixed in the "final continuation" pass, P0-A).

Ties the effective-policy compiler's filtering-related fields
(``safesearch_mode``, ``parental_policy_id``, ``security_policy_id``,
``service_blocking_ruleset_id``) to real domain-set data
(``app/v2/policy_store.py``'s service/ruleset tables,
``app/v2/safesearch.py``'s provider table) and produces one concrete
decision per qname, with a diagnostic reason (§47's "why was this blocked"
requirement).

Category independence (fixed self-identified review risk): parental/adult
protection and malware/phishing/security protection are separate,
independently-toggleable answer-affecting policy dimensions --
``parental_policy_id`` and ``security_policy_id`` respectively, both now
real fields on ``CachePolicyDimensions`` (schema v2, see
``app/v2/cache_profile.py``). Each has its own:

- policy field / ruleset identity (never shared)
- enable/disable state (``"none"`` disables that category alone)
- diagnostic category string returned in ``FilterDecision.category``
  (``"parental"`` vs ``"security"``, never a merged/ambiguous label)
- test coverage proving toggling one never affects the other

They still share the *matching mechanism* --
``policy_store.create_service_ruleset``/``is_domain_service_blocked`` --
because per §4B/§4C's own instruction to "prefer curated category/source
integration rather than a parallel ad-hoc engine," there is no reason to
duplicate suffix/exact domain matching logic three times. What's separated
is the semantic policy state (which ruleset applies, whether the category
is active at all), not the low-level string-matching code.

Precedence (deterministic, tested): explicit allow > SafeSearch rewrite >
security (malware/phishing) block > parental block > service block >
allowed. Security is checked ahead of parental/service on the reasoning
that a malware/phishing match is a safety concern independent of parental
controls being configured at all; explicit allow is checked first so it
can still override every block category (§12/§13's "explicit allow
override behavior").
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

    # Security (malware/phishing) is checked independently of, and ahead
    # of, parental -- disabling parental_policy_id ("none") has no effect
    # on whether security_policy_id still blocks, and vice versa.
    if policy.security_policy_id not in ("none", None):
        service_id = store.is_domain_service_blocked(conn, policy.security_policy_id, qname)
        if service_id is not None:
            return FilterDecision(action="blocked", reason=service_id, category="security")

    if policy.parental_policy_id not in ("none", None):
        service_id = store.is_domain_service_blocked(conn, policy.parental_policy_id, qname)
        if service_id is not None:
            return FilterDecision(action="blocked", reason=service_id, category="parental")

    if policy.service_blocking_ruleset_id not in ("none", None):
        service_id = store.is_domain_service_blocked(
            conn, policy.service_blocking_ruleset_id, qname
        )
        if service_id is not None:
            return FilterDecision(action="blocked", reason=service_id, category="service")

    return FilterDecision(action="allowed", reason="no_match")
