"""V2 unified policy objects (Workstream 3, §1-2).

A ``PolicyLayer`` is one scope's worth of policy — global, network, group,
or client. Every field is ``Optional``: ``None`` means "no opinion at this
layer, inherit from the next layer down"; any non-``None`` value is an
explicit override at that layer. This is what keeps merge semantics
unambiguous — there is no implicit "0/empty-string means unset" guessing,
and no dependency on row order.

Fields split into two groups:

- *Answer-affecting* fields (mirrors ``app/v2/cache_profile.py``'s
  ``CachePolicyDimensions`` field-for-field) — changing one of these can
  change what DNS answer a client receives, so it must also be able to
  change the compiled cache-profile identity.
- *Non-answer-affecting* fields (``query_log_enabled``, ``statistics_enabled``)
  — these change what gets recorded about a query, never the answer itself,
  and must never be allowed to influence the cache profile (see
  ``policy_compiler.to_cache_dimensions`` and its tests).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, fields
from typing import Optional

_ANSWER_AFFECTING_FIELDS = (
    "filtering_profile_id",
    "safesearch_mode",
    "parental_policy_id",
    "security_policy_id",
    "service_blocking_ruleset_id",
    "blocking_response_mode",
    # Real defect closed: custom_ip response mode was selectable/storable
    # in the API contract (webapp.py) but had nowhere in PolicyLayer to
    # actually store the address, so runtime_compile.py's
    # BlockingResponse(mode=policy.blocking_response_mode) construction
    # always omitted custom_ipv4/custom_ipv6 -- which
    # BlockingResponse.__post_init__ (app/v2/blocking_response.py)
    # correctly rejects for mode="custom_ip", crashing the ENTIRE compile
    # for every policy the moment any administrator picked custom_ip,
    # regardless of whether they'd have supplied a real address through a
    # real UI control. Answer-affecting: two different configured
    # addresses must never share a cache profile.
    "custom_ipv4",
    "custom_ipv6",
    "upstream_profile_id",
    "fallback_strategy",
    # Real defect closed: fallback_strategy was stored but the runtime
    # never invoked any real fallback decision logic, and app/v2/
    # fallback_dns.py's evaluate_fallback() was written but never called
    # from anywhere real -- fully disconnected. Nothing named WHICH
    # profile to fall back to either; that reference is this field.
    "fallback_upstream_profile_id",
    "ecs_mode",
    "domain_routing_ruleset_id",
)

_NON_ANSWER_AFFECTING_FIELDS = (
    "query_log_enabled",
    "statistics_enabled",
)


class InvalidPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyLayer:
    filtering_profile_id: Optional[str] = None
    safesearch_mode: Optional[str] = None
    parental_policy_id: Optional[str] = None
    security_policy_id: Optional[str] = None
    service_blocking_ruleset_id: Optional[str] = None
    blocking_response_mode: Optional[str] = None
    custom_ipv4: Optional[str] = None
    custom_ipv6: Optional[str] = None
    upstream_profile_id: Optional[str] = None
    fallback_strategy: Optional[str] = None
    fallback_upstream_profile_id: Optional[str] = None
    ecs_mode: Optional[str] = None
    domain_routing_ruleset_id: Optional[str] = None
    query_log_enabled: Optional[bool] = None
    statistics_enabled: Optional[bool] = None


# Defaults used when *no* layer (not even global) sets a field. Kept
# identical to ``cache_profile.CachePolicyDimensions``'s own field defaults
# so an entirely-empty policy stack compiles to the same profile as an
# entirely-default ``CachePolicyDimensions()``.
_ANSWER_DEFAULTS = {
    "filtering_profile_id": "default",
    "safesearch_mode": "off",
    "parental_policy_id": "none",
    "security_policy_id": "none",
    "service_blocking_ruleset_id": "none",
    "blocking_response_mode": "nxdomain",
    # "" is the "not configured" sentinel -- consistent with every other
    # field's DEFAULTS entry here being a real, always-resolvable value
    # rather than None (see this module's own docstring). Callers that
    # build a real BlockingResponse (app/v2/runtime_compile.py) treat ""
    # as "no address supplied," matching BlockingResponse's own None
    # convention, rather than passing "" through and getting an
    # ipaddress-parse error for an address nobody configured.
    "custom_ipv4": "",
    "custom_ipv6": "",
    "upstream_profile_id": "default",
    "fallback_strategy": "none",
    "fallback_upstream_profile_id": "none",
    "ecs_mode": "disabled",
    "domain_routing_ruleset_id": "none",
}
_NON_ANSWER_DEFAULTS = {
    "query_log_enabled": True,
    "statistics_enabled": True,
}

ALL_FIELDS = _ANSWER_AFFECTING_FIELDS + _NON_ANSWER_AFFECTING_FIELDS
DEFAULTS = {**_ANSWER_DEFAULTS, **_NON_ANSWER_DEFAULTS}

assert {f.name for f in fields(PolicyLayer)} == set(ALL_FIELDS), (
    "PolicyLayer fields drifted from the declared answer/non-answer field lists"
)


_VALID_SAFESEARCH = {"off", "moderate", "strict"}
_VALID_BLOCKING_RESPONSE = {"nxdomain", "refused", "null_ip", "custom_ip"}
_VALID_ECS = {"disabled", "preserve", "custom"}
_VALID_FALLBACK = {"none", "on_failure", "always_parallel"}


def validate_layer(layer: PolicyLayer) -> None:
    if layer.safesearch_mode is not None and layer.safesearch_mode not in _VALID_SAFESEARCH:
        raise InvalidPolicyError(f"invalid safesearch_mode: {layer.safesearch_mode!r}")
    if (
        layer.blocking_response_mode is not None
        and layer.blocking_response_mode not in _VALID_BLOCKING_RESPONSE
    ):
        raise InvalidPolicyError(
            f"invalid blocking_response_mode: {layer.blocking_response_mode!r}"
        )
    if layer.ecs_mode is not None and layer.ecs_mode not in _VALID_ECS:
        raise InvalidPolicyError(f"invalid ecs_mode: {layer.ecs_mode!r}")
    if layer.fallback_strategy is not None and layer.fallback_strategy not in _VALID_FALLBACK:
        raise InvalidPolicyError(f"invalid fallback_strategy: {layer.fallback_strategy!r}")
    # Format-validated at every layer save, independent of which mode a
    # (possibly different) layer ultimately resolves to -- catches a bad
    # address at save time rather than only at compile time. Whether
    # custom_ip mode has a real address available at ALL (i.e. at least
    # one of these is non-empty) is an EFFECTIVE-policy concern, not a
    # single-layer one (mode and address can come from different layers),
    # and is enforced where the effective values are actually consumed:
    # app/v2/blocking_response.py's BlockingResponse construction.
    if layer.custom_ipv4:
        try:
            ipaddress.IPv4Address(layer.custom_ipv4)
        except ValueError as exc:
            raise InvalidPolicyError(f"invalid custom_ipv4: {layer.custom_ipv4!r}") from exc
    if layer.custom_ipv6:
        try:
            ipaddress.IPv6Address(layer.custom_ipv6)
        except ValueError as exc:
            raise InvalidPolicyError(f"invalid custom_ipv6: {layer.custom_ipv6!r}") from exc


@dataclass(frozen=True)
class GroupPolicy:
    """A group/tag's policy layer plus the metadata needed to resolve
    conflicts deterministically when a client belongs to more than one
    group. ``priority`` is an explicit integer the administrator sets
    (higher applies later / wins on direct field conflicts); ``group_id``
    is the tie-breaker for equal priority so resolution never depends on
    insertion or SQLite row order.
    """

    group_id: str
    name: str
    priority: int
    layer: PolicyLayer

    def __post_init__(self) -> None:
        if not self.group_id:
            raise InvalidPolicyError("group_id must not be empty")
        if not self.name:
            raise InvalidPolicyError("group name must not be empty")
        validate_layer(self.layer)


def order_groups(groups: list[GroupPolicy]) -> tuple[GroupPolicy, ...]:
    """Deterministic application order: ascending priority, then
    ``group_id`` as a stable tie-break. Applied in this order during merge,
    so the *last* one in this tuple wins any direct field conflict — i.e.
    highest priority (and, among equal priorities, the lexicographically
    greatest group_id) wins.
    """
    seen: set[str] = set()
    for g in groups:
        if g.group_id in seen:
            raise InvalidPolicyError(f"duplicate group_id in membership: {g.group_id}")
        seen.add(g.group_id)
    return tuple(sorted(groups, key=lambda g: (g.priority, g.group_id)))
