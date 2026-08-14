"""V2 effective-policy compiler (Workstream 3, §5-7, §47).

Transforms a stack of ``PolicyLayer`` objects — global, network, groups,
client, and an optional active-schedule override — into an immutable
``EffectivePolicy``: the single deterministic, side-effect-free result that
everything downstream (cache-profile compilation, dnsdist/BIND generation,
policy-preview UI) consumes. No database lookup happens in this module;
callers are responsible for having already loaded the layers from
control.db before calling ``compile_effective_policy``.

Determinism contract (tested): given identical layer inputs in identical
order, ``compile_effective_policy`` always produces byte-identical output,
including the explain trace — this is what makes "compile-time resolvable,
not per-query DB lookup" true, and what makes the explain trace trustworthy
for debugging rather than a guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from app.v2 import cache_profile as cp
from app.v2.policy_model import (
    ALL_FIELDS,
    DEFAULTS,
    GroupPolicy,
    PolicyLayer,
    _ANSWER_AFFECTING_FIELDS,
    _NON_ANSWER_AFFECTING_FIELDS,
    order_groups,
    validate_layer,
)


@dataclass(frozen=True)
class ExplainEntry:
    field: str
    value: object
    source: str  # e.g. "global", "network:corp-lan", "group:kids", "client", "schedule:bedtime", "default"


@dataclass(frozen=True)
class EffectivePolicy:
    values: dict  # field name -> resolved value (fully populated, never None)
    explain_trace: tuple[ExplainEntry, ...]
    schedule_active: Optional[str]  # schedule_id if one was active and applied, else None

    def __getattr__(self, name):
        # Allow attribute-style access (policy.safesearch_mode) on top of
        # the underlying dict, without redeclaring every field twice.
        try:
            return self.values[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def explain(self) -> str:
        """Human-readable multi-line explanation, per §47's example format."""
        lines = []
        for entry in self.explain_trace:
            lines.append(f"{entry.field}: {entry.value} (source: {entry.source})")
        if self.schedule_active:
            lines.append(f"Schedule '{self.schedule_active}' active: overrides applied")
        return "\n".join(lines)


def _merge_field(
    field_name: str,
    layers: list[tuple[str, PolicyLayer]],
) -> ExplainEntry:
    """Walk layers in precedence order (lowest first); the last layer that
    sets this field (non-None) wins. If none do, fall back to the field's
    documented default with source "default".
    """
    resolved_value = None
    resolved_source = "default"
    for source_name, layer in layers:
        v = getattr(layer, field_name)
        if v is not None:
            resolved_value = v
            resolved_source = source_name
    if resolved_value is None:
        resolved_value = DEFAULTS[field_name]
        resolved_source = "default"
    return ExplainEntry(field=field_name, value=resolved_value, source=resolved_source)


def compile_effective_policy(
    global_layer: PolicyLayer,
    network_layer: Optional[PolicyLayer] = None,
    network_source: Optional[str] = None,
    groups: Optional[list[GroupPolicy]] = None,
    client_layer: Optional[PolicyLayer] = None,
    schedule_layer: Optional[PolicyLayer] = None,
    schedule_id: Optional[str] = None,
    schedule_active: bool = False,
) -> EffectivePolicy:
    """Deterministic precedence: global -> network -> groups (priority
    ascending, group_id tie-break) -> client -> active schedule override
    (only applied if ``schedule_active`` is True). Explicit emergency/access
    overrides are modeled the same way as a schedule layer — the highest
    layer passed in wins, by construction, since it's applied last.
    """
    validate_layer(global_layer)
    layers: list[tuple[str, PolicyLayer]] = [("global", global_layer)]

    if network_layer is not None:
        validate_layer(network_layer)
        layers.append((f"network:{network_source or 'unknown'}", network_layer))

    for g in order_groups(groups or []):
        layers.append((f"group:{g.name}", g.layer))

    if client_layer is not None:
        validate_layer(client_layer)
        layers.append(("client", client_layer))

    applied_schedule_id = None
    if schedule_active and schedule_layer is not None:
        validate_layer(schedule_layer)
        layers.append((f"schedule:{schedule_id or 'unknown'}", schedule_layer))
        applied_schedule_id = schedule_id

    explain_trace = tuple(_merge_field(f, layers) for f in ALL_FIELDS)
    values = {e.field: e.value for e in explain_trace}

    return EffectivePolicy(
        values=values, explain_trace=explain_trace, schedule_active=applied_schedule_id
    )


def to_cache_dimensions(policy: EffectivePolicy) -> cp.CachePolicyDimensions:
    """Project only the answer-affecting fields into a
    ``CachePolicyDimensions`` — §22/§6's hard requirement that query-log/
    statistics toggles (non-answer-affecting) can never influence the
    compiled cache profile is enforced here structurally: this function
    reads only ``_ANSWER_AFFECTING_FIELDS`` and ``CachePolicyDimensions``
    itself has no fields for the other two at all (see cache_profile.py).
    """
    kwargs = {f: policy.values[f] for f in _ANSWER_AFFECTING_FIELDS}
    return cp.CachePolicyDimensions(**kwargs)


def compile_cache_profile(policy: EffectivePolicy) -> cp.EffectiveCacheProfile:
    return cp.compile_profile(to_cache_dimensions(policy))
