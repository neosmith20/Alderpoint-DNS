"""V2 fallback DNS resolver behavior (Workstream 3 continuation, §10).

A pure decision function: given a primary upstream profile's observed
health state and a policy's ``fallback_strategy``, decide whether fallback
to a secondary profile is currently permitted, and enforce the explicit
"no silent encrypted-to-plaintext downgrade" rule from §10 --
``fallback_strategy="on_failure"`` with a plaintext fallback profile behind
an encrypted (DoT/DoH) primary requires ``allow_privacy_downgrade=True``
passed explicitly by the caller (i.e. an administrator decision, not a
default), otherwise it's refused with a clear reason rather than silently
sending queries in the clear.

This module has no health-check/network logic of its own -- ``PrimaryHealth``
is a caller-supplied snapshot (from wherever the real health-check
mechanism lives), matching the same "pure decision, real I/O happens
elsewhere" pattern as ``app/v2/tier_a_feasibility.py`` and
``app/v2/blocking_response.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_ENCRYPTED_TRANSPORTS = frozenset({"dot", "doh"})


class FallbackNotPermittedError(ValueError):
    pass


@dataclass(frozen=True)
class PrimaryHealth:
    consecutive_failures: int
    failure_threshold: int = 3

    @property
    def is_down(self) -> bool:
        return self.consecutive_failures >= self.failure_threshold


@dataclass(frozen=True)
class FallbackDecision:
    use_fallback: bool
    reason: str


def evaluate_fallback(
    fallback_strategy: str,
    primary_health: PrimaryHealth,
    primary_transport: str,
    fallback_transport: Optional[str],
    allow_privacy_downgrade: bool = False,
) -> FallbackDecision:
    """``fallback_strategy`` is one of PolicyLayer's already-validated
    values: "none" (never fall back), "on_failure" (only once
    ``primary_health.is_down``), "always_parallel" (query both -- a
    strategy this module treats as "fallback is always eligible," leaving
    the actual parallel-query mechanics to the dnsdist compiler layer,
    same "decision here, mechanism elsewhere" split as the rest of this
    module).
    """
    if fallback_strategy == "none":
        return FallbackDecision(use_fallback=False, reason="fallback_strategy is 'none'")

    if fallback_strategy == "on_failure" and not primary_health.is_down:
        return FallbackDecision(
            use_fallback=False,
            reason=f"primary healthy ({primary_health.consecutive_failures} consecutive failures, "
            f"threshold {primary_health.failure_threshold})",
        )

    downgrade = (
        primary_transport in _ENCRYPTED_TRANSPORTS
        and fallback_transport is not None
        and fallback_transport not in _ENCRYPTED_TRANSPORTS
    )
    if downgrade and not allow_privacy_downgrade:
        return FallbackDecision(
            use_fallback=False,
            reason=(
                f"refused: falling back from encrypted primary ({primary_transport}) to "
                f"plaintext fallback ({fallback_transport}) requires explicit "
                "allow_privacy_downgrade=True"
            ),
        )

    return FallbackDecision(use_fallback=True, reason=f"fallback permitted under '{fallback_strategy}'")
