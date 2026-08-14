"""V2 ECS (EDNS Client Subnet) privacy controls (Workstream 3 continuation,
§12).

Real dnsdist directive generation for the three modes
``policy_model.PolicyLayer.ecs_mode`` already validates
(``disabled``/``preserve``/``custom``), verified against the installed
dnsdist 2.1.1 binary via ``--check-config``:

- ``disabled`` (privacy-default, matches the model's own default): no ECS
  option is added to upstream queries at all -- no directive needed, this
  is dnsdist's default behavior, stated explicitly rather than left silent.
- ``preserve``: forward the real client's subnet to upstream resolvers via
  ``useClientSubnet=true`` on each backend server.
- ``custom``: override with a fixed, coarser, configured prefix length
  (``setECSSourcePrefixV4``/``setECSSourcePrefixV6`` + ``setECSOverride``)
  rather than the real client subnet -- a deliberately less-precise privacy
  compromise, not the raw client address.

This module intentionally has no "pass exact client IP with no
truncation" option, since that's not a mode the locked policy model
defines and would be a meaningfully different (weaker) privacy posture
than any of the three validated enum values.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_VALID_MODES = ("disabled", "preserve", "custom")


class InvalidEcsPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class EcsPolicy:
    mode: str
    custom_prefix_v4: int = 24
    custom_prefix_v6: int = 56

    def __post_init__(self) -> None:
        if self.mode not in _VALID_MODES:
            raise InvalidEcsPolicyError(f"invalid ecs_mode: {self.mode!r}")
        if not (0 < self.custom_prefix_v4 <= 32):
            raise InvalidEcsPolicyError(
                f"custom_prefix_v4 must be in (0, 32], got {self.custom_prefix_v4}"
            )
        if not (0 < self.custom_prefix_v6 <= 128):
            raise InvalidEcsPolicyError(
                f"custom_prefix_v6 must be in (0, 128], got {self.custom_prefix_v6}"
            )


def render_dnsdist_directives(policy: EcsPolicy) -> tuple[str, ...]:
    """Global directives to prepend to a generated dnsdist config. Empty
    for "disabled" -- there is genuinely nothing to configure, dnsdist
    sends no ECS by default."""
    if policy.mode == "disabled":
        return ()
    if policy.mode == "preserve":
        return ()  # per-server useClientSubnet=true instead; see server_kwargs()
    return (
        f"setECSSourcePrefixV4({policy.custom_prefix_v4})",
        f"setECSSourcePrefixV6({policy.custom_prefix_v6})",
        "setECSOverride(true)",
    )


def server_uses_client_subnet(policy: EcsPolicy) -> bool:
    """Whether generated ``newServer({...})`` calls should set
    ``useClientSubnet=true`` -- only true for "preserve"."""
    return policy.mode == "preserve"
