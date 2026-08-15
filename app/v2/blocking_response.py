"""V2 blocking response modes (Workstream 3 continuation, §6).

A pure, validated representation of "what happens when a query is
blocked": ``nxdomain``, ``refused``, ``null_ip``, or ``custom_ip``
(IPv4/IPv6). This module only decides *what the response should be* and
how to render it into an RPZ trigger action; it does not itself answer DNS
queries.

Cache-profile interaction: ``policy_compiler.py`` already includes
``blocking_response_mode`` in ``CachePolicyDimensions`` (Workstream 2), so
changing between these modes always changes the compiled cache profile —
proven again here at the rendering layer via
``tests/v2/test_blocking_response.py::test_response_mode_change_alters_rpz_output``,
since two profiles that render different DNS answers must never be allowed
to share a cache profile id.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

_VALID_MODES = ("nxdomain", "refused", "null_ip", "custom_ip")


class InvalidBlockingResponseError(ValueError):
    pass


@dataclass(frozen=True)
class BlockingResponse:
    mode: str
    custom_ipv4: Optional[str] = None
    custom_ipv6: Optional[str] = None
    ttl_seconds: int = 300

    def __post_init__(self) -> None:
        if self.mode not in _VALID_MODES:
            raise InvalidBlockingResponseError(f"invalid blocking response mode: {self.mode!r}")
        if self.ttl_seconds <= 0 or self.ttl_seconds > 86400:
            raise InvalidBlockingResponseError(
                f"ttl_seconds must be in (0, 86400], got {self.ttl_seconds}"
            )
        if self.mode == "custom_ip":
            if not self.custom_ipv4 and not self.custom_ipv6:
                raise InvalidBlockingResponseError(
                    "custom_ip mode requires at least one of custom_ipv4/custom_ipv6"
                )
            if self.custom_ipv4 is not None:
                try:
                    ipaddress.IPv4Address(self.custom_ipv4)
                except ValueError as exc:
                    raise InvalidBlockingResponseError(
                        f"invalid custom_ipv4: {self.custom_ipv4!r}"
                    ) from exc
            if self.custom_ipv6 is not None:
                try:
                    ipaddress.IPv6Address(self.custom_ipv6)
                except ValueError as exc:
                    raise InvalidBlockingResponseError(
                        f"invalid custom_ipv6: {self.custom_ipv6!r}"
                    ) from exc
        elif self.custom_ipv4 is not None or self.custom_ipv6 is not None:
            raise InvalidBlockingResponseError(
                f"custom_ipv4/custom_ipv6 only valid with mode='custom_ip', got mode={self.mode!r}"
            )


def render_rpz_trigger(response: BlockingResponse, rpz_name: str) -> tuple[str, ...]:
    """Render the RPZ trigger record(s) for one blocked name, per BIND's
    response-policy-zone action vocabulary. ``rpz_name`` is the already-
    normalized (trailing-dot-stripped) trigger name.

    ``refused`` mode is intentionally NOT rendered as a real BIND/RPZ
    action here — RPZ has no native REFUSED trigger, and substituting
    ``rpz-drop`` would silently return a different RCODE than the operator
    configured (a drop is not a REFUSED response; a client sees a timeout,
    not RCODE 5). The authoritative implementation for ``refused`` lives
    at the dnsdist layer instead (``app/v2/dnsdist_gen.py``'s
    ``render_refused_block_rules`` -> real ``RCodeAction(DNSRCode.REFUSED)``,
    verified end-to-end against the installed dnsdist binary to actually
    return RCODE REFUSED to the client) since dnsdist sits in front of
    BIND and answers the query before RPZ would ever see it. Rendering an
    ``rpz-drop`` fallback here too, as defense-in-depth for the case where
    BIND is somehow queried directly (bypassing dnsdist), is still
    reasonable -- it just must never be described as equivalent to
    REFUSED.
    """
    if response.mode == "nxdomain":
        return (f"{rpz_name} CNAME .", f"*.{rpz_name} CNAME .")
    if response.mode == "refused":
        # Defense-in-depth only (see docstring) -- drop, not REFUSED.
        return (f"{rpz_name} CNAME rpz-drop.", f"*.{rpz_name} CNAME rpz-drop.")
    if response.mode == "null_ip":
        return (
            f"{rpz_name} A 0.0.0.0",
            f"*.{rpz_name} A 0.0.0.0",
            f"{rpz_name} AAAA ::",
            f"*.{rpz_name} AAAA ::",
        )
    # custom_ip
    lines = []
    if response.custom_ipv4:
        lines.append(f"{rpz_name} A {response.custom_ipv4}")
        lines.append(f"*.{rpz_name} A {response.custom_ipv4}")
    if response.custom_ipv6:
        lines.append(f"{rpz_name} AAAA {response.custom_ipv6}")
        lines.append(f"*.{rpz_name} AAAA {response.custom_ipv6}")
    return tuple(lines)
