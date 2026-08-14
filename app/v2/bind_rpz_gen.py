"""V2 isolated BIND/RPZ runtime-config generation prototype (Workstream 3
continuation, §3).

Mirrors ``app/v2/dnsdist_gen.py``'s pattern: pure generation function +
validation against the real installed ``named-checkzone`` binary via
``app/v2/runtime_staging.py``. Never writes to the live BIND zone
directory or reloads the running ``named``/``bind9`` service — every path
used in this workstream's tests is an isolated tempdir.

Scope for tonight: one RPZ zone combining domain-blocklist triggers (from
``app/v2/policy_store.py``'s service definitions and any other qname set a
caller supplies) with per-trigger blocking-response-mode rendering from
``app/v2/blocking_response.py``. Precedence: rules are emitted in a fixed,
deterministic order (allow triggers first via ``PASSTHRU``, then block
triggers) so an explicit allow always overrides a same-named block --
matching the "allow overrides" requirement from §12-13. SafeSearch-specific
CNAME rewrites (§4A) and a from-scratch parallel filtering engine are
explicitly out of scope for this generator; see
``docs/v2/handoff-workstream-4.md``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from app.v2.blocking_response import BlockingResponse, render_rpz_trigger
from app.v2.runtime_staging import (
    PromotionResult,
    Validator,
    run_command_validator,
    stage_validate_promote,
)

RPZ_ZONE_NAME = "alderpointdns-v2.rpz"


class BindRpzGenError(ValueError):
    pass


def _normalize(domain: str) -> str:
    d = domain.strip(".").lower()
    if not d:
        raise BindRpzGenError("domain must not be empty")
    return d


def render_rpz_zone(
    blocked_domains: dict[str, BlockingResponse],
    allowed_domains: list[str],
    serial: int | None = None,
) -> str:
    """Deterministic (given an explicit ``serial``) RPZ zone file text.
    ``blocked_domains`` maps normalized domain -> the response mode to use
    for it; ``allowed_domains`` are emitted first as PASSTHRU overrides so
    they always win over a same-named (or shadowing) block trigger,
    regardless of dict ordering, because RPZ evaluates triggers in the
    order they physically appear in the zone and BIND takes the first
    match.
    """
    serial = serial if serial is not None else int(time.time())
    lines = [
        "$TTL 300",
        f"@ IN SOA localhost. hostmaster.localhost. {serial} 3600 900 604800 300",
        "@ IN NS localhost.",
        "",
    ]

    seen_allow = set()
    for domain in sorted(set(_normalize(d) for d in allowed_domains)):
        lines.append(f"{domain} CNAME rpz-passthru.")
        lines.append(f"*.{domain} CNAME rpz-passthru.")
        seen_allow.add(domain)

    for domain in sorted(blocked_domains):
        norm = _normalize(domain)
        if norm in seen_allow:
            continue  # explicit allow always overrides a block, by construction
        response = blocked_domains[domain]
        lines.extend(render_rpz_trigger(response, norm))

    return "\n".join(lines) + "\n"


def named_checkzone_validator(binary: str = "named-checkzone") -> Validator:
    return run_command_validator([binary, RPZ_ZONE_NAME, "{path}"])


def stage_and_validate_rpz_zone(
    staging_root: Path,
    zone_text: str,
    live_path: Path,
    binary: str = "named-checkzone",
) -> PromotionResult:
    """Stages+validates+promotes into an isolated ``live_path`` (test
    fixture, never the real installed RPZ zone file). No reload/rndc call
    is made here — this proves generation+validation only, per tonight's
    "never promote over the live V1 appliance" constraint.
    """
    return stage_validate_promote(
        staging_root=staging_root,
        name="alderpointdns-v2.rpz",
        content=zone_text,
        live_path=live_path,
        validator=named_checkzone_validator(binary),
    )
