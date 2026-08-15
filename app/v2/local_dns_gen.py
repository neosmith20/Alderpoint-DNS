"""V2 Local DNS zone generation (Workstream 3 final continuation, §10-11 /
migration §18).

Generates a real BIND zone file from local DNS records (A/AAAA/CNAME/PTR),
validated against the installed ``named-checkzone`` binary via
``app/v2/runtime_staging.py``, mirroring the same generate->validate
pattern as ``app/v2/dnsdist_gen.py``/``app/v2/bind_rpz_gen.py``. Never
writes to the live BIND zone directory or reloads ``named``/``bind9``.
"""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from pathlib import Path

from app.v2.runtime_staging import (
    PromotionResult,
    Validator,
    run_command_validator,
    stage_validate_promote,
)

LOCAL_DNS_ZONE_NAME = "alderpointdns-v2-local.zone"
_VALID_TYPES = ("A", "AAAA", "CNAME", "PTR")


class LocalDnsGenError(ValueError):
    pass


@dataclass(frozen=True)
class LocalDnsRecord:
    fqdn: str
    record_type: str
    value: str
    ttl: int = 300

    def __post_init__(self) -> None:
        if self.record_type not in _VALID_TYPES:
            raise LocalDnsGenError(f"invalid record_type: {self.record_type!r}")
        if not self.fqdn.strip("."):
            raise LocalDnsGenError("fqdn must not be empty")
        if self.ttl <= 0:
            raise LocalDnsGenError(f"ttl must be positive, got {self.ttl}")
        if self.record_type == "A":
            try:
                ipaddress.IPv4Address(self.value)
            except ValueError as exc:
                raise LocalDnsGenError(f"invalid IPv4 value for A record: {self.value!r}") from exc
        elif self.record_type == "AAAA":
            try:
                ipaddress.IPv6Address(self.value)
            except ValueError as exc:
                raise LocalDnsGenError(f"invalid IPv6 value for AAAA record: {self.value!r}") from exc
        elif not self.value.strip("."):
            raise LocalDnsGenError("value must not be empty")


def render_local_dns_zone(records: list[LocalDnsRecord], serial: int | None = None) -> str:
    """Deterministic (given an explicit serial) zone text. Duplicate
    (fqdn, record_type, value) triples are de-duplicated silently (the
    source schema itself enforces this uniqueness — see
    ``local_dns_records`` in V1's schema); a genuine conflict (same
    fqdn+type mapping to two different values, e.g. two different A
    records for one name) is left in the zone as multiple RRs, which is
    valid DNS (round-robin), not rejected here.
    """
    serial = serial if serial is not None else int(time.time())
    lines = [
        "$TTL 300",
        f"@ IN SOA localhost. hostmaster.localhost. {serial} 3600 900 604800 300",
        "@ IN NS localhost.",
        "",
    ]
    seen = set()
    for r in sorted(records, key=lambda r: (r.fqdn, r.record_type, r.value)):
        key = (r.fqdn.strip("."), r.record_type, r.value)
        if key in seen:
            continue
        seen.add(key)
        name = r.fqdn if r.fqdn.endswith(".") else r.fqdn + "."
        value = r.value if r.record_type in ("CNAME", "PTR") and r.value.endswith(".") else r.value
        if r.record_type in ("CNAME", "PTR") and not value.endswith("."):
            value = value + "."
        lines.append(f"{name} {r.ttl} IN {r.record_type} {value}")
    return "\n".join(lines) + "\n"


def named_checkzone_validator(binary: str = "named-checkzone") -> Validator:
    return run_command_validator([binary, LOCAL_DNS_ZONE_NAME, "{path}"])


def stage_and_validate_local_dns_zone(
    staging_root: Path, zone_text: str, live_path: Path, binary: str = "named-checkzone"
) -> PromotionResult:
    return stage_validate_promote(
        staging_root=staging_root,
        name="alderpointdns-v2-local.zone",
        content=zone_text,
        live_path=live_path,
        validator=named_checkzone_validator(binary),
    )
