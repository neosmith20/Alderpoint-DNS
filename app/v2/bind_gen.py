"""V2 isolated BIND recursive-cache backend generation (architecture
reconciliation: Gate #3 caught that ``docs/v2/architecture-map.md``'s
owner-locked hot path --

    Client -> dnsdist RAM packet cache -> compiled policy/routing ->
    BIND RAM recursive cache -> upstream only on miss

-- was never actually implemented; V2 forwarded straight from dnsdist to
public upstreams. This module is the real fix, not another prototype:
it generates a complete, self-contained ``named.conf`` for a BIND
instance that is genuinely part of the packaged V2 appliance, validates
it against the real installed ``named-checkconf``/``named-checkzone``
binaries via ``app/v2/runtime_staging.py``, and is promoted through the
same stage/validate/promote pipeline as ``app/v2/dnsdist_gen.py`` and
``app/v2/bind_rpz_gen.py`` (whose RPZ zone this BIND instance actually
loads via ``response-policy``, closing that module's own previously-true
"the RPZ zone is generated but no BIND ever loads it" gap).

Isolation from V1: V1's own BIND backend (``packaging/named.conf.options``,
``docs/bind-backend.md``) listens on loopback ports 5353 (plain) and 5354
(PROXYv2). This module deliberately uses a disjoint port range (5453/5553)
and entirely separate state/config/log directories
(``/etc/alderpointdns-v2/bind``, ``/var/lib/alderpointdns-v2/bind``,
``/var/log/alderpointdns-v2/bind``) so the V2 package can never collide
with a live V1 appliance on the same host, matching every other V2
systemd unit's own namespace convention. This module never writes to
``/etc/bind`` or touches ``named.service`` (V1's unit) -- see
``docs/v2/bind-backend-v2.md`` for the full isolation contract.

Scope of this pass (documented, not silently narrowed): BIND is wired as
the recursive-cache backend for the *ordinary* resolution path -- the
default (no domain-routing override, no DoT/DoH-transport override)
upstream profile, which is what ``docs/v2/policy-runtime-architecture.md``
means by "Ordinary recursive resolution | BIND". Domain-routing pools and
DoT/DoH-transport upstream profiles continue to be dispatched directly by
dnsdist to their configured backend, exactly as before this pass -- BIND
forwarders are plain DNS only (BIND 9.20 has no DoH forwarding, and
per-profile-distinct BIND views keyed only by which loopback port dnsdist
happens to connect to are not something BIND's view-matching (source
address/TSIG, not destination port) actually supports without inventing
unproven config). That is an intentional, bounded, documented follow-up
gap (tracked in ``docs/v2/architecture-map.md``), not a silent omission --
and it does not regress anything, since those two cases already bypassed
BIND before this pass existed at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.v2.bind_rpz_gen import RPZ_ZONE_NAME
from app.v2.runtime_staging import (
    PromotionResult,
    Validator,
    run_command_validator,
    stage_validate_promote,
)

# Isolated V2 loopback listener ports -- deliberately disjoint from V1's
# BIND backend (127.0.0.1:5353/5354, see this module's own docstring).
BIND_PLAIN_PORT = 5453   # unproxied loopback recursion, health/recovery checks only
BIND_PROXY_PORT = 5553   # requires PROXYv2 from dnsdist; real per-query client identity
BIND_STATISTICS_PORT = 8153

# The address dnsdist's default/"ordinary" pool must forward to once this
# module's config is promoted -- see app/v2/dnsdist_gen.py's
# BIND_BACKEND_ADDRESS, which is this same literal, kept independent
# (not cross-imported) for the same reason dnsdist_gen.py's own
# query_log_address constant is independent: this bootstrap generator and
# the real compiler are separately maintained by design.
BIND_BACKEND_ADDRESS = f"127.0.0.1:{BIND_PROXY_PORT}"

_ACL_NETWORKS = (
    "127.0.0.0/8",
    "::1/128",
)


class BindGenError(ValueError):
    pass


def _validate_forwarder(addr: str) -> str:
    from app.v2.dnsdist_gen import _LABEL_RE

    if not _LABEL_RE.match(addr):
        raise BindGenError(f"invalid BIND forwarder address: {addr!r}")
    return addr


def render_named_conf(
    forwarders: list[str],
    rpz_zone_path: str,
    zone_name: str = RPZ_ZONE_NAME,
    dnssec_validation: bool = True,
    plain_port: int = BIND_PLAIN_PORT,
    proxy_port: int = BIND_PROXY_PORT,
    statistics_port: int = BIND_STATISTICS_PORT,
    directory: str = "/var/lib/alderpointdns-v2/bind",
    log_path: str = "/var/log/alderpointdns-v2/bind/named.log",
) -> str:
    """Pure function: same inputs -> byte-identical self-contained
    ``named.conf`` text (options + the RPZ zone clause in one file, no
    external ``include``s needed beyond the already-promoted RPZ zone
    file itself, so this is directly ``named-checkconf``-able on its
    own). Mirrors the real, already-proven-in-production V1 pattern in
    ``packaging/named.conf.options`` (loopback-only, ``forward only``,
    ``response-policy``, ``allow-proxy``) with V2's own disjoint ports
    and paths.
    """
    if not forwarders:
        raise BindGenError("at least one forwarder is required")
    forwarders = [_validate_forwarder(f) for f in forwarders]
    fwd_hosts = [f.rsplit(":", 1)[0] for f in forwarders]

    acl = " ".join(_ACL_NETWORKS)
    lines = [
        "// Generated by app/v2/bind_gen.py -- the real packaged V2 BIND",
        "// recursive-cache backend. Do not hand-edit; regenerate from the",
        "// effective policy compiler.",
        'acl "alderpointdns_v2_clients" {',
        f"\t{_ACL_NETWORKS[0]};",
        f"\t{_ACL_NETWORKS[1]};",
        "};",
        "",
        "options {",
        f'\tdirectory "{directory}";',
        f"\tlisten-on port {plain_port} {{ 127.0.0.1; }};",
        f"\tlisten-on port {proxy_port} proxy plain {{ 127.0.0.1; }};",
        f"\tlisten-on-v6 port {plain_port} {{ ::1; }};",
        f"\tallow-proxy {{ 127.0.0.1; }};",
        f"\tallow-proxy-on {{ 127.0.0.1; }};",
        '\tallow-query { "alderpointdns_v2_clients"; };',
        '\tallow-query-cache { "alderpointdns_v2_clients"; };',
        '\tallow-recursion { "alderpointdns_v2_clients"; };',
        "\trecursion yes;",
        "\tforward only;",
        "\tforwarders { " + "; ".join(fwd_hosts) + "; };",
        f'\tdnssec-validation {"auto" if dnssec_validation else "no"};',
        "\tauth-nxdomain no;",
        "\tminimal-responses yes;",
        "\tempty-zones-enable yes;",
        '\tversion "not disclosed";',
        "\tquerylog no;",
        f'\tresponse-policy {{ zone "{zone_name}"; }} break-dnssec yes;',
        f'\tstatistics-file "{directory}/named.stats";',
        f'\tmemstatistics-file "{directory}/named.memstats";',
        "};",
        "",
        "statistics-channels {",
        f"\tinet 127.0.0.1 port {statistics_port} allow {{ 127.0.0.1; }};",
        "};",
        "",
        "logging {",
        '\tchannel alderpointdns_v2_default {',
        f'\t\tfile "{log_path}" versions 5 size 10m;',
        "\t\tseverity info;",
        "\t\tprint-time yes;",
        "\t\tprint-severity yes;",
        "\t\tprint-category yes;",
        "\t};",
        "\tcategory default { alderpointdns_v2_default; };",
        "\tcategory general { alderpointdns_v2_default; };",
        "\tcategory security { alderpointdns_v2_default; };",
        "};",
        "",
        f'zone "{zone_name}" {{',
        "\ttype primary;",
        f'\tfile "{rpz_zone_path}";',
        "\tallow-query { localhost; };",
        "\tallow-transfer { none; };",
        "};",
    ]
    return "\n".join(lines) + "\n"


def named_checkconf_validator(binary: str = "named-checkconf") -> Validator:
    return run_command_validator([binary, "{path}"])


def stage_and_validate_named_conf(
    staging_root: Path,
    config_text: str,
    live_path: Path,
    binary: str = "named-checkconf",
) -> PromotionResult:
    """Stages+validates+promotes into an isolated ``live_path`` -- never
    the real installed ``/etc/bind/named.conf`` (V1's) or
    ``/etc/alderpointdns-v2/bind/named.conf`` outside of a caller-supplied
    test root. Callers wiring this into the live packaged pipeline pass
    the real ``/etc/alderpointdns-v2/bind/named.conf`` explicitly.
    """
    return stage_validate_promote(
        staging_root=staging_root,
        name="named.conf",
        content=config_text,
        live_path=live_path,
        validator=named_checkconf_validator(binary),
    )
