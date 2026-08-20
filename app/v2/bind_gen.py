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
BIND_RNDC_PORT = 9553    # DNS Cache view/flush (beta-rescue priority 3A): loopback-only rndc control channel
RNDC_KEY_NAME = "alderpointdns-v2-rndc-key"

# Multi-context BIND (Gate #3 acceptance closure): a fixed, bounded number
# of simultaneous distinct plain-upstream BIND contexts -- see
# packaging/v2/alderpointdns-v2-bind@.service (a systemd template unit,
# one real instance per context) and alderpointdns-v2-bind-reload.service
# (unconditionally restarts exactly this many instance names every
# promotion; each instance's own ConditionPathExists makes restarting an
# unused slot a safe no-op). A 5th+ distinct plain upstream selection in
# one compile is a real, documented, conservative bound -- it continues
# dispatching direct-to-upstream exactly as before this pass, the same
# documented exception already applied to DoT/DoH/ECS, rather than
# silently growing an unbounded number of live processes per compile.
MAX_BIND_CONTEXTS = 4

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

# Real defect found live during Gate #3 acceptance cross-policy E2E
# testing: allow-query/allow-query-cache/allow-recursion previously used
# _ACL_NETWORKS (loopback only), which is correct for the PROXYv2
# listener's OWN allow-proxy/allow-proxy-on (only dnsdist itself, from
# 127.0.0.1, may ever speak the proxy protocol to BIND) but wrong for
# the client ACL: PROXYv2 deliberately forwards the REAL original LAN
# client address through to BIND, and BIND then evaluates allow-query/
# allow-recursion against THAT real address, not dnsdist's own loopback
# address. With the client ACL restricted to loopback, any real LAN
# client's query was REFUSED by BIND once PROXYv2 correctly exposed its
# real, non-loopback source address -- confirmed live: a query from a
# real 10.0.x.x client through a BIND-routed pool returned REFUSED with
# BIND's own EDE "Prohibited"/"recursion disabled", while a query
# answered entirely by dnsdist itself (never reaching BIND) worked fine,
# masking the defect until a pool that genuinely needed a BIND round
# trip was exercised from a real (non-loopback) client address. Matches
# the same private ranges the appliance's own dnsdist ACL already uses.
_CLIENT_NETWORKS = (
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
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
    # Real, verified-live DoT-forwarding support (BIND 9.20): when set,
    # every forwarder in this context is a DoT upstream, verified against
    # this exact hostname's certificate -- `tls <name> { remote-hostname
    # "<host>"; };` + `forwarders { <ip> port <port> tls <name>; };`.
    # Proven live: a real query through this exact config pattern
    # returned NOERROR with the `ad` (DNSSEC-validated) flag set, and
    # returned SERVFAIL only when a leftover process/state from an
    # earlier, unrelated test occupied the same directory/port -- not a
    # BIND/config limitation (see docs/v2/bind-backend-v2.md).
    tls_hostname: str | None = None,
    rndc_port: int | None = None,
    rndc_key_secret: str | None = None,
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
    if (rndc_port is None) != (rndc_key_secret is None):
        raise BindGenError("rndc_port and rndc_key_secret must be given together")
    forwarders = [_validate_forwarder(f) for f in forwarders]
    fwd_hosts = [f.rsplit(":", 1)[0] for f in forwarders]
    fwd_ports = [f.rsplit(":", 1)[1] for f in forwarders]

    tls_block: list[str] = []
    if tls_hostname:
        tls_block = [
            "tls dot_upstream {",
            f'\tremote-hostname "{tls_hostname}";',
            "};",
            "",
        ]
        forwarders_clause = "; ".join(f"{h} port {p} tls dot_upstream" for h, p in zip(fwd_hosts, fwd_ports))
    else:
        # Real bug found live during Gate #3 DoH-egress acceptance
        # testing: BIND's `forwarders { <host>; ... };` clause defaults
        # to port 53 when no port is given, silently dropping any
        # non-standard forwarder port -- masked in every earlier test
        # because every plain forwarder used so far (1.1.1.1:53,
        # 9.9.9.9:53, ...) happened to already be port 53. The local
        # DoH-egress transport (app/v2/doh_egress_gen.py) is the first
        # real plain forwarder that isn't on port 53, and it exposed
        # this: BIND's forwarders never reached the egress process at
        # all (SERVFAIL) even though the egress process itself answered
        # correctly when queried directly. Fixed by always emitting an
        # explicit `port` clause, matching the TLS branch's own pattern.
        forwarders_clause = "; ".join(f"{h} port {p}" for h, p in zip(fwd_hosts, fwd_ports))

    lines = tls_block + [
        "// Generated by app/v2/bind_gen.py -- the real packaged V2 BIND",
        "// recursive-cache backend. Do not hand-edit; regenerate from the",
        "// effective policy compiler.",
        'acl "alderpointdns_v2_clients" {',
        *(f"\t{net};" for net in _CLIENT_NETWORKS),
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
        "\tforwarders { " + forwarders_clause + "; };",
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
    ] + (
        [
            # DNS Cache view/flush (beta-rescue priority 3A): a real,
            # loopback-only rndc control channel so the web process's
            # privileged helper can issue `rndc flush`/`flushname`/
            # `flushtree` against this exact context -- no other channel
            # exists for this in the packaged runtime.
            f'key "{RNDC_KEY_NAME}" {{',
            "\talgorithm hmac-sha256;",
            f'\tsecret "{rndc_key_secret}";',
            "};",
            "",
            "controls {",
            f'\tinet 127.0.0.1 port {rndc_port} allow {{ 127.0.0.1; }} keys {{ "{RNDC_KEY_NAME}"; }};',
            "};",
            "",
        ] if rndc_port is not None else []
    ) + [
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


# --- multi-context (custom upstream profiles / domain routing) ----------
#
# Gate #3 acceptance closure: a genuinely different plain upstream
# selection (a custom upstream profile, a domain-routing rule) must get
# its own real BIND-backed recursive cache, not silently bypass BIND or
# share a cache with an unrelated upstream choice. Real, verified-live
# investigation ruled out BIND "views" matched by ``match-destinations``
# on distinct loopback addresses: a process explicitly ``listen-on``-ing
# a non-.1 loopback address (127.0.0.2, ...) needs that address actually
# assigned to an interface first (confirmed live: named silently failed
# to bind it, `ip addr add ...` requires CAP_NET_ADMIN the live
# management-API's own unprivileged runtime user does not have, and a
# dynamic per-compile set of contexts can't be pre-provisioned by a
# static systemd unit). The port-based design below needs no extra
# infrastructure at all -- confirmed live, zero setup beyond what a
# single BIND instance already needs.
#
# One independent ``named`` process per context, each on 127.0.0.1 (and
# ::1) with its own disjoint port pair, each with its own state/log
# subdirectory and its own real, independent RAM recursive cache. A
# systemd template unit (``alderpointdns-v2-bind@.service``) runs however
# many contexts a given compile actually needs.


@dataclass(frozen=True)
class BindContext:
    """One isolated BIND recursive-cache context (its own forwarder set,
    own process, own ports, own cache) -- see this module's own note
    above for why this is port-based, not view-based.
    """

    name: str
    forwarders: tuple[str, ...]
    plain_port: int
    proxy_port: int
    # Real, verified-live DoT-forwarding support (BIND 9.20) -- see
    # render_named_conf's own tls_hostname docstring. None => plain.
    tls_hostname: str | None = None

    def __post_init__(self) -> None:
        if not self.forwarders:
            raise BindGenError(f"context {self.name!r} has no forwarders")
        for f in self.forwarders:
            _validate_forwarder(f)
        if self.plain_port == self.proxy_port:
            raise BindGenError(f"context {self.name!r} plain_port and proxy_port must differ")


@dataclass(frozen=True)
class UpstreamSelection:
    """One distinct upstream selection to allocate a BIND context for --
    the allocation key. Two selections are the "same" context (dedup) only
    if both their forwarders AND their tls_hostname match; a plain
    selection and a DoT selection to the same IP:port are never merged.
    """

    forwarders: tuple[str, ...]
    tls_hostname: str | None = None

    def __hash__(self):
        return hash((self.forwarders, self.tls_hostname))


def allocate_bind_contexts(selections: "list[UpstreamSelection] | list[tuple[str, ...]]") -> list[BindContext]:
    """Deterministic context/port allocation for a list of distinct
    upstream selections (already de-duplicated and ordered by the caller
    -- see ``dnsdist_policy_runtime.py``'s own deterministic ordering
    requirement, §2H): the first gets the well-known default ports
    (``BIND_PLAIN_PORT``/``BIND_PROXY_PORT``, i.e. ``BIND_BACKEND_ADDRESS``
    stays valid for the common single-context case), each subsequent
    context gets the next disjoint port pair 2 apart. Same inputs in the
    same order always produce the same ports, so a caller can regenerate
    without invalidating other already-running contexts' identities
    unnecessarily. Only the first ``MAX_BIND_CONTEXTS`` are allocated --
    callers must keep any excess selections routed direct-to-upstream
    (see this module's own ``MAX_BIND_CONTEXTS`` docstring).

    Accepts either ``UpstreamSelection`` objects or bare forwarder tuples
    (back-compat with every caller/test written before DoT-through-BIND
    support -- treated as plain, ``tls_hostname=None``).
    """
    normalized = [
        s if isinstance(s, UpstreamSelection) else UpstreamSelection(forwarders=s)
        for s in selections
    ]
    contexts = []
    for i, sel in enumerate(normalized[:MAX_BIND_CONTEXTS]):
        contexts.append(
            BindContext(
                name=f"ctx{i}",
                forwarders=sel.forwarders,
                plain_port=BIND_PLAIN_PORT + 2 * i,
                proxy_port=BIND_PROXY_PORT + 2 * i,
                tls_hostname=sel.tls_hostname,
            )
        )
    return contexts


def context_backend_address(ctx: BindContext) -> str:
    """The address dnsdist's pool for this context must forward to
    (PROXYv2, matching ``BIND_BACKEND_ADDRESS``'s own convention)."""
    return f"127.0.0.1:{ctx.proxy_port}"


def render_named_conf_for_context(
    ctx: BindContext,
    rpz_zone_path: str,
    zone_name: str = RPZ_ZONE_NAME,
    dnssec_validation: bool = True,
    statistics_port: int | None = None,
    directory: str | None = None,
    log_path: str | None = None,
    rndc_key_secret: str | None = None,
) -> str:
    """One context's ``named.conf`` -- thin wrapper over the proven
    single-context ``render_named_conf``, just parameterized by the
    context's own allocated ports/directory/log path so multiple
    contexts' processes never collide on any file or port.
    """
    return render_named_conf(
        list(ctx.forwarders),
        rpz_zone_path,
        zone_name=zone_name,
        dnssec_validation=dnssec_validation,
        plain_port=ctx.plain_port,
        proxy_port=ctx.proxy_port,
        statistics_port=statistics_port if statistics_port is not None else (BIND_STATISTICS_PORT + list_index_of(ctx)),
        directory=directory or f"/var/lib/alderpointdns-v2/bind/{ctx.name}",
        log_path=log_path or f"/var/log/alderpointdns-v2/bind/{ctx.name}/named.log",
        tls_hostname=ctx.tls_hostname,
        rndc_port=(BIND_RNDC_PORT + list_index_of(ctx)) if rndc_key_secret is not None else None,
        rndc_key_secret=rndc_key_secret,
    )


def list_index_of(ctx: BindContext) -> int:
    # Derived from the context's own plain_port offset rather than
    # threading a separate index parameter through every caller --
    # allocate_bind_contexts() always assigns plain_port =
    # BIND_PLAIN_PORT + 2*i, so this recovers i exactly.
    return (ctx.plain_port - BIND_PLAIN_PORT) // 2


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
