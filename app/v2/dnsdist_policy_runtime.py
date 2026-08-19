"""V2 real per-effective-policy DNS runtime enforcement (Gate #2 Blocker
2).

**The real answer path, documented (§2A):**

    client identity (source network)
      -> matched against ordered, most-specific-network-first client
         policy bindings (this module)
      -> SafeSearch rewrite rule for this binding's network+domain, IF
         the qname matches a supported provider domain (terminal:
         SpoofCNAMEAction, dnsdist never forwards/caches this)
      -> parental/security/service block rule for this binding's
         network+domain, IF the qname matches a blocked domain in this
         binding's rulesets (terminal: RCodeAction/SpoofAction per the
         binding's blocking_response_mode, dnsdist never forwards/caches
         this)
      -> domain-specific routing rule for this binding's network+domain,
         IF configured (terminal: PoolAction into a routed pool)
      -> catch-all PoolAction into this binding's own policy pool
         (named after its effective cache profile id, so two bindings
         with IDENTICAL effective policy share one pool)
      -> that pool's PacketCache (per-pool, so incompatible policies can
         never share a cache entry) -> cache hit answered directly, OR
      -> that pool's newServer()s (real transport/ECS per this binding's
         upstream profile) -> real upstream query -> BIND (if the
         upstream profile points at the shared local BIND recursive
         resolver) -> answer flows back through dnsdist, gets cached in
         THIS pool's cache only, response returned to client.

Everything answer-producing (SafeSearch, parental, security, service
block, response mode, upstream/routing/ECS differences) is decided and
enforced entirely at the dnsdist layer, per-client-network, BEFORE any
query reaches a shared upstream/BIND -- so BIND's own recursive cache
never needs to be partitioned by policy at all (§2B/§29): every query
BIND ever sees is one dnsdist already decided is safe to forward, and the
real answer for a given qname/qtype doesn't depend on which policy asked
(policy differences are entirely resolved by dnsdist before or after the
BIND hop, never inside it). This directly replaces the prior single
global-RPZ/global-config design that Blocker 2 correctly identified as
insufficient -- BIND/RPZ generation (``app/v2/bind_rpz_gen.py``) is no
longer where policy-differentiated blocking decisions are enforced; RPZ
is retained only as an optional whole-appliance-wide defense-in-depth
layer for domains that are blocked for literally everyone (see
``docs/v2/policy-runtime-architecture.md``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_gen import _lua_string
from app.v2.dnsdist_cache_policy import DEFAULT_MAX_CACHE_ENTRIES, DEFAULT_MAX_CACHE_TTL_SECONDS
from app.v2.dns_name_validate import InvalidDnsNameError, validate_dns_name
from app.v2.ecs_policy import EcsPolicy, render_dnsdist_directives, server_uses_client_subnet
from app.v2.network_match import NetworkScope
from app.v2 import safesearch as safesearch_mod


class PolicyRuntimeError(ValueError):
    pass


@dataclass(frozen=True)
class ClientPolicyBinding:
    """Everything needed to compile one client-network's real runtime
    enforcement. ``cache_profile_id`` (from
    ``policy_compiler.compile_cache_profile``) is the pool/cache dedup
    key: two bindings with the same id are guaranteed by construction
    (Workstream 2/3's cache-profile compiler) to be answer-identical, so
    they intentionally share one pool and one packet cache here.
    """

    network: NetworkScope
    cache_profile_id: str
    safesearch_providers: tuple[str, ...] = ()  # subset of safesearch.SUPPORTED_PROVIDERS
    blocked_domains: dict = field(default_factory=dict)  # domain -> BlockingResponse
    allowed_domains: frozenset = frozenset()
    domain_routes: tuple = ()  # (suffix_domain, upstream_endpoints, transport, strategy)
    upstream_endpoints: tuple = ()  # policy_store.UpstreamEndpointRecord-shaped tuples
    upstream_transport: str = "plain"
    ecs_policy: EcsPolicy = field(default_factory=lambda: EcsPolicy(mode="disabled"))


def _endpoint_server_line(address: str, pool: str, transport: str, tls_hostname, doh_path, use_ecs: bool) -> str:
    kwargs = f'address={_lua_string(address)}, pool={_lua_string(pool)}'
    if use_ecs:
        kwargs += ", useClientSubnet=true"
    if transport == "dot":
        kwargs += ', tls="openssl"'
        if tls_hostname:
            kwargs += f", subjectName={_lua_string(tls_hostname)}"
    elif transport == "doh":
        if not tls_hostname:
            raise PolicyRuntimeError(f"DoH endpoint {address!r} has no tls_hostname")
        path = doh_path or "/dns-query"
        kwargs += f', tls="openssl", dohPath={_lua_string(path)}, subjectName={_lua_string(tls_hostname)}'
    return f"newServer({{{kwargs}}})"


def _bind_server_line(pool: str, backend_address: str) -> str:
    """BIND architecture correction (Gate #3): the real ``newServer()``
    line for a pool that's been determined to route through a packaged V2
    BIND recursive-cache context (``app/v2/bind_gen.py``) instead of
    directly to its configured plain upstream endpoints. Real, verified
    dnsdist 2.1.1 syntax -- see ``app/v2/dnsdist_gen.py``'s
    ``UpstreamServer.use_proxy_protocol``.
    """
    return f'newServer({{address={_lua_string(backend_address)}, pool={_lua_string(pool)}, useProxyProtocol=true}})'


def _route_via_bind(
    endpoints: tuple, transport: str, use_ecs: bool, bind_context_addresses: dict,
) -> "str | None":
    """The BIND context backend address a pool's plain-transport
    endpoints should be routed through, or ``None`` to keep going
    straight to their configured upstream addresses.

    Deliberately conservative (§ preserve upstream/routing/ECS
    semantics): only ever true for ``plain`` or ``dot`` transport, and
    ECS not in use for this pool. Real, verified-live limitations, not
    assumptions (see ``docs/v2/bind-backend-v2.md``):

    - ECS: ISC confirms open-source BIND has no resolver-side EDNS
      Client Subnet support at all (only the commercial Subscription
      Edition does; verified independently against the installed binary
      -- no ``client-subnet``/``ecs-zones`` directive exists in it). An
      ECS-using pool categorically cannot be routed through BIND without
      silently dropping its ECS behavior -- it keeps going direct,
      always. This is a narrow, explicit, documented architecture
      exception, not a general BIND bypass.
    - DoT: real, verified, certificate-hostname-verified forwarding
      through BIND 9.20 works (``forwarders { <ip> port 853 tls
      <profile>; }`` + ``tls <profile> { remote-hostname "<host>"; }``,
      proven live with a real DNSSEC-validated answer -- see
      ``app/v2/bind_gen.py``'s ``tls_hostname`` support). Routed through
      BIND like plain, keyed by ``(forwarders, tls_hostname)`` so a DoT
      selection is never merged with an unrelated plain or differently-
      verified DoT selection.
    - DoH: BIND has no native DoH-forwarder capability at all (not a
      configuration gap, an actual missing feature) -- DoH pools keep
      going direct-to-upstream from dnsdist, unchanged. See
      ``docs/v2/bind-backend-v2.md`` for the local-egress-transport
      alternative under consideration for DoH.

    ``bind_context_addresses`` maps each distinct, allocated
    ``(forwarders_frozenset, tls_hostname)`` key (see
    ``app/v2/bind_gen.UpstreamSelection``/``allocate_bind_contexts``,
    called by the compiler's caller) to that context's backend address.
    A pool whose exact key was allocated a context routes through it;
    any pool whose key wasn't allocated one (beyond
    ``bind_gen.MAX_BIND_CONTEXTS``, a documented, conservative bound)
    keeps going direct -- collapsing two different upstream choices onto
    one shared BIND forwarder list would silently change which upstream
    actually answers a given client's queries, which this compiler must
    never do.
    """
    if transport not in ("plain", "dot") or use_ecs or not bind_context_addresses:
        return None
    tls_hostname = None
    if transport == "dot":
        hostnames = {ep.tls_hostname for ep in endpoints}
        if len(hostnames) != 1 or None in hostnames:
            return None  # mixed/missing hostnames within one pool: not a safe single tls block
        tls_hostname = hostnames.pop()
    key = (frozenset(ep.address for ep in endpoints), tls_hostname)
    return bind_context_addresses.get(key)


def _route_doh_via_bind(endpoints: tuple, transport: str, use_ecs: bool, doh_bind_context_addresses: dict) -> "str | None":
    """DoH-through-BIND (Gate #3 acceptance closure #4): BIND has no
    native DoH-forwarder capability at all, so a DoH pool can only reach
    BIND's recursive cache indirectly, via a local DoH-egress dnsdist
    process (``app/v2/doh_egress_gen.py``) that BIND's own forwarders
    point at (plain DNS, loopback-only) and which re-encrypts to the
    real DoH upstream -- proven live end-to-end (real Cloudflare DoH
    answer, DNSSEC-validated, through this exact chain). ``endpoints``
    are keyed by ``(address, doh_path, tls_hostname)`` since all three
    identify a distinct DoH upstream; a DoH selection with no allocated
    egress+BIND context pair keeps going direct, same conservative
    bound as plain/DoT.
    """
    if transport != "doh" or use_ecs or not doh_bind_context_addresses:
        return None
    key = frozenset((ep.address, getattr(ep, "doh_path", None), ep.tls_hostname) for ep in endpoints)
    return doh_bind_context_addresses.get(key)


def _refused_or_spoof_action(response: BlockingResponse) -> str:
    if response.mode == "refused":
        return "RCodeAction(DNSRCode.REFUSED)"
    if response.mode == "nxdomain":
        return "RCodeAction(DNSRCode.NXDOMAIN)"
    if response.mode == "null_ip":
        return 'SpoofAction({"0.0.0.0", "::"})'
    addrs = [a for a in (response.custom_ipv4, response.custom_ipv6) if a]
    addr_list = ", ".join(_lua_string(a) for a in addrs) or '"0.0.0.0"'
    return f"SpoofAction({{{addr_list}}})"


def _local_dns_rule_lines(local_dns_records: list[tuple]) -> list[str]:
    """Appliance-wide (not per-network -- V1's local DNS records were
    never network-scoped either, and a LAN hostname answer isn't a
    policy-differentiated decision the way blocking/SafeSearch are) terminal
    rules for locally-defined A/AAAA/CNAME records, deterministically
    ordered by (name, record_type, value) so repeated compiles of the same
    control.db state are byte-identical.

    PTR records are intentionally NOT compiled here -- a PTR answer is
    looked up by a different qname (under in-addr.arpa/ip6.arpa) and
    qtype than the forward record it's paired with, which needs its own
    matcher, not a same-name QNameRule; not implemented yet. Callers
    (``app/v2/runtime_compile.py``) are expected to warn, not silently
    drop, when a PTR record is present but excluded here.
    """
    lines: list[str] = []
    for name, record_type, value, _ttl in sorted(local_dns_records, key=lambda r: (r[0], r[1], r[2])):
        if record_type == "PTR":
            continue
        try:
            validated_name = validate_dns_name(name)
        except InvalidDnsNameError as exc:
            raise PolicyRuntimeError(f"invalid local DNS record name {name!r}: {exc}") from exc
        matcher = f'QNameRule({_lua_string(validated_name + ".")})'
        if record_type in ("A", "AAAA"):
            lines.append(f'addAction({matcher}, SpoofAction({{{_lua_string(value)}}}))')
        elif record_type == "CNAME":
            target = value.rstrip(".") + "."
            try:
                validate_dns_name(value.rstrip("."))
            except InvalidDnsNameError as exc:
                raise PolicyRuntimeError(f"invalid local DNS CNAME target {value!r}: {exc}") from exc
            lines.append(f'addAction({matcher}, SpoofCNAMEAction({_lua_string(target)}))')
        else:
            raise PolicyRuntimeError(f"unsupported local DNS record_type: {record_type!r}")
    return lines


# Local-only IPC address for the real analytics event producer (roadmap
# Priority 6 continuation -- see
# docs/v2/analytics-ingestion-not-wired-to-live-dns.md for the gap this
# closes, and app/v2/dnsdist_protobuf.py for the receiver-side decoder).
# dnsdist's RemoteLogger is documented fire-and-forget: an unreachable
# receiver logs a warning and never blocks or fails a query, so this is
# always safe to emit even before/without the receiver service running.
ANALYTICS_PROTOBUF_LOG_ADDRESS = "127.0.0.1:5391"

# Local-only UDP address for the real client-discovery observer (roadmap
# Priority 12 continuation -- see docs/v2/two-node-replication-discovery-
# acceptance.md for the gap this closes: alderpointdns-v2-dns-observer's
# own ingress on 1053 was real, tested, and running from a fresh install
# onward, but nothing in this generator ever sent it a copy of real
# client traffic -- observational discovery from real DNS-originated
# packets genuinely did not work end to end until this was wired in,
# confirmed live by a real two-node acceptance pass finding
# /api/discovery/observed-clients stayed empty under real dnsdist
# traffic. dnsdist's TeeAction duplicates the query datagram to a
# second UDP target and never blocks on or uses that target's response
# -- the same fire-and-forget safety property RemoteLogger already
# gives the analytics producer above, so this cannot slow down or
# affect a real client's own answer even if dns-observer is
# unreachable, degraded, or slow.
DISCOVERY_INGRESS_ADDRESS = "127.0.0.1:1053"


@dataclass(frozen=True)
class DotConfig:
    """DNS-over-TLS listener configuration (roadmap continuation: closes
    part of the confirmed mandatory-parity gap documented in
    docs/v2/encrypted-transport-parity-gap.md). Reuses the appliance's
    existing management-API TLS cert/key (``cert_path``/``key_path`` --
    the caller passes ``app/v2/webapp.py``'s ``ACTIVE_CERT_PATH``/
    ``ACTIVE_KEY_PATH``) rather than provisioning separate key material,
    matching V1's real, production-proven ``packaging/dnsdist.conf``
    pattern (a single appliance-wide cert used for DoH/DoT alike).
    ``min_tls_version``/``ciphers`` match V1's own real values verbatim
    (``tls1.2`` / ``HIGH:!aNULL:!MD5:!RC4``) -- a real, already-deployed
    baseline, not a new choice made here.
    """

    enabled: bool
    port: int
    cert_path: str
    key_path: str
    min_tls_version: str = "tls1.2"
    ciphers: str = "HIGH:!aNULL:!MD5:!RC4"


def _dot_bind_lines(listen_address: str, dot: DotConfig) -> list[str]:
    host = listen_address.rsplit(":", 1)[0]
    return [
        f'addTLSLocal("{host}:{dot.port}", {{{_lua_string(dot.cert_path)}}}, {{{_lua_string(dot.key_path)}}}, {{',
        "  reusePort=true,",
        f'  minTLSVersion={_lua_string(dot.min_tls_version)},',
        f'  ciphers={_lua_string(dot.ciphers)}',
        "})",
        "",
    ]


@dataclass(frozen=True)
class DohConfig:
    """DNS-over-HTTPS listener configuration -- same rationale/cert-reuse
    approach as ``DotConfig`` above, plus the real RFC 8484 default path
    (``/dns-query``), matching V1's own real, production-proven
    ``packaging/dnsdist.conf`` default verbatim."""

    enabled: bool
    port: int
    cert_path: str
    key_path: str
    path: str = "/dns-query"
    min_tls_version: str = "tls1.2"
    ciphers: str = "HIGH:!aNULL:!MD5:!RC4"


def _doh_bind_lines(listen_address: str, doh: DohConfig, doh3: "Doh3Config | None" = None) -> list[str]:
    host = listen_address.rsplit(":", 1)[0]
    lines = [
        f'addDOHLocal("{host}:{doh.port}", {{{_lua_string(doh.cert_path)}}}, {{{_lua_string(doh.key_path)}}}, '
        f'{{{_lua_string(doh.path)}}}, {{',
        "  reusePort=true,",
        f'  minTLSVersion={_lua_string(doh.min_tls_version)},',
        f'  ciphers={_lua_string(doh.ciphers)},',
    ]
    if doh3 is not None and doh3.enabled:
        # Advertise the DoH3 upgrade to plain DoH (HTTP/1.1/2) clients via
        # the standard Alt-Svc response header (RFC 7838) -- ported
        # verbatim from V1's own real, production-proven
        # packaging/dnsdist.conf ("doh-altsvc" managed block) rather than
        # reinvented. Only emitted while DoH3 is actually enabled -- it
        # would otherwise point clients at a UDP port nothing is
        # listening on.
        alt_svc_value = f'h3=":{doh3.port}"; ma=86400'
        lines.append(f'  customResponseHeaders={{["alt-svc"]={_lua_string(alt_svc_value)}}},')
    lines += ["})", ""]
    return lines


@dataclass(frozen=True)
class Doh3Config:
    """DNS-over-HTTP/3 listener configuration -- same cert-reuse
    rationale as DotConfig/DohConfig, but QUIC-transported like DoQ
    (RFC 9114 over QUIC), so it shares DoqConfig's defensive
    capability-call wrapper: not every dnsdist build includes QUIC
    support (V1's own real, hands-on finding, documented in
    docs/dnsdist.md). dnsdist's real ``addDOH3Local`` takes plain
    cert/key path strings, not single-element tables (matching
    ``addDOQLocal``'s calling convention, verified against V1's own
    real ``packaging/dnsdist.conf`` syntax)."""

    enabled: bool
    port: int
    cert_path: str
    key_path: str


def _doh3_bind_lines(listen_address: str, doh3: Doh3Config) -> list[str]:
    host = listen_address.rsplit(":", 1)[0]
    return [
        _SAFE_CAPABILITY_CALL_HELPER,
        f'alderpointdnsv2SafeCapabilityCall("DoH3 (addDOH3Local)", addDOH3Local, "{host}:{doh3.port}", '
        f'{_lua_string(doh3.cert_path)}, {_lua_string(doh3.key_path)})',
        "",
    ]


@dataclass(frozen=True)
class DnscryptConfig:
    """DNSCrypt listener configuration -- the one encrypted transport that
    does NOT reuse the appliance's management TLS cert (DotConfig/
    DohConfig/DoqConfig/Doh3Config all do): DNSCrypt has its own real
    provider-identity (long-term Ed25519 signing key) and resolver-
    certificate (short-term X25519, re-issued periodically) model with no
    overlap with the TLS trust the other four share. ``cert_path``/
    ``key_path`` here point at files materialized fresh at every compile
    from protected secret material (``app/v2/dnscrypt_provisioning.py``
    generates the real bytes; see ``docs/v2/dnscrypt-transport-
    implemented.md`` for the full design and why generation always goes
    through the real dnsdist binary rather than a hand-rolled binary
    format). ``provider_name`` is the public, non-secret identity string
    clients query to discover this resolver's certificate (dnsdist's own
    real convention, matching V1's default: ``2.dnscrypt-cert.<domain>``).
    Shares DoQ/DoH3's defensive capability-call wrapper: not every distro
    build necessarily ships DNSCrypt support, even though the stock
    Debian archive build this appliance targets does (confirmed live,
    this continuation: ``dnscrypt`` listed among RC24's real installed
    ``dnsdist 1.9.16``'s ``Enabled features``) -- wrapped anyway, since
    being defensive here costs nothing and a future packaging change
    should never be able to crash-loop the live runtime."""

    enabled: bool
    port: int
    provider_name: str
    cert_path: str
    key_path: str


def _dnscrypt_bind_lines(listen_address: str, dnscrypt: DnscryptConfig) -> list[str]:
    host = listen_address.rsplit(":", 1)[0]
    return [
        _SAFE_CAPABILITY_CALL_HELPER,
        f'alderpointdnsv2SafeCapabilityCall("DNSCrypt (addDNSCryptBind)", addDNSCryptBind, '
        f'"{host}:{dnscrypt.port}", {_lua_string(dnscrypt.provider_name)}, '
        f'{_lua_string(dnscrypt.cert_path)}, {_lua_string(dnscrypt.key_path)})',
        "",
    ]


@dataclass(frozen=True)
class DoqConfig:
    """DNS-over-QUIC listener configuration -- same cert-reuse rationale
    as DotConfig/DohConfig. Unlike ``addTLSLocal``/``addDOHLocal``,
    dnsdist's real ``addDOQLocal`` takes plain cert/key path strings, not
    single-element tables (verified against V1's own real, production-
    proven ``packaging/dnsdist.conf`` syntax). ``congestion_control_algo``
    matches V1's own real value verbatim (``cubic``)."""

    enabled: bool
    port: int
    cert_path: str
    key_path: str
    congestion_control_algo: str = "cubic"


# QUIC support (DoQ/DoH3) is a newer, optional dnsdist build feature --
# not present in every distro's packaged dnsdist the way TLS/DoH are
# (V1's own real, hands-on finding, documented in docs/dnsdist.md: the
# stock Debian archive build lacks it entirely). Calling addDOQLocal/
# addDOH3Local on a build without it either raises a Lua error the
# generated config startup would otherwise crash on, or (older builds)
# the function may not exist at all -- wrapped the same defensive way
# V1's own packaging/dnsdist.conf already does (alderpointdnsSafeCapabilityCall),
# ported verbatim rather than reinvented.
_SAFE_CAPABILITY_CALL_HELPER = """\
local function alderpointdnsv2SafeCapabilityCall(label, fn, ...)
  if type(fn) ~= "function" then
    print("Alderpoint DNS V2: " .. label .. " is not supported by this dnsdist build; skipping.")
    return false
  end
  local ok, err = pcall(fn, ...)
  if not ok then
    print("Alderpoint DNS V2: " .. label .. " failed on this dnsdist build (" .. tostring(err) .. "); skipping.")
    return false
  end
  return true
end"""


def _doq_bind_lines(listen_address: str, doq: DoqConfig) -> list[str]:
    host = listen_address.rsplit(":", 1)[0]
    return [
        _SAFE_CAPABILITY_CALL_HELPER,
        f'alderpointdnsv2SafeCapabilityCall("DoQ (addDOQLocal)", addDOQLocal, "{host}:{doq.port}", '
        f'{_lua_string(doq.cert_path)}, {_lua_string(doq.key_path)}, {{',
        f'  congestionControlAlgo={_lua_string(doq.congestion_control_algo)}',
        "})",
        "",
    ]


def compile_multi_policy_dnsdist_config(
    listen_address: str,
    bindings: list[ClientPolicyBinding],
    max_cache_entries: int = DEFAULT_MAX_CACHE_ENTRIES,
    local_dns_records: list[tuple] | None = None,
    analytics_log_address: str | None = ANALYTICS_PROTOBUF_LOG_ADDRESS,
    discovery_ingress_address: str | None = DISCOVERY_INGRESS_ADDRESS,
    dot: DotConfig | None = None,
    doh: DohConfig | None = None,
    doq: DoqConfig | None = None,
    doh3: Doh3Config | None = None,
    dnscrypt: DnscryptConfig | None = None,
    bind_context_addresses: dict = None,
    doh_bind_context_addresses: dict = None,
) -> str:
    """Deterministic (§2H requires reproducible behavior regardless of
    query order): bindings are processed most-specific-network-first
    (same precedence rule already proven correct for domain routing in
    Blocker/P0-C), and every emitted rule set is internally sorted so two
    calls with the same input, regardless of list order, produce
    byte-identical output.
    """
    if not bindings:
        raise PolicyRuntimeError("at least one client policy binding is required")
    bind_context_addresses = bind_context_addresses or {}
    doh_bind_context_addresses = doh_bind_context_addresses or {}

    ordered = sorted(
        bindings,
        key=lambda b: (-b.network._net.prefixlen if hasattr(b.network, "_net") else 0, b.network.network_id),
    )

    lines = [
        "-- Generated by app/v2/dnsdist_policy_runtime.py -- V2 real per-effective-policy runtime.",
        "-- Do not hand-edit; regenerate from the effective policy compiler.",
        f'setLocal("{listen_address}")',
        "",
    ]

    if dot is not None and dot.enabled:
        lines += _dot_bind_lines(listen_address, dot)

    if doh is not None and doh.enabled:
        lines += _doh_bind_lines(listen_address, doh, doh3)

    if doq is not None and doq.enabled:
        lines += _doq_bind_lines(listen_address, doq)

    if doh3 is not None and doh3.enabled:
        lines += _doh3_bind_lines(listen_address, doh3)

    if dnscrypt is not None and dnscrypt.enabled:
        lines += _dnscrypt_bind_lines(listen_address, dnscrypt)

    if analytics_log_address:
        # Real query-log/analytics producer: logs the completed
        # question+answer (qname/qtype/rcode/client/protocol) for every
        # query. Both hooks are needed, registered here (before any
        # per-binding SpoofAction/SpoofCNAMEAction rule below, which
        # matters -- addAction rules are evaluated in registration
        # order and RemoteLogAction is non-terminal so it always runs
        # first, then evaluation continues to whichever terminal rule
        # applies): RemoteLogResponseAction alone never fires for a
        # terminally-spoofed query (blocked domains, SafeSearch, local
        # DNS records all answer entirely within the query-processing
        # stage and never reach a "response received from a backend"
        # event dnsdist can log a response for) -- verified empirically,
        # see app/v2/dnsdist_protobuf.py's module docstring. The
        # receiver correlates a query-time message with its eventual
        # response-time message by the real DNS transaction id (present
        # and identical in both, confirmed against real captured
        # traffic) and emits exactly one event per real query either
        # way.
        lines += [
            f'analytics_rl = newRemoteLogger("{analytics_log_address}")',
            "addAction(AllRule(), RemoteLogAction(analytics_rl))",
            "addResponseAction(AllRule(), RemoteLogResponseAction(analytics_rl))",
            "",
        ]

    if discovery_ingress_address:
        # Real client-discovery producer: mirrors every query datagram
        # to the dns-observer ingress (see DISCOVERY_INGRESS_ADDRESS's
        # own comment above for why this is safe to always emit).
        # addECS=false: dns-observer only needs the packet's real source
        # address (already the UDP peer address TeeAction preserves),
        # not an EDNS Client Subnet option.
        lines += [
            f'addAction(AllRule(), TeeAction("{discovery_ingress_address}", false))',
            "",
        ]

    # Local DNS records -- registered first (highest precedence, applies
    # to every network) so a LAN hostname always answers locally,
    # regardless of which policy pool the client would otherwise land in.
    local_dns_lines = _local_dns_rule_lines(local_dns_records or [])
    if local_dns_lines:
        lines.append("-- local DNS records (appliance-wide, highest precedence)")
        lines.extend(local_dns_lines)
        lines.append("")

    # Pools are deduplicated by cache_profile_id -- identical effective
    # policy always shares one pool/cache, never one per client.
    pool_bindings: dict[str, ClientPolicyBinding] = {}
    for b in ordered:
        pool_bindings.setdefault(b.cache_profile_id, b)

    for cache_profile_id, binding in pool_bindings.items():
        pool_name = f"profile_{cache_profile_id}"
        use_ecs = server_uses_client_subnet(binding.ecs_policy)
        ecs_directives = render_dnsdist_directives(binding.ecs_policy)
        if ecs_directives:
            lines.append(f"-- ECS policy for pool {pool_name}: {binding.ecs_policy.mode}")
            lines.extend(ecs_directives)
        lines.append(f"-- upstream servers for effective policy pool: {pool_name}")
        bind_addr = _route_via_bind(binding.upstream_endpoints, binding.upstream_transport, use_ecs, bind_context_addresses)
        doh_bind_addr = _route_doh_via_bind(binding.upstream_endpoints, binding.upstream_transport, use_ecs, doh_bind_context_addresses)
        if bind_addr:
            lines.append(
                "-- ordinary recursion: routed through the packaged V2 BIND "
                "recursive-cache tier (docs/v2/architecture-map.md locked hot path)"
            )
            lines.append(_bind_server_line(pool_name, bind_addr))
        elif doh_bind_addr:
            lines.append(
                "-- DoH recursion: routed through the packaged V2 BIND recursive-cache "
                "tier via a local DoH-egress transport (app/v2/doh_egress_gen.py)"
            )
            lines.append(_bind_server_line(pool_name, doh_bind_addr))
        else:
            for ep in binding.upstream_endpoints:
                lines.append(
                    _endpoint_server_line(
                        ep.address, pool_name, binding.upstream_transport,
                        ep.tls_hostname, getattr(ep, "doh_path", None), use_ecs,
                    )
                )
        for suffix, route_endpoints, route_transport, _strategy in binding.domain_routes:
            try:
                validated_suffix = validate_dns_name(suffix)
            except InvalidDnsNameError as exc:
                raise PolicyRuntimeError(f"invalid domain routing suffix {suffix!r}: {exc}") from exc
            route_pool = f"{pool_name}__route_{validated_suffix.replace('.', '_')}"
            route_bind_addr = _route_via_bind(route_endpoints, route_transport, use_ecs, bind_context_addresses)
            route_doh_bind_addr = _route_doh_via_bind(route_endpoints, route_transport, use_ecs, doh_bind_context_addresses)
            if route_bind_addr:
                lines.append(f"-- domain route {validated_suffix}: routed through the packaged V2 BIND recursive-cache tier")
                lines.append(_bind_server_line(route_pool, route_bind_addr))
            elif route_doh_bind_addr:
                lines.append(f"-- domain route {validated_suffix}: routed through the packaged V2 BIND recursive-cache tier via local DoH-egress")
                lines.append(_bind_server_line(route_pool, route_doh_bind_addr))
            else:
                for ep in route_endpoints:
                    lines.append(
                        _endpoint_server_line(
                            ep.address, route_pool, route_transport,
                            ep.tls_hostname, getattr(ep, "doh_path", None), use_ecs,
                        )
                    )
        lines.append("")

    lines.append("-- per-effective-policy-pool packet caches (never shared across pools)")
    for i, cache_profile_id in enumerate(pool_bindings):
        pool_name = f"profile_{cache_profile_id}"
        var = f"pc_{i}"
        lines.append(f'{var} = newPacketCache({max_cache_entries}, {{maxTTL={DEFAULT_MAX_CACHE_TTL_SECONDS}}})')
        lines.append(f'getPool({_lua_string(pool_name)}):setCache({var})')
    lines.append("")

    for binding in ordered:
        pool_name = f"profile_{binding.cache_profile_id}"
        net_matcher = f'NetmaskGroupRule({{{_lua_string(binding.network.cidr)}}})'
        lines.append(f"-- rules for network {binding.network.network_id} -> pool {pool_name}")

        # 1. SafeSearch rewrites -- terminal, highest precedence (an
        # explicit product-level "protect over allow-fast-path" choice
        # consistent with malware/security being checked first in
        # filtering_decision.py).
        if binding.safesearch_providers:
            rewrites = safesearch_mod.rewrites_for_providers(list(binding.safesearch_providers))
            for rw in sorted(rewrites, key=lambda r: r.domain):
                # safesearch.py's provider table is hardcoded, not
                # caller-supplied -- validated here anyway as defense in
                # depth, per §7A's "SafeSearch domains" coverage list.
                validated_domain = validate_dns_name(rw.domain)
                validated_target = validate_dns_name(rw.cname_target)
                matcher = f'AndRule({{{net_matcher}, QNameRule({_lua_string(validated_domain + ".")})}})'
                lines.append(
                    f'addAction({matcher}, SpoofCNAMEAction({_lua_string(validated_target + ".")}))'
                )

        # 2. Block rules -- terminal.
        for domain in sorted(binding.blocked_domains):
            if domain in binding.allowed_domains:
                continue  # explicit allow always overrides a block (P0-A precedence)
            response = binding.blocked_domains[domain]
            try:
                trigger = validate_dns_name(domain) + "."
            except InvalidDnsNameError as exc:
                raise PolicyRuntimeError(f"invalid blocked domain {domain!r}: {exc}") from exc
            matcher = f'AndRule({{{net_matcher}, SuffixMatchNodeRule({{{_lua_string(trigger)}}})}})'
            lines.append(f"addAction({matcher}, {_refused_or_spoof_action(response)})")

        # 3. Domain-specific routing -- terminal PoolAction, most-specific
        # suffix first (same precedence fix as Blocker/P0-C).
        routes_sorted = sorted(binding.domain_routes, key=lambda r: (-len(r[0].strip(".")), r[0]))
        for suffix, _eps, _transport, _strategy in routes_sorted:
            try:
                validated_suffix = validate_dns_name(suffix)
            except InvalidDnsNameError as exc:
                raise PolicyRuntimeError(f"invalid domain routing suffix {suffix!r}: {exc}") from exc
            route_pool = f"{pool_name}__route_{validated_suffix.replace('.', '_')}"
            trigger = validated_suffix + "."
            matcher = f'AndRule({{{net_matcher}, SuffixMatchNodeRule({{{_lua_string(trigger)}}})}})'
            lines.append(f'addAction({matcher}, PoolAction({_lua_string(route_pool)}))')

        # 4. Catch-all -> this binding's policy pool.
        lines.append(f'addAction({net_matcher}, PoolAction({_lua_string(pool_name)}))')
        lines.append("")

    return "\n".join(lines) + "\n"
