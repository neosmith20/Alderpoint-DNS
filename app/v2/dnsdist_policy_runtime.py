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


def compile_multi_policy_dnsdist_config(
    listen_address: str,
    bindings: list[ClientPolicyBinding],
    max_cache_entries: int = DEFAULT_MAX_CACHE_ENTRIES,
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
