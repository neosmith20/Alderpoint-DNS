"""V2 management-plane -> real compiled DNS runtime (Workstream 4B §18,
§46; beta-rescue pass). The missing link between the HTTPS management API
and the already-proven-correct policy runtime compiler
(``app/v2/dnsdist_policy_runtime.py``): reads real control.db state
(networks, managed clients/groups/schedules, the global policy layer,
upstream/fallback profiles, domain-routing rules, service-blocking
rulesets), builds one ``ClientPolicyBinding`` per configured network, one
per real client IP identifier (resolving that client's full
global -> network -> group(s) -> client -> active-schedule inheritance
stack through the exact same ``policy_compiler.compile_effective_policy``
the management-plane Explain endpoint uses), plus a default/global
binding, and stages -> validates (real ``dnsdist --check-config``) ->
promotes the result.

Scope, stated plainly: ``safesearch_mode`` maps to "all supported
providers" when not "off" -- a real, documented simplification; the model
does not yet support per-provider selection, though the moderate/strict
*level* is real and provider-audited (see ``app/v2/safesearch.py``).
``filtering_profile_id``, the three service-blocking-ruleset-shaped
fields (``parental_policy_id``, ``security_policy_id``,
``service_blocking_ruleset_id``), and ``domain_routing_ruleset_id`` all
now reach real per-binding dnsdist rules -- see
``docs/v2/management-plane.md`` "Known limitations" for what remains
genuinely unimplemented (product-parity gaps like AdGuard Home/Pi-hole
import and a native Software Updates surface, not runtime-wiring gaps).

Report success only after real promotion succeeds (§18's "do not report
success before runtime promotion succeeds" requirement) -- callers must
treat any exception from ``recompile_and_promote`` as "the change was
persisted to control.db but NOT yet live," matching the explicit
requirement that a known-good runtime remains active on failure (this
module never touches the live path until validation passes).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.v2 import bind_gen
from app.v2 import doh_egress_gen
from app.v2 import policy_store as store
from app.v2 import safesearch
from app.v2.blocking_response import BlockingResponse, InvalidBlockingResponseError
from app.v2.dnsdist_gen import dnsdist_check_config_validator
from app.v2.dnsdist_policy_runtime import (
    ClientPolicyBinding,
    Doh3Config,
    DnscryptConfig,
    DohConfig,
    DoqConfig,
    DotConfig,
    PolicyRuntimeError,
    compile_multi_policy_dnsdist_config,
)
from app.v2.ecs_policy import EcsPolicy, server_uses_client_subnet
from app.v2.network_match import NetworkScope
from app.v2.policy_compiler import compile_cache_profile, compile_effective_policy
from app.v2.policy_model import PolicyLayer
from app.v2.runtime_staging import Artifact, PromotionResult, stage_validate_promote, stage_validate_promote_all

_ECS_MODE_MAP = {"disabled": "disabled", "preserve": "preserve", "custom": "custom"}
_DEFAULT_NETWORK_ID = "__default__"

# client_identifiers.kind values that name a real IP/CIDR the dnsdist
# runtime can match against (see app/v2/control_db.py's schema). "clientid"
# (DHCP client-id/MAC) has no IP-based runtime matcher -- Alderpoint DNS is
# DNS-only and deliberately never gains DHCP integration (see AGENTS.md/
# project scope), so a client identified only by clientid cannot be
# materialized into a real dnsdist binding; such clients keep whatever
# policy their matched network/group/global layers already give them, same
# as an unrecognized source address always has.
_IP_IDENTIFIER_SUFFIX = {"ipv4": "/32", "ipv6": "/128", "ipv4_cidr": "", "ipv6_cidr": ""}


class RuntimeCompileError(RuntimeError):
    pass


def _domains_for_ruleset(conn: sqlite3.Connection, ruleset_id: str) -> list[str]:
    rows = conn.execute(
        """
        SELECT sdom.domain
        FROM service_blocking_ruleset_members m
        JOIN service_definitions sd ON sd.id = m.service_row_id
        JOIN service_domains sdom ON sdom.service_row_id = sd.id
        JOIN service_blocking_rulesets r ON r.id = m.ruleset_row_id
        WHERE r.ruleset_id = ?
        """,
        (ruleset_id,),
    ).fetchall()
    return [row[0] for row in rows]


def _blocking_response_for_policy(policy) -> BlockingResponse:
    """Real defect closed: this previously constructed
    ``BlockingResponse(mode=policy.blocking_response_mode)`` alone, never
    passing the effective ``custom_ipv4``/``custom_ipv6`` fields through
    -- so any policy resolving to ``custom_ip`` mode crashed the entire
    compile the instant BlockingResponse's own constructor (correctly)
    rejected a custom_ip response with no address, regardless of whether
    a real address had been configured. "" is PolicyLayer's "not
    configured" sentinel (see policy_model.py); translated to None here
    to match BlockingResponse's own convention rather than passing "" in
    and getting an ipaddress-parse error for an address nobody set.
    """
    mode = policy.blocking_response_mode
    return BlockingResponse(
        mode=mode,
        custom_ipv4=(policy.custom_ipv4 or None) if mode == "custom_ip" else None,
        custom_ipv6=(policy.custom_ipv6 or None) if mode == "custom_ip" else None,
    )


def _blocked_domains_for_policy(conn: sqlite3.Connection, policy) -> dict:
    response = _blocking_response_for_policy(policy)
    blocked: dict[str, BlockingResponse] = {}
    # filtering_profile_id joins the same three ruleset-shaped fields
    # (real defect closed: this field's docstring previously read "not yet
    # mapped" -- see docs/v2/management-plane.md "Known limitations",
    # superseded by this pass). All four dimensions already share one real
    # domain-membership mechanism (policy_store.create_service_ruleset /
    # _domains_for_ruleset above); a ruleset_id with no matching row
    # (including every field's own documented "none"/"default" no-op
    # value) simply contributes zero domains, so leaving an unconfigured
    # field at its default remains a true no-op.
    for ruleset_id in filter(
        None,
        (
            policy.filtering_profile_id,
            policy.parental_policy_id,
            policy.security_policy_id,
            policy.service_blocking_ruleset_id,
        ),
    ):
        for domain in _domains_for_ruleset(conn, ruleset_id):
            blocked[domain] = response
    return blocked


def _domain_routes_for_policy(conn: sqlite3.Connection, policy) -> tuple:
    """Materializes ``policy.domain_routing_ruleset_id`` into real
    ``ClientPolicyBinding.domain_routes`` entries. Real defect closed:
    prior to this pass no caller ever populated this field at all, so
    stored domain-routing rules never reached the compiled runtime
    regardless of how they were configured (owner-reported P0).
    """
    ruleset_id = policy.domain_routing_ruleset_id
    if not ruleset_id or ruleset_id == "none":
        return ()
    routes = []
    for match_kind, domain, upstream_profile_id in store.list_domain_routing_rules(conn, ruleset_id):
        profile = store.load_upstream_profile(conn, upstream_profile_id)
        if profile is None:
            continue  # dangling reference: never silently route into nothing
        routes.append((domain, profile.endpoints, profile.transport, profile.strategy, match_kind))
    return tuple(routes)


def _safesearch_providers_for_policy(policy) -> tuple[str, ...]:
    if policy.safesearch_mode and policy.safesearch_mode != "off":
        return safesearch.SUPPORTED_PROVIDERS
    return ()


def _safesearch_level_for_policy(policy) -> str:
    # Real defect closed: "moderate" and "strict" previously produced
    # byte-identical runtime rewrites because nothing downstream of this
    # policy field ever distinguished them (see safesearch.py's own
    # per-provider audit of which providers can genuinely differ).
    return policy.safesearch_mode if policy.safesearch_mode in ("moderate", "strict") else "strict"


def _default_upstream_endpoints() -> tuple:
    from app.v2.policy_store import UpstreamEndpointRecord

    return (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None), UpstreamEndpointRecord("9.9.9.9:53", None, 0, 1, None))


def _upstream_for_policy(conn: sqlite3.Connection, policy) -> tuple[tuple, str, str]:
    if policy.upstream_profile_id:
        profile = store.load_upstream_profile(conn, policy.upstream_profile_id)
        if profile is not None:
            if profile.strategy not in ("ordered", "failover", "load_balanced"):
                # Defensive: create_upstream_profile() already rejects
                # unsupported strategies at write time, but a stale row
                # from before that validation existed must never be
                # silently ignored at compile time either -- report it,
                # don't pretend it compiled correctly.
                raise RuntimeCompileError(
                    f"upstream profile {policy.upstream_profile_id!r} has unsupported "
                    f"strategy {profile.strategy!r}"
                )
            return profile.endpoints, profile.transport, profile.strategy
    return _default_upstream_endpoints(), "plain", "ordered"


def _ecs_for_policy(policy) -> EcsPolicy:
    mode = _ECS_MODE_MAP.get(policy.ecs_mode, "disabled")
    return EcsPolicy(mode=mode)


def _apply_fallback(
    conn: sqlite3.Connection, policy, endpoints: tuple, transport: str, strategy: str
) -> tuple[tuple, str]:
    """Real defect closed (beta-rescue pass): fallback_strategy was
    stored but nothing ever invoked app/v2/fallback_dns.py's real
    decision logic or added a fallback server to the compiled pool at
    all -- a fully disconnected control. Wires it in for real:

    - "on_failure": fallback endpoints are appended to the SAME pool at
      strictly lower priority than every primary endpoint, and the
      pool's server-selection policy is forced to "ordered"
      (firstAvailable) regardless of the primary profile's own
      configured preference -- the entire point of configuring a
      fallback is defined failover order, and dnsdist's own live health
      checks (not a separate Python-side health loop) are what actually
      decide, at real query time, whether a primary endpoint is down.
    - "always_parallel": fallback endpoints are appended too, but the
      pool keeps its normal (primary-profile-configured) selection
      policy -- both primary and fallback are equally eligible at all
      times, matching fallback_dns.py's own documented "always eligible"
      semantics, genuinely distinct from "on_failure"'s strict ordering.

    A single dnsdist pool speaks exactly one transport to every server
    in it (ClientPolicyBinding.upstream_transport is one value, not
    per-endpoint) -- a real, documented, narrow limitation, not a
    silent bug: a fallback profile using a DIFFERENT transport than the
    primary is not merged into this pool. This is deliberately the same
    conservative default app/v2/fallback_dns.py's own
    evaluate_fallback() already enforces (an encrypted-primary ->
    plaintext-fallback downgrade requires an explicit administrator
    allow_privacy_downgrade=True this pass exposes no control for yet);
    evaluate_fallback() is called below as the real, single decision
    point for whether a fallback merge is permitted, rather than
    duplicating its logic ad hoc.
    """
    if policy.fallback_strategy == "none" or not policy.fallback_upstream_profile_id or policy.fallback_upstream_profile_id == "none":
        return endpoints, strategy
    fb_profile = store.load_upstream_profile(conn, policy.fallback_upstream_profile_id)
    if fb_profile is None:
        return endpoints, strategy  # dangling reference: never silently route into nothing

    from app.v2.fallback_dns import PrimaryHealth, evaluate_fallback

    decision = evaluate_fallback(
        fallback_strategy=policy.fallback_strategy,
        # Compile-time gate only: real per-query health is dnsdist's own
        # job once the pool is compiled (firstAvailable's live health
        # checks). Primary is deliberately reported "down" here purely to
        # reach evaluate_fallback's transport-downgrade safety check --
        # the one thing this pure decision function can usefully tell us
        # statically, at compile time.
        primary_health=PrimaryHealth(consecutive_failures=1, failure_threshold=1),
        primary_transport=transport,
        fallback_transport=fb_profile.transport,
    )
    if not decision.use_fallback or fb_profile.transport != transport:
        return endpoints, strategy

    max_priority = max((ep.priority for ep in endpoints), default=0)
    fallback_endpoints = tuple(
        type(ep)(ep.address, ep.tls_hostname, max_priority + 1 + i, ep.weight, ep.secret_ref, getattr(ep, "doh_path", None))
        for i, ep in enumerate(fb_profile.endpoints)
    )
    merged = endpoints + fallback_endpoints
    new_strategy = "ordered" if policy.fallback_strategy == "on_failure" else strategy
    return merged, new_strategy


def _binding_for_scope(conn: sqlite3.Connection, network: NetworkScope, policy) -> ClientPolicyBinding:
    cache_profile = compile_cache_profile(policy)
    endpoints, transport, strategy = _upstream_for_policy(conn, policy)
    endpoints, strategy = _apply_fallback(conn, policy, endpoints, transport, strategy)
    return ClientPolicyBinding(
        network=network,
        cache_profile_id=cache_profile.profile_id,
        safesearch_providers=_safesearch_providers_for_policy(policy),
        safesearch_level=_safesearch_level_for_policy(policy),
        blocked_domains=_blocked_domains_for_policy(conn, policy),
        domain_routes=_domain_routes_for_policy(conn, policy),
        upstream_endpoints=endpoints,
        upstream_transport=transport,
        upstream_strategy=strategy,
        ecs_policy=_ecs_for_policy(policy),
    )


def _active_schedule(conn: sqlite3.Connection, now: datetime) -> tuple[Optional[str], Optional[PolicyLayer]]:
    """The single active-schedule layer for this compile pass, resolved
    once and applied uniformly to every binding below -- matching
    ``policy_service.compile_effective_policy_from_store``'s own
    per-client resolution exactly, so a schedule that Explain reports as
    active is the same schedule the compiled runtime actually applies.
    Deterministic first-match (schedules table has no declared priority),
    the same tie-break policy_service.py already documents.
    """
    for (schedule_id,) in conn.execute("SELECT schedule_id FROM policy_schedules").fetchall():
        schedule = store.load_schedule(conn, schedule_id)
        if schedule is not None and schedule.is_active(now):
            return schedule_id, store.load_policy_layer(conn, "schedule", schedule_id)
    return None, None


def _managed_client_scopes(conn: sqlite3.Connection) -> list[tuple[int, NetworkScope]]:
    """One ``NetworkScope`` per real IP/CIDR identifier of every enabled
    managed client -- always a /32 or /128 (or the identifier's own CIDR,
    for an ``ipv4_cidr``/``ipv6_cidr`` identifier), so it is always at
    least as specific as any configured network and therefore always wins
    ``network_match.CompiledNetworkTable``'s most-specific-first
    precedence over a plain network-level binding, giving real
    "client overrides network" behavior with no change to the matching
    algorithm itself. ``clientid``-kind identifiers (no real IP) are
    skipped -- see ``_IP_IDENTIFIER_SUFFIX``'s docstring.
    """
    scopes: list[tuple[int, NetworkScope]] = []
    rows = conn.execute(
        """
        SELECT c.id, ci.kind, ci.value
        FROM clients c
        JOIN client_identifiers ci ON ci.client_id = c.id
        WHERE c.enabled = 1
        ORDER BY c.id ASC, ci.kind ASC, ci.value ASC
        """
    ).fetchall()
    for client_id, kind, value in rows:
        suffix = _IP_IDENTIFIER_SUFFIX.get(kind)
        if suffix is None:
            continue
        cidr = value if "/" in value else f"{value}{suffix}"
        network_id = f"client:{client_id}:{value}"
        try:
            scope = NetworkScope.create(network_id, cidr, policy_ref=network_id)
        except Exception:
            continue  # invalid/corrupt identifier: never let one bad row break the whole compile
        scopes.append((client_id, scope))
    return scopes


def build_bindings(conn: sqlite3.Connection, now: Optional[datetime] = None) -> list[ClientPolicyBinding]:
    """The real, complete effective-policy -> runtime-binding materialization
    (owner-reported P0 fixed by this pass): one binding per configured
    network (network layer merged over global), a catch-all default
    binding (0.0.0.0/0, global layer alone), AND one binding per real IP
    identifier of every enabled managed client -- resolving that client's
    full inheritance stack (global -> matched network -> group(s) ->
    client -> active schedule override) through the exact same
    ``policy_compiler.compile_effective_policy`` the management-plane
    Explain endpoint uses (``app/v2/policy_service.py``), so there is
    never a second, competing definition of "effective policy" between
    what the UI explains and what the DNS runtime enforces. Real control
    state, no synthetic/test-only shortcuts.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    global_layer = store.load_policy_layer(conn, "global", "singleton")
    network_table = store.load_network_table(conn)
    schedule_id, schedule_layer = _active_schedule(conn, now)

    bindings: list[ClientPolicyBinding] = []
    for network_id, cidr in conn.execute("SELECT network_id, cidr FROM policy_networks").fetchall():
        scope = NetworkScope.create(network_id, cidr, policy_ref=network_id)
        network_layer = store.load_policy_layer(conn, "network", network_id)
        policy = compile_effective_policy(
            global_layer=global_layer,
            network_layer=network_layer,
            network_source=network_id,
            schedule_layer=schedule_layer,
            schedule_id=schedule_id,
            schedule_active=schedule_id is not None,
        )
        bindings.append(_binding_for_scope(conn, scope, policy))

    for client_id, client_scope in _managed_client_scopes(conn):
        network_layer = None
        network_source = None
        match = network_table.match(str(client_scope._net.network_address))
        if match is not None:
            network_layer = store.load_policy_layer(conn, "network", match.network_id)
            network_source = match.network_id
        groups = store.load_groups_for_client(conn, client_id)
        client_layer = store.load_policy_layer(conn, "client", str(client_id))
        policy = compile_effective_policy(
            global_layer=global_layer,
            network_layer=network_layer,
            network_source=network_source,
            groups=groups,
            client_layer=client_layer,
            schedule_layer=schedule_layer,
            schedule_id=schedule_id,
            schedule_active=schedule_id is not None,
        )
        bindings.append(_binding_for_scope(conn, client_scope, policy))

    default_scope = NetworkScope.create(_DEFAULT_NETWORK_ID, "0.0.0.0/0", policy_ref=_DEFAULT_NETWORK_ID)
    default_policy = compile_effective_policy(
        global_layer=global_layer,
        schedule_layer=schedule_layer,
        schedule_id=schedule_id,
        schedule_active=schedule_id is not None,
    )
    bindings.append(_binding_for_scope(conn, default_scope, default_policy))
    return bindings


@dataclass(frozen=True)
class RuntimeCompileResult:
    promoted: bool
    validation_output: str
    binding_count: int
    ptr_records_skipped: int = 0


def recompile_and_promote(
    conn: sqlite3.Connection,
    staging_dir: Path,
    live_dnsdist_conf_path: Path,
    # Real "now" this compile pass resolves active-schedule overrides
    # against (see ``_active_schedule``). Omitted (None) uses real wall-
    # clock time, exactly matching every real caller's expectation and
    # ``policy_service.explain_policy_for_client``'s own default; tests
    # pass a fixed value so schedule-boundary behavior is deterministic
    # rather than depending on when the suite happens to run.
    now: "datetime | None" = None,
    # Defense-in-depth default only -- every real caller (webapp.py,
    # replication_v2.py, scripts/v2/alderpointdns_v2_ctl.py) explicitly
    # passes the appliance's real configured listener. A loopback-only
    # default here previously meant any caller that forgot to pass
    # listen_address would silently cut dnsdist off from real LAN
    # clients with no error (found live during RC1 acceptance testing --
    # webapp.py's own live policy-mutation path was exactly that missing
    # caller). "0.0.0.0:53" matches what every real install actually
    # needs, so an omitted argument now fails toward "still reachable"
    # rather than "silently loopback-only."
    listen_address: str = "0.0.0.0:53",
    dnsdist_binary: str = "dnsdist",
    # Real defect this closes (docs/v2/encrypted-transport-parity-gap.md):
    # DoT was entirely absent from V2's real config generation. Omitted
    # (``None``) by default -- callers that don't yet pass it (migration.py,
    # replication_v2.py as of this pass) simply compile without a DoT
    # listener, same as before this change; wiring every caller is a
    # separate, incremental step from adding the capability itself.
    dot: DotConfig | None = None,
    doh: DohConfig | None = None,
    doq: DoqConfig | None = None,
    doh3: Doh3Config | None = None,
    dnscrypt: DnscryptConfig | None = None,
    # BIND architecture correction (Gate #3): when the caller supplies a
    # real live BIND config path, this becomes the single code path from
    # "control.db changed" to "coherently compiled+validated+promoted
    # dnsdist config AND BIND config" -- see
    # app/v2/runtime_staging.py's stage_validate_promote_all. Omitted
    # (None, the default) preserves the exact prior behavior (dnsdist.conf
    # only) for any caller not yet updated to pass it -- no regression.
    live_bind_conf_path: "Path | None" = None,
    live_bind_log_root: "Path | None" = None,
    rpz_zone_path: "Path | None" = None,
    named_checkconf_binary: str = "named-checkconf",
    live_doh_egress_dir: "Path | None" = None,
    # Real defect found live during Gate #3 acceptance testing (failure-
    # domain proof): omitting this made every BIND context's own
    # `directory` (its writable working dir for stats/journal files)
    # default to the COMPILED artifact root -- which
    # alderpointdns-v2-bind@.service's own ReadOnlyPaths=.../compiled
    # deliberately makes read-only, so named failed to (re)start with
    # "directory ... is not writable" the moment it needed to actually
    # write there (masked on first start in some cases; caught for real
    # on a subsequent restart). Real installs must always pass the real
    # writable state root (STATE_DIR / "bind").
    live_bind_state_root: "Path | None" = None,
) -> RuntimeCompileResult:
    """The real, single code path from "control.db changed" to "compiled
    dnsdist (and, when wired, BIND) config on disk validated by the real
    binaries." Raises on any failure (invalid domain data, dnsdist/BIND
    rejects the config, ...) -- the live path is never touched until
    validation succeeds, so a known-good runtime always remains active on
    failure, per §18.
    """
    try:
        bindings = build_bindings(conn, now=now)
        local_dns_records = store.load_local_dns_records(conn)
        # compile_multi_policy_dnsdist_config()'s local-DNS compiler
        # silently skips PTR rows (needs a different matcher than the
        # forward record it's paired with -- not implemented yet);
        # counted here, not inside the compiler, so a caller can decide
        # whether to surface it rather than it vanishing with no signal.
        ptr_records_skipped = sum(1 for r in local_dns_records if r[1] == "PTR")

        # Multi-context BIND (Gate #3 acceptance closure): every distinct
        # plain OR DoT, non-ECS upstream selection actually in use
        # anywhere in this compile (the appliance-wide default binding,
        # any other binding's own upstream selection, any domain-routing
        # rule's endpoints) gets its own real BIND context/cache -- not
        # just the single default selection. The default binding's
        # selection is ordered first so it keeps the well-known default
        # ports/back-compat address (app/v2/bind_gen.BIND_BACKEND_ADDRESS)
        # whenever it's present, matching every prior RC's behavior for
        # the common case; the rest are ordered deterministically
        # (sorted) so the same control.db state always allocates the
        # same ports regardless of dict/iteration order (§2H). ECS pools
        # (BIND has no EDNS Client Subnet support at all -- an explicit,
        # documented, narrow architecture exception, see
        # dnsdist_policy_runtime._route_via_bind's own docstring) and DoH
        # pools (BIND has no DoH-forwarder capability at all) never
        # contribute a selection here; they keep going direct.
        def _bind_eligible_selections(binding) -> list[bind_gen.UpstreamSelection]:
            sels = []
            if binding.upstream_transport in ("plain", "dot") and not server_uses_client_subnet(binding.ecs_policy):
                hostnames = {ep.tls_hostname for ep in binding.upstream_endpoints}
                if binding.upstream_transport == "plain" or (len(hostnames) == 1 and None not in hostnames):
                    sels.append(bind_gen.UpstreamSelection(
                        forwarders=tuple(sorted(ep.address for ep in binding.upstream_endpoints)),
                        tls_hostname=(hostnames.pop() if binding.upstream_transport == "dot" else None),
                    ))
            for _suffix, route_endpoints, route_transport, _strategy, _match_kind in binding.domain_routes:
                if route_transport in ("plain", "dot") and not server_uses_client_subnet(binding.ecs_policy):
                    route_hostnames = {ep.tls_hostname for ep in route_endpoints}
                    if route_transport == "plain" or (len(route_hostnames) == 1 and None not in route_hostnames):
                        sels.append(bind_gen.UpstreamSelection(
                            forwarders=tuple(sorted(ep.address for ep in route_endpoints)),
                            tls_hostname=(route_hostnames.pop() if route_transport == "dot" else None),
                        ))
            return sels

        default_binding = next((b for b in bindings if b.network.network_id == _DEFAULT_NETWORK_ID), None)
        ordered_selections: list[bind_gen.UpstreamSelection] = []
        seen: set = set()
        if live_bind_conf_path is not None:
            if default_binding is not None:
                for sel in _bind_eligible_selections(default_binding):
                    if sel.forwarders and sel not in seen:
                        ordered_selections.append(sel)
                        seen.add(sel)
            for b in sorted(bindings, key=lambda b: b.network.network_id):
                for sel in sorted(_bind_eligible_selections(b), key=lambda s: (s.forwarders, s.tls_hostname or "")):
                    if sel.forwarders and sel not in seen:
                        ordered_selections.append(sel)
                        seen.add(sel)

        # DoH-through-BIND (Gate #3 acceptance closure #4): every distinct
        # DoH selection gets a local egress process (app/v2/doh_egress_gen.py)
        # plus its own BIND context whose forwarders point at that egress
        # process -- only attempted when the caller also wires
        # live_doh_egress_dir (backward-compatible: omitted means DoH
        # pools simply keep going direct, exactly as before this pass).
        def _doh_selections(binding) -> list[tuple[str, str, str]]:
            sels = []
            if binding.upstream_transport == "doh" and not server_uses_client_subnet(binding.ecs_policy):
                for ep in binding.upstream_endpoints:
                    if ep.tls_hostname and getattr(ep, "doh_path", None):
                        sels.append((ep.address, ep.doh_path, ep.tls_hostname))
            for _suffix, route_endpoints, route_transport, _strategy, _match_kind in binding.domain_routes:
                if route_transport == "doh" and not server_uses_client_subnet(binding.ecs_policy):
                    for ep in route_endpoints:
                        if ep.tls_hostname and getattr(ep, "doh_path", None):
                            sels.append((ep.address, ep.doh_path, ep.tls_hostname))
            return sels

        doh_egress_contexts = []
        doh_bind_context_addresses: dict = {}
        if live_bind_conf_path is not None and live_doh_egress_dir is not None:
            ordered_doh: list[tuple[str, str, str]] = []
            seen_doh: set = set()
            for b in sorted(bindings, key=lambda b: b.network.network_id):
                for sel in sorted(_doh_selections(b)):
                    if sel not in seen_doh:
                        ordered_doh.append(sel)
                        seen_doh.add(sel)
            doh_egress_contexts = doh_egress_gen.allocate_doh_egress_contexts(ordered_doh)
            # Each egress context needs its own BIND context too, appended
            # after the plain/DoT ones within the same MAX_BIND_CONTEXTS
            # bound (a DoH selection beyond that bound keeps going direct,
            # same conservative rule as everything else).
            doh_egress_backends = [bind_gen.UpstreamSelection(forwarders=(doh_egress_gen.egress_backend_address(ec),)) for ec in doh_egress_contexts]
            ordered_selections = ordered_selections + doh_egress_backends

        bind_contexts = bind_gen.allocate_bind_contexts(ordered_selections)
        bind_context_addresses = {
            (frozenset(ctx.forwarders), ctx.tls_hostname): bind_gen.context_backend_address(ctx)
            for ctx in bind_contexts
        }
        if doh_egress_contexts:
            plain_bind_context_count = len(bind_contexts) - len(doh_egress_contexts)
            for i, ec in enumerate(doh_egress_contexts):
                bctx = bind_contexts[plain_bind_context_count + i] if plain_bind_context_count + i < len(bind_contexts) else None
                if bctx is not None:
                    doh_bind_context_addresses[frozenset({(ec.upstream_address, ec.doh_path, ec.tls_hostname)})] = bind_gen.context_backend_address(bctx)

        config_text = compile_multi_policy_dnsdist_config(
            listen_address, bindings, local_dns_records=local_dns_records,
            dot=dot, doh=doh, doq=doq, doh3=doh3, dnscrypt=dnscrypt,
            bind_context_addresses=bind_context_addresses,
            doh_bind_context_addresses=doh_bind_context_addresses,
        )
    except PolicyRuntimeError as exc:
        raise RuntimeCompileError(f"policy runtime compile failed: {exc}") from exc
    except InvalidBlockingResponseError as exc:
        # e.g. an effective policy resolved to blocking_response_mode=
        # "custom_ip" with no custom_ipv4/custom_ipv6 configured at any
        # layer -- a real, reportable configuration error, not an
        # unhandled crash. §18's "known-good runtime remains active on
        # failure" applies here exactly like any other compile failure.
        raise RuntimeCompileError(f"blocking response configuration invalid: {exc}") from exc

    staging_dir.mkdir(parents=True, exist_ok=True)
    try:
        if live_bind_conf_path is not None and bind_contexts:
            if rpz_zone_path is None:
                raise RuntimeCompileError(
                    "live_bind_conf_path was given but rpz_zone_path was not -- "
                    "BIND's named.conf must reference an already-promoted RPZ zone file"
                )
            bind_root = Path(live_bind_conf_path)
            log_root = Path(live_bind_log_root) if live_bind_log_root is not None else bind_root
            state_root = Path(live_bind_state_root) if live_bind_state_root is not None else bind_root
            artifacts = []
            if doh_egress_contexts and live_doh_egress_dir is not None:
                egress_root = Path(live_doh_egress_dir)
                for ec in doh_egress_contexts:
                    artifacts.append(
                        Artifact(
                            name=f"{ec.name}/dnsdist.conf",
                            content=doh_egress_gen.render_egress_config(ec),
                            live_path=egress_root / ec.name / "dnsdist.conf",
                            validator=dnsdist_check_config_validator(dnsdist_binary),
                        )
                    )
            for ctx in bind_contexts:
                ctx_state_dir = state_root / ctx.name
                ctx_log_path = log_root / ctx.name / "named.log"
                ctx_state_dir.mkdir(parents=True, exist_ok=True)
                ctx_log_path.parent.mkdir(parents=True, exist_ok=True)
                ctx_conf_text = bind_gen.render_named_conf_for_context(
                    ctx, str(rpz_zone_path), directory=str(ctx_state_dir), log_path=str(ctx_log_path),
                )
                artifacts.append(
                    Artifact(
                        name=f"{ctx.name}/named.conf", content=ctx_conf_text,
                        live_path=bind_root / ctx.name / "named.conf",
                        validator=bind_gen.named_checkconf_validator(named_checkconf_binary),
                    )
                )
            artifacts.append(
                Artifact(
                    name="dnsdist.conf", content=config_text, live_path=live_dnsdist_conf_path,
                    validator=dnsdist_check_config_validator(dnsdist_binary),
                )
            )
            results = stage_validate_promote_all(staging_dir, artifacts)
            result = results[-1]
        else:
            result: PromotionResult = stage_validate_promote(
                staging_root=staging_dir,
                name="dnsdist.conf",
                content=config_text,
                live_path=live_dnsdist_conf_path,
                validator=dnsdist_check_config_validator(dnsdist_binary),
            )
    except Exception as exc:  # ValidationFailedError, StagingError
        raise RuntimeCompileError(f"runtime validation/promotion failed: {exc}") from exc

    return RuntimeCompileResult(
        promoted=result.promoted, validation_output=result.validation.output, binding_count=len(bindings),
        ptr_records_skipped=ptr_records_skipped,
    )
