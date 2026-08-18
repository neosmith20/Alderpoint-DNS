"""V2 management-plane -> real compiled DNS runtime (Workstream 4B §18,
§46). The missing link between the HTTPS management API and the already-
proven-correct policy runtime compiler
(``app/v2/dnsdist_policy_runtime.py``): reads real control.db state
(networks, the global policy layer, upstream profiles, service-blocking
rulesets), builds one ``ClientPolicyBinding`` per configured network plus
a default/global binding, and stages -> validates (real ``dnsdist
--check-config``) -> promotes the result.

Scope, stated plainly: this maps ``safesearch_mode`` (all supported
providers when not "off" -- a real, documented simplification; the model
does not yet support per-provider selection) and the three
service-blocking-ruleset-shaped fields (``parental_policy_id``,
``security_policy_id``, ``service_blocking_ruleset_id`` -- all three
already share one real domain-membership mechanism,
``policy_store.create_service_ruleset``/``is_domain_service_blocked``, see
``app/v2/filtering_decision.py``'s own docstring) into real per-network
dnsdist rules. ``filtering_profile_id`` (ordinary allow/block lists, not
yet wired to a distinct storage/CRUD surface as of this pass) is not yet
mapped -- see ``docs/v2/management-plane.md`` "Known limitations."

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
from pathlib import Path

from app.v2 import policy_store as store
from app.v2 import safesearch
from app.v2.blocking_response import BlockingResponse
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
from app.v2.ecs_policy import EcsPolicy
from app.v2.network_match import NetworkScope
from app.v2.policy_compiler import compile_cache_profile, compile_effective_policy
from app.v2.policy_model import PolicyLayer
from app.v2.runtime_staging import PromotionResult, stage_validate_promote

_ECS_MODE_MAP = {"disabled": "disabled", "preserve": "preserve", "custom": "custom"}
_DEFAULT_NETWORK_ID = "__default__"


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


def _blocked_domains_for_policy(conn: sqlite3.Connection, policy) -> dict:
    response = BlockingResponse(mode=policy.blocking_response_mode)
    blocked: dict[str, BlockingResponse] = {}
    for ruleset_id in filter(
        None,
        (policy.parental_policy_id, policy.security_policy_id, policy.service_blocking_ruleset_id),
    ):
        for domain in _domains_for_ruleset(conn, ruleset_id):
            blocked[domain] = response
    return blocked


def _safesearch_providers_for_policy(policy) -> tuple[str, ...]:
    if policy.safesearch_mode and policy.safesearch_mode != "off":
        return safesearch.SUPPORTED_PROVIDERS
    return ()


def _default_upstream_endpoints() -> tuple:
    from app.v2.policy_store import UpstreamEndpointRecord

    return (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None), UpstreamEndpointRecord("9.9.9.9:53", None, 0, 1, None))


def _upstream_for_policy(conn: sqlite3.Connection, policy) -> tuple[tuple, str]:
    if policy.upstream_profile_id:
        profile = store.load_upstream_profile(conn, policy.upstream_profile_id)
        if profile is not None:
            return profile.endpoints, profile.transport
    return _default_upstream_endpoints(), "plain"


def _ecs_for_policy(policy) -> EcsPolicy:
    mode = _ECS_MODE_MAP.get(policy.ecs_mode, "disabled")
    return EcsPolicy(mode=mode)


def _binding_for_scope(conn: sqlite3.Connection, network: NetworkScope, policy) -> ClientPolicyBinding:
    cache_profile = compile_cache_profile(policy)
    endpoints, transport = _upstream_for_policy(conn, policy)
    return ClientPolicyBinding(
        network=network,
        cache_profile_id=cache_profile.profile_id,
        safesearch_providers=_safesearch_providers_for_policy(policy),
        blocked_domains=_blocked_domains_for_policy(conn, policy),
        upstream_endpoints=endpoints,
        upstream_transport=transport,
        ecs_policy=_ecs_for_policy(policy),
    )


def build_bindings(conn: sqlite3.Connection) -> list[ClientPolicyBinding]:
    """One binding per configured network (network-layer policy merged
    over the global layer), plus a catch-all default binding covering
    everything else (0.0.0.0/0) using the global layer alone. Real control
    state, no synthetic/test-only shortcuts."""
    global_layer = store.load_policy_layer(conn, "global", "singleton")

    bindings: list[ClientPolicyBinding] = []
    for network_id, cidr in conn.execute("SELECT network_id, cidr FROM policy_networks").fetchall():
        scope = NetworkScope.create(network_id, cidr, policy_ref=network_id)
        network_layer = store.load_policy_layer(conn, "network", network_id)
        policy = compile_effective_policy(
            global_layer=global_layer, network_layer=network_layer, network_source=network_id
        )
        bindings.append(_binding_for_scope(conn, scope, policy))

    default_scope = NetworkScope.create(_DEFAULT_NETWORK_ID, "0.0.0.0/0", policy_ref=_DEFAULT_NETWORK_ID)
    default_policy = compile_effective_policy(global_layer=global_layer)
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
) -> RuntimeCompileResult:
    """The real, single code path from "control.db changed" to "compiled
    dnsdist config on disk validated by the real binary." Raises on any
    failure (invalid domain data, dnsdist rejects the config, ...) -- the
    live path is never touched until validation succeeds, so a known-good
    runtime always remains active on failure, per §18.
    """
    try:
        bindings = build_bindings(conn)
        local_dns_records = store.load_local_dns_records(conn)
        # compile_multi_policy_dnsdist_config()'s local-DNS compiler
        # silently skips PTR rows (needs a different matcher than the
        # forward record it's paired with -- not implemented yet);
        # counted here, not inside the compiler, so a caller can decide
        # whether to surface it rather than it vanishing with no signal.
        ptr_records_skipped = sum(1 for r in local_dns_records if r[1] == "PTR")
        config_text = compile_multi_policy_dnsdist_config(
            listen_address, bindings, local_dns_records=local_dns_records,
            dot=dot, doh=doh, doq=doq, doh3=doh3, dnscrypt=dnscrypt,
        )
    except PolicyRuntimeError as exc:
        raise RuntimeCompileError(f"policy runtime compile failed: {exc}") from exc

    staging_dir.mkdir(parents=True, exist_ok=True)
    try:
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
