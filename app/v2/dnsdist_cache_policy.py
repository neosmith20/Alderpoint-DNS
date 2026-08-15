"""V2 dnsdist packet-cache / effective-cache-profile integration
(Workstream 3 final continuation, Priority 4, §28-29).

**Real finding from implementation evidence (documented per §52, not
silently redesigned):** the current generators (``app/v2/dnsdist_gen.py``,
``app/v2/bind_rpz_gen.py``) produce ONE global RPZ zone and ONE dnsdist
config -- filtering/blocking decisions are not yet differentiated per
client/network/effective-cache-profile at the BIND layer at all (BIND's
RPZ has no per-client view in what's generated so far). A single shared
packet cache would therefore already be "safe" in the narrow sense that
every client currently gets the same filtered answer regardless of
profile -- but that defeats the actual product requirement (different
policy per client/group/network), so this module treats that as a real
gap to design around, not something to paper over with a cache-safety
claim that would become false the moment per-profile filtering is
actually wired up.

**The safe hybrid strategy implemented here** (§28's own suggested
escape hatch: "if native packet-cache partitioning is limited, implement
a safe hybrid/bypass strategy"): apply policy-sensitive decisions
(blocking/REFUSED) at the dnsdist layer, scoped by client source network,
*before* any pool/cache selection -- ``RCodeAction``/similar terminal
actions bypass the packet cache entirely for that query (dnsdist never
caches a locally-synthesized non-forwarded answer), so:

- BIND's recursive cache stays maximally shared (§29) -- BIND only ever
  sees queries dnsdist decided to actually forward, and forwarded queries
  for the same qname/qtype get the same real upstream answer regardless
  of which client asked, so nothing prevents full cache reuse there.
- dnsdist's packet cache is partitioned **per upstream pool** (one
  ``PacketCache`` object per named pool, via ``getPool(name):setCache()``)
  -- this is the real, verified-against-the-installed-binary boundary
  available in this dnsdist version. Any answer-affecting policy
  dimension that should prevent cache sharing MUST be reflected in pool
  assignment (upstream routing already does this); dimensions that are
  NOT reflected in pool assignment (yet) are the same known gap stated
  above, not silently claimed solved by this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_gen import _lua_string
from app.v2.network_match import NetworkScope

DEFAULT_MAX_CACHE_ENTRIES = 10_000
DEFAULT_MAX_CACHE_TTL_SECONDS = 86400


@dataclass(frozen=True)
class ClientScopedBlockRule:
    network: NetworkScope
    domains: tuple[str, ...]
    response: BlockingResponse


def render_packet_cache_setup(pool_names: list[str], max_entries: int = DEFAULT_MAX_CACHE_ENTRIES) -> tuple[str, ...]:
    """One independent ``PacketCache`` object per named pool (including
    the default/unnamed pool, represented here as ``""``) -- proven at
    the dnsdist-syntax level against the installed binary
    (``newPacketCache``/``getPool(name):setCache()``). Two different pools
    can never share a cache entry by construction: they are two entirely
    separate cache objects, not a filtered view of one shared object.
    """
    lines = []
    for i, pool in enumerate(pool_names):
        var = f"pc_{i}"
        lines.append(
            f'{var} = newPacketCache({max_entries}, {{maxTTL={DEFAULT_MAX_CACHE_TTL_SECONDS}}})'
        )
        lines.append(f'getPool({_lua_string(pool)}):setCache({var})')
    return tuple(lines)


def render_client_scoped_block_rules(rules: list[ClientScopedBlockRule]) -> tuple[str, ...]:
    """Each rule becomes an ``AndRule(NetmaskGroupRule(...),
    SuffixMatchNodeRule(...))`` -> terminal action (``RCodeAction`` for
    refused, or a suffix-CNAME/A/AAAA spoof for the other modes),
    evaluated *before* any pool selection, so a blocked query for a given
    client network never reaches the shared upstream pool or its packet
    cache at all -- there is nothing to leak, because dnsdist itself
    synthesizes the answer without ever forwarding or caching it.

    ``nxdomain``/``null_ip``/``custom_ip`` modes use ``SpoofAction`` (a
    real, verified terminal dnsdist action distinct from RPZ's CNAME-based
    approach) so this works even for clients/networks whose blocking
    should differ from the global RPZ zone.
    """
    lines = []
    for rule in rules:
        from app.v2.dns_name_validate import InvalidDnsNameError, validate_dns_name

        try:
            validated = [validate_dns_name(d) for d in rule.domains]
        except InvalidDnsNameError as exc:
            raise ValueError(f"invalid domain in client-scoped block rule: {exc}") from exc
        domain_list = ", ".join(_lua_string(d + ".") for d in validated)
        matcher = (
            f'AndRule({{NetmaskGroupRule({{{_lua_string(rule.network.cidr)}}}), '
            f'SuffixMatchNodeRule({{{domain_list}}})}})'
        )
        if rule.response.mode == "refused":
            action = "RCodeAction(DNSRCode.REFUSED)"
        elif rule.response.mode == "nxdomain":
            action = "RCodeAction(DNSRCode.NXDOMAIN)"
        elif rule.response.mode == "null_ip":
            # Real verified dnsdist syntax: SpoofAction takes a single Lua
            # table of address strings, not separate positional v4/v6
            # arguments (a first attempt using two positional string args
            # failed a real --check-config run with a Lua type-conversion
            # error -- caught before this ever shipped, fixed here).
            action = 'SpoofAction({"0.0.0.0", "::"})'
        else:  # custom_ip
            addrs = [a for a in (rule.response.custom_ipv4, rule.response.custom_ipv6) if a]
            addr_list = ", ".join(_lua_string(a) for a in addrs) or '"0.0.0.0"'
            action = f'SpoofAction({{{addr_list}}})'
        lines.append(f"-- client-scoped block: network {rule.network.network_id}")
        lines.append(f"addAction({matcher}, {action})")
    return tuple(lines)
