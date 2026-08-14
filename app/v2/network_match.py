"""V2 network-scoped policy matching (Workstream 3, §4).

Compiles a set of client-network CIDR policy scopes into a structure that
resolves "which network policy applies to this client IP" without a
database lookup per query, and with deterministic most-specific-wins
precedence when networks overlap (e.g. a client inside both 10.0.0.0/8 and
10.0.1.0/24 gets the /24's policy — the narrower, more specific match).

This module only does *matching*; it has no opinion on what a "network
policy" contains — callers (the policy compiler) attach whatever policy
object they like via ``policy_ref``.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddr = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class InvalidNetworkError(ValueError):
    pass


@dataclass(frozen=True)
class NetworkScope:
    """One configured network-policy scope. ``network_id`` is a stable
    identifier (not derived from CIDR text, so renumbering/renaming a scope
    doesn't change identity); ``policy_ref`` is an opaque reference to
    whatever policy object applies (e.g. a network-policy row's stable id).
    """

    network_id: str
    cidr: str
    policy_ref: str
    _net: IPNetwork

    @staticmethod
    def create(network_id: str, cidr: str, policy_ref: str) -> "NetworkScope":
        if not network_id:
            raise InvalidNetworkError("network_id must not be empty")
        if not policy_ref:
            raise InvalidNetworkError("policy_ref must not be empty")
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            raise InvalidNetworkError(f"invalid CIDR {cidr!r}: {exc}") from exc
        return NetworkScope(
            network_id=network_id, cidr=str(net), policy_ref=policy_ref, _net=net
        )


@dataclass(frozen=True)
class CompiledNetworkTable:
    """Immutable, compile-time-resolved set of network scopes, ready for
    O(n) — and in practice small-n — matching with no I/O. ``scopes`` is
    kept pre-sorted by specificity (longest prefix first) so matching is a
    simple linear scan returning the first hit, which is also the most
    specific one by construction.
    """

    scopes: tuple[NetworkScope, ...]

    def match(self, client_ip: str) -> Optional[NetworkScope]:
        try:
            addr = ipaddress.ip_address(client_ip)
        except ValueError as exc:
            raise InvalidNetworkError(f"invalid client IP {client_ip!r}: {exc}") from exc
        for scope in self.scopes:
            if addr.version == scope._net.version and addr in scope._net:
                return scope
        return None


def _duplicate_check(scopes: list[NetworkScope]) -> None:
    seen_ids: set[str] = set()
    seen_nets: set[str] = set()
    for s in scopes:
        if s.network_id in seen_ids:
            raise InvalidNetworkError(f"duplicate network_id: {s.network_id}")
        if s.cidr in seen_nets:
            raise InvalidNetworkError(f"duplicate CIDR: {s.cidr}")
        seen_ids.add(s.network_id)
        seen_nets.add(s.cidr)


def compile_network_table(scopes: list[NetworkScope]) -> CompiledNetworkTable:
    """Deterministic most-specific-first ordering: sort by prefix length
    descending (longer prefix == more specific == wins), tie-broken by
    ``network_id`` (never insertion/DB-row order) so identical-specificity
    ties are always resolved the same way regardless of input order.
    """
    _duplicate_check(scopes)
    ordered = sorted(
        scopes,
        key=lambda s: (-s._net.prefixlen, s._net.version, s.network_id),
    )
    return CompiledNetworkTable(scopes=tuple(ordered))
