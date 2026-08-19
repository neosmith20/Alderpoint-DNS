"""BIND architecture correction (Gate #3) regression coverage, including
the multi-context acceptance-closure design (a genuinely distinct plain
upstream selection gets its own real BIND-backed recursive cache, not
just the single appliance default).

Proves the things a review must be able to re-check mechanically,
without a live installed appliance:

1. The default/bootstrap dnsdist config generated for a fresh install
   forwards to the packaged V2 BIND recursive-cache backend, never
   straight to a public upstream -- the exact regression the locked
   ``docs/v2/architecture-map.md`` hot path requires.
2. ``compile_multi_policy_dnsdist_config``'s real per-effective-policy
   compiler routes a pool through its allocated BIND context only when
   that pool's plain, non-ECS upstream endpoints exactly match a
   forwarder set a context was actually allocated for -- multiple
   distinct plain upstream selections each get their own context/cache;
   an unallocated (beyond ``bind_gen.MAX_BIND_CONTEXTS``) or
   ECS/DoT/DoH selection keeps going direct, never silently collapsed
   onto an unrelated context.
"""

from __future__ import annotations

import shutil

import pytest

from app.v2 import bind_gen
from app.v2.dnsdist_gen import UpstreamServer, generate_dnsdist_config
from app.v2.dnsdist_policy_runtime import ClientPolicyBinding, compile_multi_policy_dnsdist_config
from app.v2.ecs_policy import EcsPolicy
from app.v2.network_match import NetworkScope
from app.v2.policy_store import UpstreamEndpointRecord

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


def _binding(cidr, profile_id, endpoints, **kwargs):
    net = NetworkScope.create(f"n-{profile_id}", cidr, "x")
    defaults = dict(
        network=net, cache_profile_id=profile_id,
        upstream_endpoints=endpoints, upstream_transport="plain",
    )
    defaults.update(kwargs)
    return ClientPolicyBinding(**defaults)


def _context_addresses(*forwarder_sets):
    contexts = bind_gen.allocate_bind_contexts(list(forwarder_sets))
    return {(frozenset(ctx.forwarders), ctx.tls_hostname): bind_gen.context_backend_address(ctx) for ctx in contexts}


class TestDefaultBootstrapRoutesThroughBind:
    def test_default_pool_targets_bind_backend_not_public_upstream(self):
        upstreams = [UpstreamServer("bind-v2", bind_gen.BIND_BACKEND_ADDRESS, use_proxy_protocol=True)]
        text = generate_dnsdist_config("0.0.0.0:53", [], upstreams)
        assert bind_gen.BIND_BACKEND_ADDRESS in text
        assert "useProxyProtocol=true" in text
        assert "1.1.1.1" not in text
        assert "9.9.9.9" not in text

    def test_bind_backend_address_uses_proxy_port_not_v1s_ports(self):
        assert bind_gen.BIND_BACKEND_ADDRESS == f"127.0.0.1:{bind_gen.BIND_PROXY_PORT}"
        assert "5353" not in bind_gen.BIND_BACKEND_ADDRESS
        assert "5354" not in bind_gen.BIND_BACKEND_ADDRESS


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="requires dnsdist")
class TestPolicyCompilerBindRouting:
    def test_matching_default_forwarders_route_via_bind(self):
        addrs = _context_addresses(("1.1.1.1:53", "9.9.9.9:53"))
        eps = (
            UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),
            UpstreamEndpointRecord("9.9.9.9:53", None, 0, 1, None),
        )
        b = _binding("10.0.0.0/24", "p1", eps)
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b], bind_context_addresses=addrs)
        assert bind_gen.BIND_BACKEND_ADDRESS in text
        assert "useProxyProtocol=true" in text
        assert '"1.1.1.1:53"' not in text

    def test_two_distinct_custom_profiles_each_get_own_bind_context(self):
        # The multi-context acceptance-closure case: two genuinely
        # different plain upstream selections must each be routed
        # through BIND, via two DIFFERENT context addresses -- neither
        # bypasses BIND, and neither is silently collapsed onto the
        # other's cache.
        addrs = _context_addresses(("1.1.1.1:53",), ("9.9.9.9:53",))
        b1 = _binding("10.0.0.0/24", "p1", (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),))
        b2 = _binding("10.0.1.0/24", "p2", (UpstreamEndpointRecord("9.9.9.9:53", None, 0, 1, None),))
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b1, b2], bind_context_addresses=addrs)
        ctx0_addr = addrs[(frozenset({"1.1.1.1:53"}), None)]
        ctx1_addr = addrs[(frozenset({"9.9.9.9:53"}), None)]
        assert ctx0_addr != ctx1_addr
        assert f'address="{ctx0_addr}"' in text
        assert f'address="{ctx1_addr}"' in text
        # Neither the direct public addresses appear as a dnsdist backend
        assert '"1.1.1.1:53"' not in text
        assert '"9.9.9.9:53"' not in text

    def test_unallocated_custom_upstream_bypasses_bind_not_collapsed(self):
        # A distinct provider with no allocated context (e.g. beyond
        # MAX_BIND_CONTEXTS, or simply not passed in by the caller) must
        # never be silently forwarded through an unrelated context.
        addrs = _context_addresses(("1.1.1.1:53",))
        eps = (UpstreamEndpointRecord("8.8.8.8:53", None, 0, 1, None),)
        b = _binding("10.0.0.0/24", "p2", eps)
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b], bind_context_addresses=addrs)
        assert '"8.8.8.8:53"' in text
        for ctx_addr in addrs.values():
            assert f'address="{ctx_addr}"' not in text

    def test_ecs_exception_pool_bypasses_bind(self):
        # The documented, narrow, explicit ECS architecture exception
        # (owner decision, docs/v2/bind-backend-v2.md): ISC confirms
        # open-source BIND provides no resolver-side EDNS Client Subnet
        # support at all (only the commercial Subscription Edition does)
        # -- verified independently against the installed binary (no
        # client-subnet/ecs-zones directive exists in it). An ECS pool
        # must never be routed through BIND -- it stays on the existing,
        # safe, already-proven dnsdist-direct path, which DOES preserve
        # ECS correctly (useClientSubnet=true, asserted below). This is
        # the ONLY category excluded for a real, verified technical
        # reason, not a general BIND bypass -- every other transport
        # (plain, DoT, DoH-via-egress) routes through BIND.
        addrs = _context_addresses(("1.1.1.1:53",))
        eps = (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),)
        b = _binding("10.0.0.0/24", "p3", eps, ecs_policy=EcsPolicy(mode="preserve"))
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b], bind_context_addresses=addrs)
        for ctx_addr in addrs.values():
            assert f'address="{ctx_addr}"' not in text
        # The exception preserves real functionality, not just "skips
        # BIND silently" -- ECS is genuinely applied on the direct path.
        assert "useClientSubnet=true" in text
        assert '"1.1.1.1:53"' in text

    def test_dot_with_matching_context_routes_via_bind(self):
        # Real, verified-live DoT-through-BIND (BIND 9.20's own
        # certificate-hostname-verified TLS forwarding) -- when a context
        # was allocated for this exact (forwarders, tls_hostname) pair,
        # DoT routes through it just like plain.
        addrs = _context_addresses(
            bind_gen.UpstreamSelection(forwarders=("1.1.1.1:853",), tls_hostname="cloudflare-dns.com"),
        )
        eps = (UpstreamEndpointRecord("1.1.1.1:853", "cloudflare-dns.com", 0, 1, None),)
        b = _binding("10.0.0.0/24", "p4", eps, upstream_transport="dot")
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b], bind_context_addresses=addrs)
        ctx_addr = list(addrs.values())[0]
        assert f'address="{ctx_addr}"' in text
        assert 'tls="openssl"' not in text  # not dispatched direct

    def test_dot_without_matching_context_bypasses_bind(self):
        # No context allocated for this DoT selection -- must keep going
        # direct, never silently merged with an unrelated context.
        addrs = _context_addresses(("1.1.1.1:853",))  # plain context, not DoT
        eps = (UpstreamEndpointRecord("1.1.1.1:853", "cloudflare-dns.com", 0, 1, None),)
        b = _binding("10.0.0.0/24", "p4", eps, upstream_transport="dot")
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b], bind_context_addresses=addrs)
        for ctx_addr in addrs.values():
            assert f'address="{ctx_addr}"' not in text
        assert 'tls="openssl"' in text

    def test_doh_transport_always_bypasses_bind(self):
        # BIND has no DoH-forwarder capability at all -- DoH pools never
        # route through BIND regardless of what contexts are allocated.
        addrs = _context_addresses(("1.1.1.1:443",))
        eps = (UpstreamEndpointRecord("1.1.1.1:443", "cloudflare-dns.com", 0, 1, None),)
        b = _binding("10.0.0.0/24", "p6", eps, upstream_transport="doh")
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b], bind_context_addresses=addrs)
        for ctx_addr in addrs.values():
            assert f'address="{ctx_addr}"' not in text
        assert 'dohPath' in text

    def test_no_bind_contexts_configured_never_routes_via_bind(self):
        # Backward compatibility: a caller that hasn't wired BIND
        # contexts yet gets exactly the pre-existing direct-to-upstream
        # behavior -- no silent behavior change for any not-yet-updated
        # caller.
        eps = (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),)
        b = _binding("10.0.0.0/24", "p5", eps)
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b])
        assert bind_gen.BIND_BACKEND_ADDRESS not in text
        assert '"1.1.1.1:53"' in text


class TestContextAllocation:
    def test_deterministic_regardless_of_call_count(self):
        a = bind_gen.allocate_bind_contexts([("1.1.1.1:53",), ("9.9.9.9:53",)])
        b = bind_gen.allocate_bind_contexts([("1.1.1.1:53",), ("9.9.9.9:53",)])
        assert [(c.name, c.plain_port, c.proxy_port) for c in a] == [(c.name, c.plain_port, c.proxy_port) for c in b]

    def test_bounded_at_max_contexts(self):
        many = [(f"10.0.0.{i}:53",) for i in range(bind_gen.MAX_BIND_CONTEXTS + 3)]
        contexts = bind_gen.allocate_bind_contexts(many)
        assert len(contexts) == bind_gen.MAX_BIND_CONTEXTS

    def test_ports_disjoint_across_contexts(self):
        contexts = bind_gen.allocate_bind_contexts([("1.1.1.1:53",), ("9.9.9.9:53",), ("8.8.8.8:53",)])
        ports = [p for c in contexts for p in (c.plain_port, c.proxy_port)]
        assert len(ports) == len(set(ports))

    def test_first_context_uses_well_known_default_ports(self):
        contexts = bind_gen.allocate_bind_contexts([("1.1.1.1:53",)])
        assert contexts[0].plain_port == bind_gen.BIND_PLAIN_PORT
        assert contexts[0].proxy_port == bind_gen.BIND_PROXY_PORT
        assert bind_gen.context_backend_address(contexts[0]) == bind_gen.BIND_BACKEND_ADDRESS
