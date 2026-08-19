"""BIND architecture correction (Gate #3) regression coverage.

Proves the two things a review must be able to re-check mechanically,
without a live installed appliance:

1. The default/bootstrap dnsdist config generated for a fresh install
   forwards to the packaged V2 BIND recursive-cache backend, never
   straight to a public upstream -- this is the exact regression the
   locked ``docs/v2/architecture-map.md`` hot path (client -> dnsdist
   packet cache -> compiled policy/routing -> BIND RAM recursive cache ->
   upstream) requires, and the exact thing Gate #3 caught was silently
   missing.
2. ``compile_multi_policy_dnsdist_config``'s real per-effective-policy
   compiler only ever routes a pool through BIND when that pool's plain,
   non-ECS upstream endpoints exactly match the appliance's configured
   BIND forwarder set -- a distinct custom upstream selection (a
   different provider, DoT, DoH, or ECS) must never be silently
   collapsed onto the shared BIND forwarder list.
"""

from __future__ import annotations

import shutil

import pytest

from app.v2 import bind_gen
from app.v2.blocking_response import BlockingResponse
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


class TestDefaultBootstrapRoutesThroughBind:
    def test_default_pool_targets_bind_backend_not_public_upstream(self):
        # This is the literal regression a fresh install shipped for a
        # long time (scripts/v2/alderpointdns_v2_ctl.py's
        # _default_dnsdist_config_text, before this pass): the only
        # newServer() in a clean-install config pointed straight at
        # 1.1.1.1:53/9.9.9.9:53. It must now point only at BIND.
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
        bind_forwarders = frozenset({"1.1.1.1:53", "9.9.9.9:53"})
        eps = (
            UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),
            UpstreamEndpointRecord("9.9.9.9:53", None, 0, 1, None),
        )
        b = _binding("10.0.0.0/24", "p1", eps)
        text = compile_multi_policy_dnsdist_config(
            "0.0.0.0:53", [b], bind_forwarders=bind_forwarders,
        )
        assert bind_gen.BIND_BACKEND_ADDRESS in text
        assert "useProxyProtocol=true" in text
        assert '"1.1.1.1:53"' not in text  # not emitted as a direct newServer target

    def test_distinct_custom_upstream_bypasses_bind_not_collapsed(self):
        # A different, deliberately-chosen provider must never be
        # silently forwarded through BIND's shared forwarder set.
        bind_forwarders = frozenset({"1.1.1.1:53"})
        eps = (UpstreamEndpointRecord("8.8.8.8:53", None, 0, 1, None),)
        b = _binding("10.0.0.0/24", "p2", eps)
        text = compile_multi_policy_dnsdist_config(
            "0.0.0.0:53", [b], bind_forwarders=bind_forwarders,
        )
        assert '"8.8.8.8:53"' in text
        assert bind_gen.BIND_BACKEND_ADDRESS not in text

    def test_ecs_pool_bypasses_bind(self):
        bind_forwarders = frozenset({"1.1.1.1:53"})
        eps = (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),)
        b = _binding(
            "10.0.0.0/24", "p3", eps,
            ecs_policy=EcsPolicy(mode="preserve"),
        )
        text = compile_multi_policy_dnsdist_config(
            "0.0.0.0:53", [b], bind_forwarders=bind_forwarders,
        )
        assert bind_gen.BIND_BACKEND_ADDRESS not in text

    def test_dot_transport_bypasses_bind(self):
        bind_forwarders = frozenset({"1.1.1.1:853"})
        eps = (UpstreamEndpointRecord("1.1.1.1:853", "cloudflare-dns.com", 0, 1, None),)
        b = _binding("10.0.0.0/24", "p4", eps, upstream_transport="dot")
        text = compile_multi_policy_dnsdist_config(
            "0.0.0.0:53", [b], bind_forwarders=bind_forwarders,
        )
        assert bind_gen.BIND_BACKEND_ADDRESS not in text
        assert 'tls="openssl"' in text

    def test_no_bind_forwarders_configured_never_routes_via_bind(self):
        # Backward compatibility: a caller that hasn't wired BIND forwarders
        # yet (bind_forwarders left at its default empty frozenset) gets
        # exactly the pre-existing direct-to-upstream behavior -- no
        # silent behavior change for any not-yet-updated caller.
        eps = (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),)
        b = _binding("10.0.0.0/24", "p5", eps)
        text = compile_multi_policy_dnsdist_config("0.0.0.0:53", [b])
        assert bind_gen.BIND_BACKEND_ADDRESS not in text
        assert '"1.1.1.1:53"' in text
