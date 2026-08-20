"""Gate #2 MEDIUM §7B: invalid domain data must never reach rendered
zone/config text -- proven by injecting malicious names at every real
generation call site and confirming rejection happens BEFORE any text is
rendered (named-checkzone/dnsdist --check-config remain defense-in-depth,
exercised separately elsewhere, not the only line of defense).
"""

import pytest

from app.v2.bind_rpz_gen import BindRpzGenError, render_rpz_zone
from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_cache_policy import ClientScopedBlockRule, render_client_scoped_block_rules
from app.v2.dnsdist_gen import DnsdistGenError, UpstreamServer, generate_dnsdist_config_from_profiles
from app.v2.dnsdist_policy_runtime import (
    ClientPolicyBinding,
    PolicyRuntimeError,
    compile_multi_policy_dnsdist_config,
)
from app.v2.local_dns_gen import LocalDnsGenError, LocalDnsRecord
from app.v2.network_match import NetworkScope
from app.v2.policy_store import UpstreamEndpointRecord, UpstreamProfileRecord

MALICIOUS = "evil.example\nA 6.6.6.6\n;"


class TestRPZGeneration:
    def test_malicious_blocked_domain_rejected_before_render(self):
        with pytest.raises(BindRpzGenError):
            render_rpz_zone({MALICIOUS: BlockingResponse(mode="nxdomain")}, [], serial=1)

    def test_malicious_allowed_domain_rejected_before_render(self):
        with pytest.raises(BindRpzGenError):
            render_rpz_zone({}, [MALICIOUS], serial=1)


class TestLocalDnsGeneration:
    def test_malicious_fqdn_rejected(self):
        with pytest.raises(LocalDnsGenError):
            LocalDnsRecord(MALICIOUS, "A", "10.0.0.1")

    def test_malicious_cname_target_rejected(self):
        with pytest.raises(LocalDnsGenError):
            LocalDnsRecord("alias.example", "CNAME", MALICIOUS)


class TestDomainRoutingGeneration:
    def test_malicious_routing_suffix_rejected(self):
        default = UpstreamProfileRecord(
            "default", "D", "plain", "ordered",
            (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),),
        )
        bad = UpstreamProfileRecord(
            "bad", "Bad", "plain", "ordered",
            (UpstreamEndpointRecord("9.9.9.9:53", None, 0, 1, None),),
        )
        with pytest.raises(DnsdistGenError):
            generate_dnsdist_config_from_profiles(
                "127.0.0.1:5300", [], default, domain_routing=[(MALICIOUS, bad)]
            )


class TestClientScopedBlockRuleGeneration:
    def test_malicious_domain_in_client_scoped_rule_rejected(self):
        net = NetworkScope.create("n1", "10.0.0.0/24", "x")
        rule = ClientScopedBlockRule(net, (MALICIOUS,), BlockingResponse(mode="refused"))
        with pytest.raises(ValueError):
            render_client_scoped_block_rules([rule])


class TestPolicyRuntimeGeneration:
    def test_malicious_blocked_domain_in_binding_rejected(self):
        net = NetworkScope.create("n1", "10.0.0.0/24", "x")
        binding = ClientPolicyBinding(
            network=net, cache_profile_id="p1",
            blocked_domains={MALICIOUS: BlockingResponse(mode="refused")},
            upstream_endpoints=(UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),),
        )
        with pytest.raises(PolicyRuntimeError):
            compile_multi_policy_dnsdist_config("127.0.0.1:5300", [binding])

    def test_malicious_domain_route_suffix_in_binding_rejected(self):
        net = NetworkScope.create("n1", "10.0.0.0/24", "x")
        binding = ClientPolicyBinding(
            network=net, cache_profile_id="p1",
            domain_routes=((MALICIOUS, (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),), "plain", "ordered", "suffix"),),
            upstream_endpoints=(UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),),
        )
        with pytest.raises(PolicyRuntimeError):
            compile_multi_policy_dnsdist_config("127.0.0.1:5300", [binding])


class TestPolicyStoreValidation:
    def test_malicious_domain_routing_rule_rejected_at_storage(self, tmp_path):
        from app.v2 import control_db, policy_store as store

        path = tmp_path / "control.db"
        store.ensure_schema(path)
        with control_db.connect(path) as conn:
            with pytest.raises(store.PolicyStoreError):
                store.add_domain_routing_rule(conn, "r1", "suffix", MALICIOUS, "default")
