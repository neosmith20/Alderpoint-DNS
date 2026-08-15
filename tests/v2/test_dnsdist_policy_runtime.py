import shutil

import pytest

from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_policy_runtime import (
    ClientPolicyBinding,
    PolicyRuntimeError,
    compile_multi_policy_dnsdist_config,
)
from app.v2.ecs_policy import EcsPolicy
from app.v2.network_match import NetworkScope
from app.v2.policy_store import UpstreamEndpointRecord

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


def _binding(net_cidr, profile_id, **kwargs):
    net = NetworkScope.create(f"n-{profile_id}", net_cidr, "x")
    defaults = dict(
        network=net, cache_profile_id=profile_id,
        upstream_endpoints=(UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),),
        upstream_transport="plain",
    )
    defaults.update(kwargs)
    return ClientPolicyBinding(**defaults)


class TestBasicGeneration:
    def test_requires_at_least_one_binding(self):
        with pytest.raises(PolicyRuntimeError):
            compile_multi_policy_dnsdist_config("127.0.0.1:5300", [])

    def test_deterministic_output(self):
        b1 = _binding("10.0.1.0/24", "p1")
        b2 = _binding("10.0.2.0/24", "p2")
        a = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b1, b2])
        b = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b2, b1])
        # Same set regardless of input order (sorted by specificity/id).
        assert set(a.splitlines()) == set(b.splitlines())


class TestPoolDeduplication:
    def test_identical_cache_profile_id_shares_one_pool(self):
        b1 = _binding("10.0.1.0/24", "shared")
        b2 = _binding("10.0.2.0/24", "shared")
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b1, b2])
        assert text.count("newPacketCache") == 1
        assert text.count('newServer({address="1.1.1.1:53"') == 1

    def test_different_profiles_get_separate_pools_and_caches(self):
        b1 = _binding("10.0.1.0/24", "p1")
        b2 = _binding("10.0.2.0/24", "p2")
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b1, b2])
        assert text.count("newPacketCache") == 2


class TestSpecificityOrdering:
    def test_more_specific_network_rules_appear_before_broader(self):
        broad = _binding("10.0.0.0/8", "broad")
        narrow = _binding("10.0.1.0/24", "narrow")
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [broad, narrow])
        narrow_pos = text.index("-- rules for network n-narrow")
        broad_pos = text.index("-- rules for network n-broad")
        assert narrow_pos < broad_pos


class TestBlockingAndAllowOverride:
    def test_explicit_allow_excludes_domain_from_block_rules(self):
        b = _binding(
            "10.0.1.0/24", "p1",
            blocked_domains={"x.example": BlockingResponse(mode="refused")},
            allowed_domains=frozenset({"x.example"}),
        )
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b])
        assert 'SuffixMatchNodeRule({"x.example."})' not in text

    def test_refused_uses_rcode_action(self):
        b = _binding("10.0.1.0/24", "p1", blocked_domains={"x.example": BlockingResponse(mode="refused")})
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b])
        assert "RCodeAction(DNSRCode.REFUSED)" in text


class TestSafeSearchRendering:
    def test_safesearch_generates_cname_spoof_scoped_to_network(self):
        b = _binding("10.0.1.0/24", "p1", safesearch_providers=("google",))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b])
        assert "SpoofCNAMEAction" in text
        assert 'NetmaskGroupRule({"10.0.1.0/24"})' in text


class TestDoHWithinPolicyRuntime:
    def test_doh_endpoint_requires_tls_hostname(self):
        b = _binding(
            "10.0.1.0/24", "p1",
            upstream_endpoints=(UpstreamEndpointRecord("1.1.1.1:443", None, 0, 1, None),),
            upstream_transport="doh",
        )
        with pytest.raises(PolicyRuntimeError):
            compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b])

    def test_doh_endpoint_with_hostname_renders_correctly(self):
        b = _binding(
            "10.0.1.0/24", "p1",
            upstream_endpoints=(
                UpstreamEndpointRecord("1.1.1.1:443", "cloudflare-dns.com", 0, 1, None, doh_path="/dns-query"),
            ),
            upstream_transport="doh",
        )
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b])
        assert 'dohPath="/dns-query"' in text
        assert 'subjectName="cloudflare-dns.com"' in text


class TestECSDifferentiation:
    def test_preserve_sets_use_client_subnet_only_for_that_pool(self):
        b1 = _binding("10.0.1.0/24", "p1", ecs_policy=EcsPolicy(mode="preserve"))
        b2 = _binding("10.0.2.0/24", "p2", ecs_policy=EcsPolicy(mode="disabled"))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b1, b2])
        assert "useClientSubnet=true" in text


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist not installed")
class TestRealValidation:
    def test_multi_policy_config_validates(self, tmp_path):
        import subprocess

        b1 = _binding("10.0.1.0/24", "p1", safesearch_providers=("google",))
        b2 = _binding(
            "10.0.2.0/24", "p2",
            blocked_domains={"bad.example": BlockingResponse(mode="refused")},
        )
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15350", [b1, b2])
        conf_path = tmp_path / "c.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
