import shutil

import pytest

from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_policy_runtime import (
    ClientPolicyBinding,
    DotConfig,
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
class TestLocalDnsRecords:
    def test_a_record_compiled_as_terminal_spoof_action(self):
        b = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:5300", [b], local_dns_records=[("host1.lan", "A", "10.20.1.1", 300)],
        )
        assert 'QNameRule("host1.lan.")' in text
        assert 'SpoofAction({"10.20.1.1"})' in text
        # Registered before any per-binding pool/catch-all rule.
        assert text.index("host1.lan") < text.index("-- rules for network")

    def test_cname_record_compiled_as_spoof_cname(self):
        b = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:5300", [b],
            local_dns_records=[("alias.lan", "CNAME", "host1.lan", 300)],
        )
        assert 'SpoofCNAMEAction("host1.lan.")' in text

    def test_ptr_record_silently_excluded_from_generated_rules(self):
        b = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:5300", [b],
            local_dns_records=[("1.1.20.10.in-addr.arpa", "PTR", "host1.lan", 300)],
        )
        assert "in-addr" not in text

    def test_invalid_local_dns_name_rejected(self):
        b = _binding("10.0.1.0/24", "p1")
        with pytest.raises(PolicyRuntimeError):
            compile_multi_policy_dnsdist_config(
                "127.0.0.1:5300", [b],
                local_dns_records=[("not a valid name!", "A", "10.0.0.1", 300)],
            )

    def test_deterministic_regardless_of_input_order(self):
        b = _binding("10.0.1.0/24", "p1")
        records = [("host2.lan", "A", "10.0.0.2", 300), ("host1.lan", "A", "10.0.0.1", 300)]
        a = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b], local_dns_records=records)
        c = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b], local_dns_records=list(reversed(records)))
        assert a == c

    def test_real_validation_with_local_dns_records(self, tmp_path):
        import subprocess

        b = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15351", [b],
            local_dns_records=[
                ("host1.lan", "A", "10.20.1.1", 300),
                ("alias.lan", "CNAME", "host1.lan", 300),
            ],
        )
        conf_path = tmp_path / "c.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr


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

    def test_query_log_remote_logger_wired_and_passes_real_check_config(self, tmp_path):
        import subprocess

        b1 = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15351", [b1])
        assert 'newRemoteLogger("127.0.0.1:5391")' in text
        assert "addResponseAction(AllRule(), RemoteLogResponseAction(" in text
        conf_path = tmp_path / "c.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_query_log_can_be_disabled(self):
        b1 = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15352", [b1], analytics_log_address=None)
        assert "RemoteLogger" not in text

    def test_dot_listener_wired_and_passes_real_check_config(self, tmp_path):
        # Real defect this closes (docs/v2/encrypted-transport-parity-gap.md):
        # DoH/DoT/DoQ/DoH3/DNSCrypt were entirely absent from V2's real
        # config generation. This proves DoT's real addTLSLocal directive
        # (V1's own proven packaging/dnsdist.conf syntax, ported here)
        # both renders correctly and validates against the real installed
        # dnsdist binary.
        import subprocess

        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        dot = DotConfig(enabled=True, port=15353, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15354", [b1], dot=dot)
        assert 'addTLSLocal("127.0.0.1:15353"' in text
        assert 'minTLSVersion="tls1.2"' in text
        conf_path = tmp_path / "c.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_dot_listener_omitted_when_disabled(self):
        b1 = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15355", [b1], dot=DotConfig(enabled=False, port=853, cert_path="x", key_path="y")
        )
        assert "addTLSLocal" not in text

    def test_dot_listener_omitted_when_not_passed_at_all(self):
        b1 = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15356", [b1])
        assert "addTLSLocal" not in text


def _self_signed_cert(tmp_path):
    import subprocess

    cert_path = tmp_path / "dot-test.crt"
    key_path = tmp_path / "dot-test.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key_path), "-out", str(cert_path),
            "-days", "1", "-subj", "/CN=dot-test",
        ],
        check=True, capture_output=True,
    )
    return cert_path, key_path
