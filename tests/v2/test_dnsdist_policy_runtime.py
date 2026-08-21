import shutil

import pytest

from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_policy_runtime import (
    ClientPolicyBinding,
    DohConfig,
    Doh3Config,
    DnscryptConfig,
    DoqConfig,
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

    def test_discovery_ingress_gets_a_real_copy_of_every_query(self):
        # Real defect found live during two-node discovery acceptance
        # testing: alderpointdns-v2-dns-observer's own ingress (1053)
        # was real and running from a fresh install onward, but nothing
        # in this generator ever sent it a copy of real client queries
        # -- /api/discovery/observed-clients stayed empty forever under
        # real dnsdist traffic. TeeAction is dnsdist's documented
        # fire-and-forget mirror (never blocks on or uses the target's
        # response), matching RemoteLogger's existing safety contract
        # for the analytics producer just above it.
        b = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b])
        assert 'TeeAction("127.0.0.1:1053", true)' in text
        assert "addAction(AllRule(), TeeAction(" in text

    def test_discovery_ingress_address_can_be_disabled(self):
        b = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b], discovery_ingress_address=None)
        assert "TeeAction" not in text

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


class TestBlockedDomainsAtRealBlocklistScale:
    """Real defect found live during the owner-beta closure blocklist-
    refresh acceptance pass: refreshing the V1.1.1-parity default
    StevenBlack Unified Hosts subscription (~150k domains) crashed
    dnsdist outright ("main function has more than 65536 constants") --
    every blocked domain was a literal Lua constant in one big
    `addAction` per domain. Fixed by routing blocked-domain rules
    through a runtime-loaded data file (see
    dnsdist_policy_runtime.py's own docstring) whenever a real
    ``blocked_domains_data_dir`` is given -- this is the direct
    regression test for that path; every OTHER test in this file
    (passing no data dir) still proves the small-scale literal path is
    completely unchanged."""

    def test_without_data_dir_keeps_the_prior_literal_output(self):
        """Backward compatibility: every existing caller/test (no
        blocked_domains_data_dir) must see byte-identical behavior."""
        b = _binding("10.0.1.0/24", "p1", blocked_domains={"x.example": BlockingResponse(mode="refused")})
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b])
        assert 'SuffixMatchNodeRule({"x.example."})' in text

    def test_with_data_dir_writes_a_real_file_and_loads_it_at_runtime(self, tmp_path):
        b = _binding("10.0.1.0/24", "p1", blocked_domains={"x.example": BlockingResponse(mode="refused")})
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b], blocked_domains_data_dir=tmp_path)
        assert 'SuffixMatchNodeRule({"x.example."})' not in text
        assert "newSuffixMatchNode()" in text
        assert "alderpointdnsDomainLines(" in text
        data_file = tmp_path / "blocked-domains" / f"{b.network.network_id}__0.txt"
        assert data_file.exists()
        assert data_file.read_text().strip().splitlines() == ["x.example."]

    def test_a_domain_count_that_would_have_exceeded_the_lua_constant_ceiling_compiles(self, tmp_path):
        """The actual regression: 100,000 blocked domains (well past
        Lua's 65536-constants-per-chunk ceiling) must compile without
        error and produce a real, complete data file -- this is what a
        real StevenBlack-sized subscription looks like."""
        domains = {f"blocked-{i}.example": BlockingResponse(mode="nxdomain") for i in range(100_000)}
        b = _binding("10.0.1.0/24", "p1", blocked_domains=domains)
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b], blocked_domains_data_dir=tmp_path)
        # The whole point: no domain string appears as a literal Lua
        # table entry in the generated config text at all.
        assert "blocked-99999.example" not in text
        data_file = tmp_path / "blocked-domains" / f"{b.network.network_id}__0.txt"
        lines = data_file.read_text().splitlines()
        assert len(lines) == 100_000
        assert "blocked-99999.example." in lines

    @pytest.mark.skipif(not DNSDIST_INSTALLED, reason="requires the real dnsdist binary")
    def test_real_dnsdist_check_config_accepts_a_config_at_this_scale(self, tmp_path):
        """The real regression, proven against the real binary: this is
        exactly what crashed with 'main function has more than 65536
        constants' before the fix."""
        import subprocess

        domains = {f"blocked-{i}.example": BlockingResponse(mode="nxdomain") for i in range(100_000)}
        b = _binding("10.0.1.0/24", "p1", blocked_domains=domains)
        text = compile_multi_policy_dnsdist_config("127.0.0.1:5300", [b], blocked_domains_data_dir=tmp_path)
        conf = tmp_path / "dnsdist.conf"
        conf.write_text(text)
        result = subprocess.run(["dnsdist", "--check-config", "-C", str(conf)], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr


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

    def test_doh_listener_wired_and_passes_real_check_config(self, tmp_path):
        import subprocess

        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        doh = DohConfig(enabled=True, port=15357, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15358", [b1], doh=doh)
        assert 'addDOHLocal("127.0.0.1:15357"' in text
        assert '"/dns-query"' in text
        conf_path = tmp_path / "c2.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_doh_listener_omitted_when_disabled(self):
        b1 = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15359", [b1], doh=DohConfig(enabled=False, port=443, cert_path="x", key_path="y")
        )
        assert "addDOHLocal" not in text

    def test_doh_and_dot_can_both_be_enabled_simultaneously(self, tmp_path):
        import subprocess

        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        dot = DotConfig(enabled=True, port=15360, cert_path=str(cert_path), key_path=str(key_path))
        doh = DohConfig(enabled=True, port=15361, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15362", [b1], dot=dot, doh=doh)
        assert 'addTLSLocal("127.0.0.1:15360"' in text
        assert 'addDOHLocal("127.0.0.1:15361"' in text
        conf_path = tmp_path / "c3.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_doq_listener_wired_and_passes_real_check_config(self, tmp_path):
        # Real defect this closes (docs/v2/encrypted-transport-parity-gap.md):
        # DoQ was entirely absent from V2's real config generation.
        # Confirmed this exact real installed dnsdist build supports QUIC
        # (`dnsdist --version` lists dns-over-quic) -- if it hadn't, the
        # generated alderpointdnsv2SafeCapabilityCall wrapper (ported from
        # V1's own real, production-proven fallback) would print a skip
        # message and validate cleanly anyway rather than crash.
        import subprocess

        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        doq = DoqConfig(enabled=True, port=15363, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15364", [b1], doq=doq)
        assert "addDOQLocal" in text
        assert 'congestionControlAlgo="cubic"' in text
        conf_path = tmp_path / "c4.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_doq_listener_omitted_when_disabled(self):
        b1 = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15365", [b1], doq=DoqConfig(enabled=False, port=853, cert_path="x", key_path="y")
        )
        assert "addDOQLocal" not in text

    def test_all_three_dot_doh_doq_enabled_simultaneously(self, tmp_path):
        import subprocess

        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        dot = DotConfig(enabled=True, port=15366, cert_path=str(cert_path), key_path=str(key_path))
        doh = DohConfig(enabled=True, port=15367, cert_path=str(cert_path), key_path=str(key_path))
        doq = DoqConfig(enabled=True, port=15368, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15369", [b1], dot=dot, doh=doh, doq=doq)
        conf_path = tmp_path / "c5.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_doh3_listener_wired_and_passes_real_check_config(self, tmp_path):
        # Real defect this closes (docs/v2/encrypted-transport-parity-gap.md
        # / docs/v2/doh3-transport-implemented.md): DoH3 was entirely
        # absent from V2's real config generation, the last QUIC-dependent
        # row of the confirmed mandatory-parity gap alongside DoQ. This
        # dev host has the real PowerDNS-repo dnsdist 2.1.1 build
        # installed (`dnsdist --version` lists dns-over-http3) -- if it
        # hadn't, the generated alderpointdnsv2SafeCapabilityCall wrapper
        # would print a skip message and validate cleanly anyway rather
        # than crash, same as DoQ.
        import subprocess

        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        doh3 = Doh3Config(enabled=True, port=15370, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15371", [b1], doh3=doh3)
        assert "addDOH3Local" in text
        conf_path = tmp_path / "c6.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_doh3_listener_omitted_when_disabled(self):
        b1 = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15372", [b1], doh3=Doh3Config(enabled=False, port=443, cert_path="x", key_path="y")
        )
        assert "addDOH3Local" not in text

    def test_doh3_advertised_via_alt_svc_on_doh_listener_when_both_enabled(self, tmp_path):
        # Ported behavior from V1's own real, production-proven
        # packaging/dnsdist.conf "doh-altsvc" managed block: when DoH3 is
        # enabled, the plain DoH (HTTP/1.1/2) listener advertises the
        # HTTP/3 upgrade via the standard Alt-Svc response header
        # (RFC 7838) so real clients can discover and use it.
        import subprocess

        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        doh = DohConfig(enabled=True, port=15373, cert_path=str(cert_path), key_path=str(key_path))
        doh3 = Doh3Config(enabled=True, port=15373, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15374", [b1], doh=doh, doh3=doh3)
        assert 'customResponseHeaders={["alt-svc"]="h3=\\":15373\\"; ma=86400"}' in text
        conf_path = tmp_path / "c7.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_no_alt_svc_header_when_doh3_disabled(self, tmp_path):
        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        doh = DohConfig(enabled=True, port=15375, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15376", [b1], doh=doh)
        assert "alt-svc" not in text

    def test_all_four_encrypted_transports_enabled_simultaneously(self, tmp_path):
        import subprocess

        cert_path, key_path = _self_signed_cert(tmp_path)
        b1 = _binding("10.0.1.0/24", "p1")
        dot = DotConfig(enabled=True, port=15377, cert_path=str(cert_path), key_path=str(key_path))
        doh = DohConfig(enabled=True, port=15378, cert_path=str(cert_path), key_path=str(key_path))
        doq = DoqConfig(enabled=True, port=15379, cert_path=str(cert_path), key_path=str(key_path))
        doh3 = Doh3Config(enabled=True, port=15380, cert_path=str(cert_path), key_path=str(key_path))
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15381", [b1], dot=dot, doh=doh, doq=doq, doh3=doh3
        )
        conf_path = tmp_path / "c8.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_dnscrypt_listener_wired_and_passes_real_check_config(self, tmp_path):
        # Real defect this closes (docs/v2/encrypted-transport-parity-
        # gap.md / docs/v2/dnscrypt-transport-implemented.md): DNSCrypt
        # was the last unimplemented row. Uses real dnsdist-generated key
        # material (app/v2/dnscrypt_provisioning.py), not synthetic
        # bytes -- a malformed cert would be rejected by real
        # --check-config, the same rigor every other transport here uses.
        import subprocess
        import time

        from app.v2 import dnscrypt_provisioning as prov

        _, provider_priv = prov.generate_provider_keypair()
        now = int(time.time())
        cert, resolver_key = prov.generate_resolver_certificate(
            provider_priv, serial=1, valid_from=now, valid_until=now + 365 * 86400
        )
        cert_path = tmp_path / "dnscrypt-resolver.cert"
        key_path = tmp_path / "dnscrypt-resolver.key"
        cert_path.write_bytes(cert)
        key_path.write_bytes(resolver_key)

        b1 = _binding("10.0.1.0/24", "p1")
        dnscrypt = DnscryptConfig(
            enabled=True, port=15382, provider_name="2.dnscrypt-cert.pytest.local.",
            cert_path=str(cert_path), key_path=str(key_path),
        )
        text = compile_multi_policy_dnsdist_config("127.0.0.1:15383", [b1], dnscrypt=dnscrypt)
        assert "addDNSCryptBind" in text
        conf_path = tmp_path / "c9.conf"
        conf_path.write_text(text)
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stderr

    def test_dnscrypt_listener_omitted_when_disabled(self):
        b1 = _binding("10.0.1.0/24", "p1")
        text = compile_multi_policy_dnsdist_config(
            "127.0.0.1:15384", [b1],
            dnscrypt=DnscryptConfig(enabled=False, port=5443, provider_name="x", cert_path="x", key_path="y"),
        )
        assert "addDNSCryptBind" not in text


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
