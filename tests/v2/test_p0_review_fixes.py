"""Dedicated tests for the three self-identified review risks fixed in
this pass (P0-A/B/C): parental vs malware/security category separation
(covered in test_filtering_decision.py::TestCategoryIndependence), REFUSED
response mode actually returning RCODE REFUSED (not rpz-drop), and
domain-routing precedence being enforced by the generator regardless of
caller input order.
"""

import shutil
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from app.v2.dnsdist_gen import (
    DnsdistGenError,
    generate_dnsdist_config,
    generate_dnsdist_config_from_profiles,
    render_refused_block_rules,
)
from app.v2.policy_store import UpstreamEndpointRecord, UpstreamProfileRecord

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


def _profile(profile_id, *addrs, strategy="ordered"):
    eps = tuple(UpstreamEndpointRecord(a, None, i, 1, None) for i, a in enumerate(addrs))
    return UpstreamProfileRecord(profile_id, "Test", "plain", strategy, eps)


class TestP0BRefusedRendering:
    def test_no_domains_renders_nothing(self):
        assert render_refused_block_rules([]) == ()

    def test_domains_render_rcode_action_not_rpz_drop(self):
        lines = render_refused_block_rules(["blocked.example"])
        directive_lines = [l for l in lines if not l.strip().startswith("--")]
        joined = "\n".join(directive_lines)
        assert "RCodeAction(DNSRCode.REFUSED)" in joined
        assert "rpz-drop" not in joined

    def test_multiple_domains_batched_into_one_rule(self):
        lines = render_refused_block_rules(["a.example", "b.example"])
        joined = "\n".join(lines)
        assert joined.count("RCodeAction(DNSRCode.REFUSED)") == 1
        assert '"a.example."' in joined
        assert '"b.example."' in joined

    def test_wired_into_full_config_generation(self):
        from app.v2.dnsdist_gen import UpstreamServer

        text = generate_dnsdist_config(
            "127.0.0.1:5300", [], [UpstreamServer("p", "1.1.1.1:53")],
            refused_domains=["blocked.example"],
        )
        assert "RCodeAction(DNSRCode.REFUSED)" in text


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist not installed")
class TestP0BRealRcode:
    def test_refused_domain_actually_returns_rcode_refused(self, tmp_path):
        from app.v2.dnsdist_gen import UpstreamServer

        text = generate_dnsdist_config(
            "127.0.0.1:15310", [], [UpstreamServer("p", "1.1.1.1:53")],
            refused_domains=["blocked.example"],
        )
        conf_path = tmp_path / "refused.conf"
        conf_path.write_text(text)
        proc = subprocess.Popen(
            ["dnsdist", "-C", str(conf_path), "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(1.0)

            def query_rcode(qname):
                header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
                qparts = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
                pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                s.sendto(pkt, ("127.0.0.1", 15310))
                data, _ = s.recvfrom(4096)
                s.close()
                return struct.unpack(">H", data[2:4])[0] & 0xF

            assert query_rcode("blocked.example") == 5  # RCODE REFUSED
            assert query_rcode("example.com") == 0  # RCODE NOERROR (unaffected)
        finally:
            proc.terminate()
            proc.wait(timeout=5)


class TestP0CDomainRoutingPrecedence:
    def test_most_specific_suffix_wins_regardless_of_input_order(self):
        default = _profile("default", "1.1.1.1:53")
        broad = _profile("broad", "9.9.9.9:53")
        narrow = _profile("narrow", "8.8.8.8:53")

        # Deliberately shuffled: broad listed AFTER narrow here...
        text_a = generate_dnsdist_config_from_profiles(
            "127.0.0.1:5300", [], default,
            domain_routing=[("example.com", broad), ("corp.example.com", narrow)],
        )
        # ...and reversed here. Output must be identical either way.
        text_b = generate_dnsdist_config_from_profiles(
            "127.0.0.1:5300", [], default,
            domain_routing=[("corp.example.com", narrow), ("example.com", broad)],
        )
        assert text_a == text_b

        # The narrow (more specific) rule must appear before the broad one
        # in the generated file, since dnsdist's PoolAction is terminal and
        # takes the first match in file order.
        narrow_pos = text_a.index("route_narrow")
        broad_pos = text_a.index("route_broad")
        assert narrow_pos < broad_pos

    def test_conflicting_duplicate_suffix_raises(self):
        default = _profile("default", "1.1.1.1:53")
        a = _profile("a", "9.9.9.9:53")
        b = _profile("b", "8.8.8.8:53")
        with pytest.raises(DnsdistGenError):
            generate_dnsdist_config_from_profiles(
                "127.0.0.1:5300", [], default,
                domain_routing=[("dup.example", a), ("dup.example", b)],
            )

    def test_identical_duplicate_suffix_same_profile_is_not_an_error(self):
        default = _profile("default", "1.1.1.1:53")
        a = _profile("a", "9.9.9.9:53")
        # Same suffix listed twice pointing at the same profile is
        # redundant input, not a conflict -- must not raise.
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:5300", [], default,
            domain_routing=[("dup.example", a), ("dup.example", a)],
        )
        assert text.count("route_a") >= 1

    def test_case_and_trailing_dot_normalized_for_conflict_detection(self):
        default = _profile("default", "1.1.1.1:53")
        a = _profile("a", "9.9.9.9:53")
        b = _profile("b", "8.8.8.8:53")
        with pytest.raises(DnsdistGenError):
            generate_dnsdist_config_from_profiles(
                "127.0.0.1:5300", [], default,
                domain_routing=[("Dup.Example.", a), ("dup.example", b)],
            )

    @pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist not installed")
    def test_shuffled_input_still_passes_real_check_config(self, tmp_path):
        from app.v2.dnsdist_gen import stage_and_validate_dnsdist_config

        default = _profile("default", "1.1.1.1:53")
        broad = _profile("broad", "9.9.9.9:53")
        narrow = _profile("narrow", "8.8.8.8:53")
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:15311", [], default,
            domain_routing=[("corp.example.com", narrow), ("example.com", broad)],
        )
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        result = stage_and_validate_dnsdist_config(staging, text, live)
        assert result.promoted
