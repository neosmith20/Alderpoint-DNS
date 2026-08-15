import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path

import pytest

from app.v2.blocking_response import BlockingResponse
from app.v2.dnsdist_cache_policy import (
    ClientScopedBlockRule,
    render_client_scoped_block_rules,
    render_packet_cache_setup,
)
from app.v2.network_match import NetworkScope

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


def _net(cidr="127.0.0.1/32"):
    return NetworkScope.create("test-net", cidr, "x")


class TestPacketCacheSetup:
    def test_one_cache_per_pool(self):
        lines = render_packet_cache_setup(["", "kids", "guests"])
        joined = "\n".join(lines)
        assert joined.count("newPacketCache") == 3
        assert 'getPool(""):setCache(pc_0)' in joined
        assert 'getPool("kids"):setCache(pc_1)' in joined
        assert 'getPool("guests"):setCache(pc_2)' in joined

    def test_empty_pool_list_produces_nothing(self):
        assert render_packet_cache_setup([]) == ()


class TestClientScopedBlockRendering:
    def test_refused_rule(self):
        rule = ClientScopedBlockRule(_net(), ("bad.example",), BlockingResponse(mode="refused"))
        lines = render_client_scoped_block_rules([rule])
        joined = "\n".join(lines)
        assert "RCodeAction(DNSRCode.REFUSED)" in joined
        assert "NetmaskGroupRule" in joined
        assert "SuffixMatchNodeRule" in joined

    def test_nxdomain_rule(self):
        rule = ClientScopedBlockRule(_net(), ("bad.example",), BlockingResponse(mode="nxdomain"))
        lines = render_client_scoped_block_rules([rule])
        assert "RCodeAction(DNSRCode.NXDOMAIN)" in "\n".join(lines)

    def test_null_ip_rule(self):
        rule = ClientScopedBlockRule(_net(), ("bad.example",), BlockingResponse(mode="null_ip"))
        lines = render_client_scoped_block_rules([rule])
        joined = "\n".join(lines)
        assert 'SpoofAction({"0.0.0.0", "::"})' in joined

    def test_custom_ip_rule(self):
        rule = ClientScopedBlockRule(
            _net(), ("bad.example",), BlockingResponse(mode="custom_ip", custom_ipv4="10.5.5.5")
        )
        lines = render_client_scoped_block_rules([rule])
        assert '"10.5.5.5"' in "\n".join(lines)

    def test_multiple_rules_all_rendered(self):
        rules = [
            ClientScopedBlockRule(_net(), ("a.example",), BlockingResponse(mode="refused")),
            ClientScopedBlockRule(_net(), ("b.example",), BlockingResponse(mode="nxdomain")),
        ]
        lines = render_client_scoped_block_rules(rules)
        joined = "\n".join(lines)
        assert "a.example." in joined
        assert "b.example." in joined


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist not installed")
class TestRealValidationAndBehavior:
    def test_generated_config_with_cache_and_block_rules_validates(self, tmp_path):
        pc_lines = render_packet_cache_setup(["", "kids"])
        rule = ClientScopedBlockRule(_net(), ("bad.example",), BlockingResponse(mode="refused"))
        block_lines = render_client_scoped_block_rules([rule])
        conf = "\n".join(
            [
                'setLocal("127.0.0.1:15320")',
                'newServer({address="1.1.1.1:53"})',
                'newServer({address="9.9.9.9:53", pool="kids"})',
                *block_lines,
                *pc_lines,
            ]
        )
        conf_path = tmp_path / "c.conf"
        conf_path.write_text(conf)
        result = subprocess.run(
            ["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr

    def test_blocked_domain_bypasses_cache_and_returns_real_refused(self, tmp_path):
        net = _net("127.0.0.1/32")
        rule = ClientScopedBlockRule(net, ("blocked.example",), BlockingResponse(mode="refused"))
        block_lines = render_client_scoped_block_rules([rule])
        pc_lines = render_packet_cache_setup([""])
        conf = "\n".join(
            [
                'setLocal("127.0.0.1:15321")',
                'newServer({address="1.1.1.1:53"})',
                *block_lines,
                *pc_lines,
            ]
        )
        conf_path = tmp_path / "c.conf"
        conf_path.write_text(conf)
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
                s.sendto(pkt, ("127.0.0.1", 15321))
                data, _ = s.recvfrom(4096)
                s.close()
                return struct.unpack(">H", data[2:4])[0] & 0xF

            assert query_rcode("blocked.example") == 5  # REFUSED, real, not cached/forwarded
            assert query_rcode("example.com") == 0  # unaffected, resolves normally
        finally:
            proc.terminate()
            proc.wait(timeout=5)


class TestDocumentedArchitectureGap:
    def test_module_docstring_states_the_real_finding(self):
        import app.v2.dnsdist_cache_policy as mod

        assert "not yet differentiated per" in mod.__doc__ or "real finding" in mod.__doc__.lower()
