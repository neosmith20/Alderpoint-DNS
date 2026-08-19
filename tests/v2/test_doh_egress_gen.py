"""app/v2/doh_egress_gen.py: the local DoH-egress transport that
preserves the locked BIND recursive-cache tier for DoH upstream
selections (Gate #3 acceptance closure #4 -- BIND has no native
DoH-forwarder capability at all)."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from app.v2 import doh_egress_gen as deg

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None
pytestmark = pytest.mark.skipif(not DNSDIST_INSTALLED, reason="requires dnsdist")


class TestAllocation:
    def test_deterministic(self):
        a = deg.allocate_doh_egress_contexts([("1.1.1.1:443", "/dns-query", "cloudflare-dns.com")])
        b = deg.allocate_doh_egress_contexts([("1.1.1.1:443", "/dns-query", "cloudflare-dns.com")])
        assert [(c.name, c.listen_port) for c in a] == [(c.name, c.listen_port) for c in b]

    def test_bounded(self):
        many = [(f"10.0.0.{i}:443", "/dns-query", f"h{i}.test") for i in range(deg.MAX_DOH_EGRESS_CONTEXTS + 3)]
        assert len(deg.allocate_doh_egress_contexts(many)) == deg.MAX_DOH_EGRESS_CONTEXTS

    def test_ports_disjoint_from_bind_ports(self):
        from app.v2 import bind_gen

        ctxs = deg.allocate_doh_egress_contexts([("1.1.1.1:443", "/p", "h.test")])
        assert ctxs[0].listen_port not in (bind_gen.BIND_PLAIN_PORT, bind_gen.BIND_PROXY_PORT)


class TestRenderEgressConfig:
    def test_valid_against_real_dnsdist(self, tmp_path):
        ctxs = deg.allocate_doh_egress_contexts([("1.1.1.1:443", "/dns-query", "cloudflare-dns.com")])
        conf_path = tmp_path / "dnsdist.conf"
        conf_path.write_text(deg.render_egress_config(ctxs[0]))
        result = subprocess.run(["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr

    def test_real_doh_backend_syntax_present(self):
        ctxs = deg.allocate_doh_egress_contexts([("1.1.1.1:443", "/dns-query", "cloudflare-dns.com")])
        text = deg.render_egress_config(ctxs[0])
        assert 'tls="openssl"' in text
        assert 'dohPath="/dns-query"' in text
        assert 'subjectName="cloudflare-dns.com"' in text

    def test_no_hostname_rejected(self):
        with pytest.raises(Exception):
            deg.DohEgressContext(name="x", upstream_address="1.1.1.1:443", doh_path="/p", tls_hostname="", listen_port=5653)
