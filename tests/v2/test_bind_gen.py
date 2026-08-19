"""Real tests for app/v2/bind_gen.py (BIND architecture correction, Gate
#3): generation + validation against the real installed
``named-checkconf`` binary, no mocks -- mirrors the pattern already
proven in tests/v2/test_dnsdist_gen.py and tests/v2/test_bind_rpz_gen.py.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from app.v2 import bind_gen
from app.v2 import bind_rpz_gen

NAMED_CHECKCONF_INSTALLED = shutil.which("named-checkconf") is not None
pytestmark = pytest.mark.skipif(not NAMED_CHECKCONF_INSTALLED, reason="requires named-checkconf")


def _rpz_path(tmp_path: Path) -> Path:
    p = tmp_path / "alderpointdns-v2.rpz"
    p.write_text(bind_rpz_gen.render_rpz_zone({}, [], serial=1))
    return p


class TestRenderNamedConf:
    def test_valid_against_real_named_checkconf(self, tmp_path):
        rpz = _rpz_path(tmp_path)
        conf = bind_gen.render_named_conf(
            ["1.1.1.1:53", "9.9.9.9:53"], str(rpz),
            directory=str(tmp_path), log_path=str(tmp_path / "named.log"),
        )
        conf_path = tmp_path / "named.conf"
        conf_path.write_text(conf)
        result = subprocess.run(["named-checkconf", str(conf_path)], capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr

    def test_deterministic_same_inputs_same_bytes(self, tmp_path):
        rpz = _rpz_path(tmp_path)
        a = bind_gen.render_named_conf(["1.1.1.1:53"], str(rpz), directory=str(tmp_path))
        b = bind_gen.render_named_conf(["1.1.1.1:53"], str(rpz), directory=str(tmp_path))
        assert a == b

    def test_no_forwarders_rejected(self, tmp_path):
        with pytest.raises(bind_gen.BindGenError):
            bind_gen.render_named_conf([], str(_rpz_path(tmp_path)))

    def test_invalid_forwarder_rejected(self, tmp_path):
        with pytest.raises(bind_gen.BindGenError):
            bind_gen.render_named_conf(["not a valid address!"], str(_rpz_path(tmp_path)))

    def test_disjoint_from_v1_ports(self):
        # V1's real installed BIND backend (packaging/named.conf.options,
        # docs/bind-backend.md) uses 5353/5354 -- this module must never
        # collide with it (see this module's own docstring).
        assert bind_gen.BIND_PLAIN_PORT not in (5353, 5354)
        assert bind_gen.BIND_PROXY_PORT not in (5353, 5354)
        assert bind_gen.BIND_PLAIN_PORT != bind_gen.BIND_PROXY_PORT

    def test_forwarders_appear_verbatim(self, tmp_path):
        conf = bind_gen.render_named_conf(["1.2.3.4:53", "5.6.7.8:53"], str(_rpz_path(tmp_path)))
        # Real defect found live (Gate #3 DoH-egress testing): forwarders
        # must always carry an explicit port, not be silently truncated
        # to a bare host (which BIND then defaults to port 53).
        assert "1.2.3.4 port 53; 5.6.7.8 port 53;" in conf

    def test_rpz_zone_referenced(self, tmp_path):
        rpz = _rpz_path(tmp_path)
        conf = bind_gen.render_named_conf(["1.1.1.1:53"], str(rpz))
        assert bind_rpz_gen.RPZ_ZONE_NAME in conf
        assert str(rpz) in conf

    def test_loopback_only_listeners(self, tmp_path):
        conf = bind_gen.render_named_conf(["1.1.1.1:53"], str(_rpz_path(tmp_path)))
        listen_lines = [l for l in conf.splitlines() if l.strip().startswith("listen-on")]
        assert listen_lines
        assert all("127.0.0.1" in l or "::1" in l for l in listen_lines)
        assert not any("0.0.0.0" in l for l in listen_lines)


class TestStageAndValidate:
    def test_promotes_on_success(self, tmp_path):
        rpz = _rpz_path(tmp_path)
        conf = bind_gen.render_named_conf(
            ["1.1.1.1:53"], str(rpz), directory=str(tmp_path), log_path=str(tmp_path / "named.log"),
        )
        live = tmp_path / "live" / "named.conf"
        result = bind_gen.stage_and_validate_named_conf(tmp_path / "staging", conf, live)
        assert result.promoted
        assert live.read_text() == conf

    def test_invalid_config_never_promoted(self, tmp_path):
        from app.v2.runtime_staging import ValidationFailedError

        live = tmp_path / "live" / "named.conf"
        live.parent.mkdir(parents=True)
        live.write_text("-- previous good config --\n")
        with pytest.raises(ValidationFailedError):
            bind_gen.stage_and_validate_named_conf(
                tmp_path / "staging", "options { this is not valid bind syntax", live,
            )
        assert live.read_text() == "-- previous good config --\n"


class TestForwarderPortPreserved:
    """Real defect found live during Gate #3 DoH-egress acceptance
    testing: plain forwarders silently dropped any non-53 port (BIND
    defaults forwarders with no port to 53), masked until a real
    non-standard-port forwarder (the local DoH-egress transport) was
    tested end-to-end."""

    def test_non_standard_port_forwarder_preserved(self, tmp_path):
        rpz = _rpz_path(tmp_path)
        conf = bind_gen.render_named_conf(["127.0.0.1:5653"], str(rpz))
        forwarders_line = next(line for line in conf.splitlines() if line.strip().startswith("forwarders"))
        assert "127.0.0.1 port 5653" in forwarders_line
        assert forwarders_line.strip() != "forwarders { 127.0.0.1; };"  # never silently truncated

    def test_multiple_forwarders_each_keep_own_port(self, tmp_path):
        rpz = _rpz_path(tmp_path)
        conf = bind_gen.render_named_conf(["1.1.1.1:53", "127.0.0.1:5653"], str(rpz))
        assert "1.1.1.1 port 53" in conf
        assert "127.0.0.1 port 5653" in conf


class TestClientAclCoversRealLanRanges:
    """Real defect found live during Gate #3 cross-policy E2E acceptance
    testing: allow-query/allow-query-cache/allow-recursion were
    restricted to loopback, but PROXYv2 (dnsdist -> BIND) deliberately
    forwards the REAL original client address, which BIND then evaluates
    against those same ACLs -- a real LAN client's query through a
    BIND-routed pool was REFUSED the moment PROXYv2 correctly exposed
    its true, non-loopback source address (masked whenever a query
    happened to be answered entirely by dnsdist itself, e.g. a
    SpoofCNAMEAction, without ever reaching BIND)."""

    def test_client_acl_includes_private_lan_ranges(self, tmp_path):
        rpz = _rpz_path(tmp_path)
        conf = bind_gen.render_named_conf(["1.1.1.1:53"], str(rpz))
        acl_block = conf.split('acl "alderpointdns_v2_clients" {')[1].split("};")[0]
        for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            assert net in acl_block, f"{net} missing from BIND client ACL"

    def test_proxy_source_still_restricted_to_loopback(self, tmp_path):
        # allow-proxy/allow-proxy-on (who may SPEAK PROXYv2 to BIND) is a
        # different, correctly-narrower restriction than the client ACL
        # above (whose real identity PROXYv2 then carries) -- must stay
        # loopback-only: only dnsdist itself may use the proxy protocol.
        rpz = _rpz_path(tmp_path)
        conf = bind_gen.render_named_conf(["1.1.1.1:53"], str(rpz))
        proxy_lines = [l for l in conf.splitlines() if l.strip().startswith("allow-proxy")]
        assert len(proxy_lines) == 2
        assert all("127.0.0.1" in l and "10.0.0.0" not in l for l in proxy_lines)
