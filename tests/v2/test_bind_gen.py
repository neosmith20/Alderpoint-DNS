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
        assert "1.2.3.4; 5.6.7.8;" in conf

    def test_rpz_zone_referenced(self, tmp_path):
        rpz = _rpz_path(tmp_path)
        conf = bind_gen.render_named_conf(["1.1.1.1:53"], str(rpz))
        assert bind_rpz_gen.RPZ_ZONE_NAME in conf
        assert str(rpz) in conf

    def test_loopback_only_listeners(self, tmp_path):
        conf = bind_gen.render_named_conf(["1.1.1.1:53"], str(_rpz_path(tmp_path)))
        assert "127.0.0.1" in conf
        assert "0.0.0.0" not in conf


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
