import shutil

import pytest

from app.v2.bind_rpz_gen import (
    BindRpzGenError,
    render_rpz_zone,
    stage_and_validate_rpz_zone,
)
from app.v2.blocking_response import BlockingResponse
from app.v2.runtime_staging import ValidationFailedError

NAMED_CHECKZONE_INSTALLED = shutil.which("named-checkzone") is not None


class TestRendering:
    def test_deterministic_given_explicit_serial(self):
        a = render_rpz_zone({"bad.example": BlockingResponse(mode="nxdomain")}, [], serial=1)
        b = render_rpz_zone({"bad.example": BlockingResponse(mode="nxdomain")}, [], serial=1)
        assert a == b

    def test_allow_overrides_block_for_same_domain(self):
        zone = render_rpz_zone(
            {"good.example": BlockingResponse(mode="nxdomain")},
            allowed_domains=["good.example"],
            serial=1,
        )
        assert "good.example CNAME rpz-passthru." in zone
        assert "good.example CNAME .\n" not in zone

    def test_empty_domain_rejected(self):
        with pytest.raises(BindRpzGenError):
            render_rpz_zone({"": BlockingResponse(mode="nxdomain")}, [], serial=1)

    def test_multiple_modes_all_present(self):
        zone = render_rpz_zone(
            {
                "a.example": BlockingResponse(mode="nxdomain"),
                "b.example": BlockingResponse(mode="null_ip"),
                "c.example": BlockingResponse(mode="custom_ip", custom_ipv4="9.9.9.9"),
                "d.example": BlockingResponse(mode="refused"),
            },
            [],
            serial=1,
        )
        assert "a.example CNAME .\n" in zone
        assert "b.example A 0.0.0.0" in zone
        assert "c.example A 9.9.9.9" in zone
        assert "d.example CNAME rpz-drop." in zone


@pytest.mark.skipif(not NAMED_CHECKZONE_INSTALLED, reason="named-checkzone not installed")
class TestRealValidation:
    def test_generated_zone_passes_real_named_checkzone(self, tmp_path):
        zone = render_rpz_zone(
            {
                "bad.example": BlockingResponse(mode="nxdomain"),
                "ads.example": BlockingResponse(mode="null_ip"),
            },
            allowed_domains=["good.bad.example"],
            serial=1,
        )
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "zone.rpz"
        result = stage_and_validate_rpz_zone(staging, zone, live)
        assert result.promoted
        assert result.validation.ok

    def test_malformed_zone_fails_and_never_promotes(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "zone.rpz"
        with pytest.raises(ValidationFailedError):
            stage_and_validate_rpz_zone(staging, "this is not a valid zone file\n", live)
        assert not live.exists()

    def test_isolated_from_live_bind_paths(self):
        zone = render_rpz_zone({"x.example": BlockingResponse(mode="nxdomain")}, [], serial=1)
        assert "/etc/bind" not in zone
        assert "/var/lib/alderpointdns" not in zone
