import pytest

from app.v2.blocking_response import BlockingResponse, InvalidBlockingResponseError, render_rpz_trigger


class TestValidation:
    def test_invalid_mode_rejected(self):
        with pytest.raises(InvalidBlockingResponseError):
            BlockingResponse(mode="teleport")

    def test_custom_ip_requires_an_address(self):
        with pytest.raises(InvalidBlockingResponseError):
            BlockingResponse(mode="custom_ip")

    def test_invalid_custom_ipv4_rejected(self):
        with pytest.raises(InvalidBlockingResponseError):
            BlockingResponse(mode="custom_ip", custom_ipv4="999.999.999.999")

    def test_invalid_custom_ipv6_rejected(self):
        with pytest.raises(InvalidBlockingResponseError):
            BlockingResponse(mode="custom_ip", custom_ipv6="not-an-ipv6")

    def test_custom_ip_fields_rejected_on_non_custom_mode(self):
        with pytest.raises(InvalidBlockingResponseError):
            BlockingResponse(mode="nxdomain", custom_ipv4="1.2.3.4")

    def test_ttl_bounds(self):
        with pytest.raises(InvalidBlockingResponseError):
            BlockingResponse(mode="nxdomain", ttl_seconds=0)
        with pytest.raises(InvalidBlockingResponseError):
            BlockingResponse(mode="nxdomain", ttl_seconds=999999)


class TestRendering:
    def test_nxdomain_renders_cname_dot(self):
        lines = render_rpz_trigger(BlockingResponse(mode="nxdomain"), "bad.example")
        assert "bad.example CNAME ." in lines
        assert "*.bad.example CNAME ." in lines

    def test_null_ip_renders_zero_addresses(self):
        lines = render_rpz_trigger(BlockingResponse(mode="null_ip"), "ads.example")
        assert "ads.example A 0.0.0.0" in lines
        assert "ads.example AAAA ::" in lines

    def test_custom_ip_renders_given_addresses(self):
        resp = BlockingResponse(mode="custom_ip", custom_ipv4="10.0.0.1", custom_ipv6="fe80::1")
        lines = render_rpz_trigger(resp, "blocked.example")
        assert "blocked.example A 10.0.0.1" in lines
        assert "blocked.example AAAA fe80::1" in lines

    def test_refused_uses_rpz_drop_with_documented_limitation(self):
        lines = render_rpz_trigger(BlockingResponse(mode="refused"), "drop.example")
        assert "drop.example CNAME rpz-drop." in lines


class TestCacheProfileInteraction:
    def test_different_modes_are_distinguishable_configs(self):
        nx = render_rpz_trigger(BlockingResponse(mode="nxdomain"), "x.example")
        null_mode = render_rpz_trigger(BlockingResponse(mode="null_ip"), "x.example")
        assert nx != null_mode
