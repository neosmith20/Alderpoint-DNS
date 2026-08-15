import shutil

import pytest

from app.v2.local_dns_gen import (
    LocalDnsGenError,
    LocalDnsRecord,
    render_local_dns_zone,
    stage_and_validate_local_dns_zone,
)
from app.v2.runtime_staging import ValidationFailedError

NAMED_CHECKZONE_INSTALLED = shutil.which("named-checkzone") is not None


class TestValidation:
    def test_invalid_record_type_rejected(self):
        with pytest.raises(LocalDnsGenError):
            LocalDnsRecord("host.lan", "MX", "10 mail.lan")

    def test_invalid_ipv4_rejected(self):
        with pytest.raises(LocalDnsGenError):
            LocalDnsRecord("host.lan", "A", "999.1.1.1")

    def test_invalid_ipv6_rejected(self):
        with pytest.raises(LocalDnsGenError):
            LocalDnsRecord("host.lan", "AAAA", "not-ipv6")

    def test_empty_fqdn_rejected(self):
        with pytest.raises(LocalDnsGenError):
            LocalDnsRecord("", "A", "10.0.0.1")


class TestRendering:
    def test_deterministic(self):
        recs = [LocalDnsRecord("host1.lan", "A", "10.0.0.1")]
        a = render_local_dns_zone(recs, serial=1)
        b = render_local_dns_zone(recs, serial=1)
        assert a == b

    def test_duplicate_record_deduplicated(self):
        recs = [
            LocalDnsRecord("host1.lan", "A", "10.0.0.1"),
            LocalDnsRecord("host1.lan", "A", "10.0.0.1"),
        ]
        zone = render_local_dns_zone(recs, serial=1)
        assert zone.count("host1.lan.") == 1

    def test_cname_target_gets_trailing_dot(self):
        recs = [LocalDnsRecord("alias.lan", "CNAME", "host1.lan")]
        zone = render_local_dns_zone(recs, serial=1)
        assert "CNAME host1.lan." in zone

    def test_multiple_a_records_same_name_allowed(self):
        recs = [
            LocalDnsRecord("host.lan", "A", "10.0.0.1"),
            LocalDnsRecord("host.lan", "A", "10.0.0.2"),
        ]
        zone = render_local_dns_zone(recs, serial=1)
        assert "10.0.0.1" in zone and "10.0.0.2" in zone


@pytest.mark.skipif(not NAMED_CHECKZONE_INSTALLED, reason="named-checkzone not installed")
class TestRealValidation:
    def test_generated_zone_passes_real_named_checkzone(self, tmp_path):
        recs = [
            LocalDnsRecord("host1.lan", "A", "10.0.0.5"),
            LocalDnsRecord("host2.lan", "AAAA", "fe80::1"),
            LocalDnsRecord("alias.lan", "CNAME", "host1.lan"),
        ]
        zone = render_local_dns_zone(recs, serial=1)
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "local.zone"
        result = stage_and_validate_local_dns_zone(staging, zone, live)
        assert result.promoted

    def test_malformed_zone_fails_and_never_promotes(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "local.zone"
        with pytest.raises(ValidationFailedError):
            stage_and_validate_local_dns_zone(staging, "not a valid zone {{{\n", live)
        assert not live.exists()
