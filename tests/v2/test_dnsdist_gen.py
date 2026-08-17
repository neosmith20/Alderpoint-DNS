import shutil

import pytest

from app.v2.dnsdist_gen import (
    DnsdistGenError,
    UpstreamServer,
    generate_dnsdist_config,
    stage_and_validate_dnsdist_config,
)
from app.v2.network_match import NetworkScope
from app.v2.runtime_staging import ValidationFailedError

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


def _acl():
    return [NetworkScope.create("lan", "10.0.0.0/8", "lan-policy")]


def _upstreams():
    return [UpstreamServer("primary", "127.0.0.1:5301")]


class TestGeneration:
    def test_deterministic_output(self):
        a = generate_dnsdist_config("127.0.0.1:5300", _acl(), _upstreams())
        b = generate_dnsdist_config("127.0.0.1:5300", _acl(), _upstreams())
        assert a == b

    def test_requires_at_least_one_upstream(self):
        with pytest.raises(DnsdistGenError):
            generate_dnsdist_config("127.0.0.1:5300", _acl(), [])

    def test_multiple_pools_grouped(self):
        ups = [
            UpstreamServer("a", "127.0.0.1:5301", pool="family"),
            UpstreamServer("b", "127.0.0.1:5302", pool="default"),
        ]
        text = generate_dnsdist_config("127.0.0.1:5300", [], ups)
        assert "family" in text
        assert 'newServer({address="127.0.0.1:5301", {pool="family"}})' in text

    def test_cache_profile_summary_included_as_comment_only(self):
        text = generate_dnsdist_config(
            "127.0.0.1:5300", [], _upstreams(), {"deadbeef": "kids policy"}
        )
        assert "-- " in text
        assert "deadbeef" in text
        assert "kids policy" in text


class TestUpstreamValidation:
    def test_invalid_name_rejected(self):
        with pytest.raises(DnsdistGenError):
            UpstreamServer("bad name!", "127.0.0.1:5301")

    def test_invalid_address_rejected(self):
        with pytest.raises(DnsdistGenError):
            UpstreamServer("primary", "not an address")


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist binary not installed")
class TestRealValidation:
    def test_generated_config_passes_real_dnsdist_check_config(self, tmp_path):
        text = generate_dnsdist_config("127.0.0.1:15300", _acl(), _upstreams())
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        result = stage_and_validate_dnsdist_config(staging, text, live)
        assert result.promoted
        assert result.validation.ok
        assert live.read_text() == text

    def test_query_log_remote_logger_wired_and_passes_real_check_config(self, tmp_path):
        # Real regression for the analytics-ingestion gap documented in
        # docs/v2/analytics-ingestion-not-wired-to-live-dns.md: a fresh
        # install must emit a real dnsdist query-log producer from its
        # very first boot (this bootstrap generator), not only after
        # the real per-policy compiler takes over.
        text = generate_dnsdist_config("127.0.0.1:15301", _acl(), _upstreams())
        assert 'newRemoteLogger("127.0.0.1:5391")' in text
        assert "addResponseAction(AllRule(), RemoteLogResponseAction(" in text
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        result = stage_and_validate_dnsdist_config(staging, text, live)
        assert result.promoted
        assert result.validation.ok

    def test_query_log_can_be_disabled(self, tmp_path):
        text = generate_dnsdist_config("127.0.0.1:15302", _acl(), _upstreams(), query_log_address=None)
        assert "RemoteLogger" not in text

    def test_malformed_config_fails_real_check_and_never_promotes(self, tmp_path):
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        with pytest.raises(ValidationFailedError):
            stage_and_validate_dnsdist_config(staging, "this is not valid lua {{{", live)
        assert not live.exists()

    def test_isolated_from_real_dnsdist_service(self, tmp_path):
        # Sanity check this test suite never references the live install
        # paths — proves isolation by construction, not just by convention.
        text = generate_dnsdist_config("127.0.0.1:15300", _acl(), _upstreams())
        assert "/etc/dnsdist" not in text
        assert "/etc/alderpointdns" not in text
