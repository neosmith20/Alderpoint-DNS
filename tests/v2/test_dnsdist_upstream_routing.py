import shutil

import pytest

from app.v2.dnsdist_gen import (
    DnsdistGenError,
    generate_dnsdist_config_from_profiles,
    stage_and_validate_dnsdist_config,
)
from app.v2.policy_store import UpstreamEndpointRecord, UpstreamProfileRecord
from app.v2.runtime_staging import ValidationFailedError

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


def _profile(strategy="ordered", profile_id="default", *addrs):
    addrs = addrs or ("1.1.1.1:53",)
    eps = tuple(UpstreamEndpointRecord(a, None, i, 1, None) for i, a in enumerate(addrs))
    return UpstreamProfileRecord(profile_id, "Test", "plain", strategy, eps)


class TestGeneration:
    def test_default_profile_compiled(self):
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:5300", [], _profile("ordered")
        )
        assert 'newServer({address="1.1.1.1:53"})' in text
        assert "setServerPolicy(firstAvailable)" in text

    def test_load_balanced_maps_to_least_outstanding(self):
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:5300", [], _profile("load_balanced")
        )
        assert "setServerPolicy(leastOutstanding)" in text

    def test_unsupported_strategy_rejected(self):
        with pytest.raises(DnsdistGenError):
            generate_dnsdist_config_from_profiles(
                "127.0.0.1:5300", [], _profile("parallel_first_success")
            )

    def test_domain_routing_produces_pool_and_rule(self):
        default = _profile("ordered", "default")
        corp = _profile("ordered", "corp", "9.9.9.9:53")
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:5300", [], default, domain_routing=[("corp.example", corp)]
        )
        assert 'pool="route_corp"' in text
        assert 'SuffixMatchNodeRule({"corp.example."})' in text
        assert "PoolAction(\"route_corp\")" in text

    def test_domain_routing_unsupported_strategy_rejected(self):
        default = _profile("ordered")
        bad = _profile("parallel_first_success", "bad", "9.9.9.9:53")
        with pytest.raises(DnsdistGenError):
            generate_dnsdist_config_from_profiles(
                "127.0.0.1:5300", [], default, domain_routing=[("corp.example", bad)]
            )


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist binary not installed")
class TestRealValidation:
    def test_default_only_passes_real_check_config(self, tmp_path):
        text = generate_dnsdist_config_from_profiles("127.0.0.1:15301", [], _profile("ordered"))
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        result = stage_and_validate_dnsdist_config(staging, text, live)
        assert result.promoted

    def test_domain_routing_passes_real_check_config(self, tmp_path):
        default = _profile("ordered", "default")
        corp = _profile("load_balanced", "corp", "9.9.9.9:53", "8.8.8.8:53")
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:15302", [], default, domain_routing=[("corp.example", corp)]
        )
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        result = stage_and_validate_dnsdist_config(staging, text, live)
        assert result.promoted
        assert result.validation.ok
