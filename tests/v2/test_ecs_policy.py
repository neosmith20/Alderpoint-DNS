import shutil

import pytest

from app.v2.dnsdist_gen import generate_dnsdist_config_from_profiles, stage_and_validate_dnsdist_config
from app.v2.ecs_policy import EcsPolicy, InvalidEcsPolicyError, render_dnsdist_directives, server_uses_client_subnet
from app.v2.policy_store import UpstreamEndpointRecord, UpstreamProfileRecord

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


def _profile():
    eps = (UpstreamEndpointRecord("1.1.1.1:53", None, 0, 1, None),)
    return UpstreamProfileRecord("default", "Test", "plain", "ordered", eps)


class TestValidation:
    def test_invalid_mode_rejected(self):
        with pytest.raises(InvalidEcsPolicyError):
            EcsPolicy(mode="leak-everything")

    def test_invalid_prefix_rejected(self):
        with pytest.raises(InvalidEcsPolicyError):
            EcsPolicy(mode="custom", custom_prefix_v4=99)


class TestDirectives:
    def test_disabled_emits_nothing(self):
        assert render_dnsdist_directives(EcsPolicy(mode="disabled")) == ()

    def test_preserve_emits_nothing_globally_but_flags_servers(self):
        policy = EcsPolicy(mode="preserve")
        assert render_dnsdist_directives(policy) == ()
        assert server_uses_client_subnet(policy) is True

    def test_custom_emits_override_directives(self):
        directives = render_dnsdist_directives(EcsPolicy(mode="custom", custom_prefix_v4=20))
        assert any("setECSSourcePrefixV4(20)" in d for d in directives)
        assert any("setECSOverride(true)" in d for d in directives)


class TestGenerationIntegration:
    def test_preserve_sets_use_client_subnet_on_servers(self):
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:5300", [], _profile(), ecs_policy=EcsPolicy(mode="preserve")
        )
        assert "useClientSubnet=true" in text

    def test_disabled_has_no_ecs_directives_at_all(self):
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:5300", [], _profile(), ecs_policy=EcsPolicy(mode="disabled")
        )
        assert "ECS" not in text
        assert "useClientSubnet" not in text


@pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist binary not installed")
class TestRealValidation:
    def test_preserve_mode_passes_real_check_config(self, tmp_path):
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:15303", [], _profile(), ecs_policy=EcsPolicy(mode="preserve")
        )
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        result = stage_and_validate_dnsdist_config(staging, text, live)
        assert result.promoted

    def test_custom_mode_passes_real_check_config(self, tmp_path):
        text = generate_dnsdist_config_from_profiles(
            "127.0.0.1:15304", [], _profile(), ecs_policy=EcsPolicy(mode="custom", custom_prefix_v4=22)
        )
        staging = tmp_path / "staging"
        staging.mkdir()
        live = tmp_path / "live" / "dnsdist.conf"
        result = stage_and_validate_dnsdist_config(staging, text, live)
        assert result.promoted
