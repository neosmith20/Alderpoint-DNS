import pytest

from app.v2.cache_profile import compile_profile
from app.v2.policy_compiler import (
    compile_cache_profile,
    compile_effective_policy,
    to_cache_dimensions,
)
from app.v2.policy_model import GroupPolicy, InvalidPolicyError, PolicyLayer


class TestPrecedenceBasics:
    def test_global_only(self):
        policy = compile_effective_policy(PolicyLayer(safesearch_mode="moderate"))
        assert policy.safesearch_mode == "moderate"
        assert policy.filtering_profile_id == "default"  # untouched -> default

    def test_client_overrides_global(self):
        policy = compile_effective_policy(
            PolicyLayer(safesearch_mode="off"),
            client_layer=PolicyLayer(safesearch_mode="strict"),
        )
        assert policy.safesearch_mode == "strict"

    def test_network_overrides_global_but_not_client(self):
        policy = compile_effective_policy(
            PolicyLayer(safesearch_mode="off"),
            network_layer=PolicyLayer(safesearch_mode="moderate"),
            network_source="lan",
            client_layer=PolicyLayer(safesearch_mode="strict"),
        )
        assert policy.safesearch_mode == "strict"

    def test_group_overrides_network(self):
        policy = compile_effective_policy(
            PolicyLayer(safesearch_mode="off"),
            network_layer=PolicyLayer(safesearch_mode="moderate"),
            network_source="lan",
            groups=[
                GroupPolicy("g1", "Kids", 10, PolicyLayer(safesearch_mode="strict")),
            ],
        )
        assert policy.safesearch_mode == "strict"

    def test_unset_field_falls_through_to_default(self):
        policy = compile_effective_policy(PolicyLayer())
        assert policy.blocking_response_mode == "nxdomain"
        assert policy.query_log_enabled is True


class TestGroupConflictResolution:
    def test_higher_priority_group_wins(self):
        low = GroupPolicy("g1", "Guests", 1, PolicyLayer(safesearch_mode="moderate"))
        high = GroupPolicy("g2", "Kids", 10, PolicyLayer(safesearch_mode="strict"))
        # order shouldn't matter -- pass reversed
        policy = compile_effective_policy(PolicyLayer(), groups=[high, low])
        assert policy.safesearch_mode == "strict"

    def test_equal_priority_tiebreaks_on_group_id(self):
        a = GroupPolicy("aaa", "A", 5, PolicyLayer(safesearch_mode="moderate"))
        z = GroupPolicy("zzz", "Z", 5, PolicyLayer(safesearch_mode="strict"))
        policy = compile_effective_policy(PolicyLayer(), groups=[a, z])
        assert policy.safesearch_mode == "strict"  # 'zzz' > 'aaa' lexically

    def test_duplicate_group_id_rejected(self):
        a = GroupPolicy("g1", "A", 1, PolicyLayer())
        b = GroupPolicy("g1", "B", 2, PolicyLayer())
        with pytest.raises(InvalidPolicyError):
            compile_effective_policy(PolicyLayer(), groups=[a, b])

    def test_non_conflicting_fields_from_different_groups_both_apply(self):
        g1 = GroupPolicy("g1", "A", 1, PolicyLayer(safesearch_mode="strict"))
        g2 = GroupPolicy("g2", "B", 2, PolicyLayer(ecs_mode="disabled"))
        policy = compile_effective_policy(PolicyLayer(), groups=[g1, g2])
        assert policy.safesearch_mode == "strict"
        assert policy.ecs_mode == "disabled"


class TestScheduleOverride:
    def test_schedule_applies_only_when_active(self):
        base = compile_effective_policy(
            PolicyLayer(blocking_response_mode="nxdomain"),
            client_layer=PolicyLayer(safesearch_mode="off"),
            schedule_layer=PolicyLayer(safesearch_mode="strict"),
            schedule_id="bedtime",
            schedule_active=False,
        )
        assert base.safesearch_mode == "off"
        assert base.schedule_active is None

        during = compile_effective_policy(
            PolicyLayer(blocking_response_mode="nxdomain"),
            client_layer=PolicyLayer(safesearch_mode="off"),
            schedule_layer=PolicyLayer(safesearch_mode="strict"),
            schedule_id="bedtime",
            schedule_active=True,
        )
        assert during.safesearch_mode == "strict"
        assert during.schedule_active == "bedtime"


class TestDeterminism:
    def test_identical_inputs_produce_identical_output(self):
        def build():
            return compile_effective_policy(
                PolicyLayer(safesearch_mode="off"),
                network_layer=PolicyLayer(ecs_mode="preserve"),
                network_source="lan",
                groups=[GroupPolicy("g1", "Kids", 5, PolicyLayer(safesearch_mode="strict"))],
                client_layer=PolicyLayer(upstream_profile_id="family"),
            )

        a, b = build(), build()
        assert a.values == b.values
        assert a.explain_trace == b.explain_trace


class TestExplainability:
    def test_explain_trace_names_correct_source(self):
        policy = compile_effective_policy(
            PolicyLayer(safesearch_mode="off"),
            groups=[GroupPolicy("g1", "Kids", 5, PolicyLayer(safesearch_mode="strict"))],
            client_layer=PolicyLayer(upstream_profile_id="family"),
        )
        by_field = {e.field: e for e in policy.explain_trace}
        assert by_field["safesearch_mode"].source == "group:Kids"
        assert by_field["upstream_profile_id"].source == "client"
        assert by_field["blocking_response_mode"].source == "default"

    def test_explain_string_has_no_secrets_and_is_readable(self):
        policy = compile_effective_policy(PolicyLayer(safesearch_mode="strict"))
        text = policy.explain()
        assert "safesearch_mode: strict" in text
        assert "secret" not in text.lower()
        assert "password" not in text.lower()


class TestValidation:
    def test_invalid_safesearch_mode_rejected(self):
        with pytest.raises(InvalidPolicyError):
            compile_effective_policy(PolicyLayer(safesearch_mode="nonsense"))

    def test_invalid_blocking_response_mode_rejected(self):
        with pytest.raises(InvalidPolicyError):
            compile_effective_policy(PolicyLayer(blocking_response_mode="teleport"))


class TestCacheProfileIntegration:
    def test_non_answer_fields_never_affect_cache_dimensions(self):
        with_logging = compile_effective_policy(
            PolicyLayer(query_log_enabled=True, statistics_enabled=True)
        )
        without_logging = compile_effective_policy(
            PolicyLayer(query_log_enabled=False, statistics_enabled=False)
        )
        assert to_cache_dimensions(with_logging) == to_cache_dimensions(without_logging)
        assert compile_cache_profile(with_logging).profile_id == compile_cache_profile(
            without_logging
        ).profile_id

    def test_answer_affecting_change_changes_cache_profile(self):
        off = compile_effective_policy(PolicyLayer(safesearch_mode="off"))
        strict = compile_effective_policy(PolicyLayer(safesearch_mode="strict"))
        assert compile_cache_profile(off).profile_id != compile_cache_profile(strict).profile_id

    def test_matches_direct_cache_profile_compile_for_default_policy(self):
        policy = compile_effective_policy(PolicyLayer())
        from app.v2.cache_profile import CachePolicyDimensions

        direct = compile_profile(CachePolicyDimensions())
        assert compile_cache_profile(policy).profile_id == direct.profile_id

    def test_many_clients_same_policy_share_one_cache_profile(self):
        # 50 "different clients" resolving to identical effective policy
        # must all compile to the same cache profile id (no per-client
        # cache fragmentation for identical policy).
        profiles = set()
        for _ in range(50):
            policy = compile_effective_policy(
                PolicyLayer(safesearch_mode="strict"),
                client_layer=PolicyLayer(upstream_profile_id="family"),
            )
            profiles.add(compile_cache_profile(policy).profile_id)
        assert len(profiles) == 1
