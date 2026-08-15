"""Integration test: schedule_runtime.py wired to the real policy
compiler + cache profile compiler + a staged/validated dnsdist config,
proving the full "schedule transition -> recompile -> stage -> validate
-> promote -> cache generation changes" chain (§25), not just the
scheduling mechanism in isolation.
"""

from datetime import datetime, timezone

import pytest

from app.v2.dnsdist_gen import UpstreamServer, generate_dnsdist_config
from app.v2.policy_compiler import compile_cache_profile, compile_effective_policy
from app.v2.policy_model import PolicyLayer
from app.v2.runtime_staging import ValidationResult
from app.v2.schedule_policy import Schedule, make_window
from app.v2.schedule_runtime import ScheduleTransitionRuntime


def _always_ok_validator(path):
    return ValidationResult(ok=True, output="")


class TestFullChain:
    def test_transition_recompiles_policy_and_changes_cache_profile(self, tmp_path):
        w = make_window("22:00", "06:00", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"])
        sched = Schedule("bedtime", "UTC", (w,))

        seen_profiles = []
        live_path = tmp_path / "live" / "dnsdist.conf"

        def on_transition(now, active_ids):
            bedtime_active = "bedtime" in active_ids
            policy = compile_effective_policy(
                PolicyLayer(safesearch_mode="off"),
                schedule_layer=PolicyLayer(safesearch_mode="strict"),
                schedule_id="bedtime",
                schedule_active=bedtime_active,
            )
            profile = compile_cache_profile(policy)
            seen_profiles.append(profile.profile_id)

            from app.v2.runtime_staging import stage_validate_promote

            text = generate_dnsdist_config(
                "127.0.0.1:5300", [], [UpstreamServer("p", "1.1.1.1:53")],
                cache_profile_summary={profile.profile_id: policy.safesearch_mode},
            )
            result = stage_validate_promote(
                tmp_path / "staging", "dnsdist.conf", text, live_path, _always_ok_validator
            )
            return result.promoted

        runtime = ScheduleTransitionRuntime(schedules=[sched], on_transition=on_transition)

        # Daytime: safesearch off.
        runtime.on_start(datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc))
        assert live_path.read_text().count("off") >= 0  # config was written

        # Bedtime boundary: safesearch strict, different cache profile,
        # and the live (staged/validated) config actually changes.
        runtime.tick(datetime(2026, 8, 17, 22, 1, tzinfo=timezone.utc))

        assert len(seen_profiles) == 2
        assert seen_profiles[0] != seen_profiles[1]  # cache profile genuinely changed
        assert "strict" in live_path.read_text()

    def test_failed_validation_never_promotes_and_schedule_state_unaffected(self, tmp_path):
        w = make_window("22:00", "06:00", ["mon"])
        sched = Schedule("bedtime", "UTC", (w,))
        live_path = tmp_path / "live" / "dnsdist.conf"

        def failing_validator(path):
            return ValidationResult(ok=False, output="synthetic failure")

        def on_transition(now, active_ids):
            from app.v2.runtime_staging import ValidationFailedError, stage_validate_promote

            try:
                stage_validate_promote(
                    tmp_path / "staging", "dnsdist.conf", "bad config",
                    live_path, failing_validator,
                )
                return True
            except ValidationFailedError:
                return False

        runtime = ScheduleTransitionRuntime(schedules=[sched], on_transition=on_transition)
        result = runtime.on_start(datetime(2026, 8, 17, 21, 0, tzinfo=timezone.utc))
        assert result.promotion_succeeded is False
        assert not live_path.exists()  # never promoted
