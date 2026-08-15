from datetime import datetime, timedelta, timezone

import pytest

from app.v2.schedule_policy import Schedule, make_window
from app.v2.schedule_runtime import (
    ScheduleTransitionRuntime,
    compute_active_schedule_ids,
    next_recompile_time,
)


def _bedtime_schedule(schedule_id="bedtime", tz="UTC"):
    w = make_window("22:00", "06:00", ["mon", "tue", "wed", "thu", "fri", "sat", "sun"])
    return Schedule(schedule_id, tz, (w,))


class TestComputeActiveIds:
    def test_active_when_within_window(self):
        sched = _bedtime_schedule()
        now = datetime(2026, 8, 17, 23, 0, tzinfo=timezone.utc)  # Monday 23:00
        assert compute_active_schedule_ids([sched], now) == frozenset({"bedtime"})

    def test_inactive_outside_window(self):
        sched = _bedtime_schedule()
        now = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)
        assert compute_active_schedule_ids([sched], now) == frozenset()

    def test_no_schedules_configured(self):
        assert compute_active_schedule_ids([], datetime.now(timezone.utc)) == frozenset()


class TestNextRecompileTime:
    def test_no_schedules_returns_far_future_not_error(self):
        now = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)
        nxt = next_recompile_time([], now)
        assert nxt > now

    def test_matches_schedule_next_transition(self):
        sched = _bedtime_schedule()
        now = datetime(2026, 8, 17, 21, 0, tzinfo=timezone.utc)
        nxt = next_recompile_time([sched], now)
        assert nxt.hour == 22


class TestRuntimeBasicFlow:
    def test_on_start_always_fires_once(self):
        sched = _bedtime_schedule()
        calls = []

        def on_transition(now, active_ids):
            calls.append(active_ids)
            return True

        runtime = ScheduleTransitionRuntime(schedules=[sched], on_transition=on_transition)
        now = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)  # inactive period
        result = runtime.on_start(now)
        assert result.fired
        assert len(calls) == 1
        assert calls[0] == frozenset()  # correctly inactive at startup

    def test_tick_with_no_change_does_not_fire(self):
        sched = _bedtime_schedule()
        calls = []

        def on_transition(now, active_ids):
            calls.append(active_ids)
            return True

        runtime = ScheduleTransitionRuntime(schedules=[sched], on_transition=on_transition)
        now = datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc)
        runtime.on_start(now)
        result = runtime.tick(now + timedelta(minutes=5))
        assert not result.fired
        assert len(calls) == 1  # only the on_start call

    def test_tick_at_transition_boundary_fires(self):
        sched = _bedtime_schedule()
        calls = []

        def on_transition(now, active_ids):
            calls.append(active_ids)
            return True

        runtime = ScheduleTransitionRuntime(schedules=[sched], on_transition=on_transition)
        start = datetime(2026, 8, 17, 21, 0, tzinfo=timezone.utc)
        runtime.on_start(start)
        result = runtime.tick(datetime(2026, 8, 17, 22, 1, tzinfo=timezone.utc))
        assert result.fired
        assert result.active_schedule_ids == frozenset({"bedtime"})
        assert len(calls) == 2

    def test_failed_promotion_retains_previous_active_set(self):
        sched = _bedtime_schedule()
        outcomes = iter([True, False])  # on_start succeeds, boundary tick fails

        def flaky_transition(now, active_ids):
            return next(outcomes)

        runtime = ScheduleTransitionRuntime(schedules=[sched], on_transition=flaky_transition)
        start = datetime(2026, 8, 17, 21, 0, tzinfo=timezone.utc)
        runtime.on_start(start)  # succeeds, confirms empty active set
        assert runtime._last_active_ids == frozenset()

        result = runtime.tick(datetime(2026, 8, 17, 22, 1, tzinfo=timezone.utc))
        assert result.promotion_succeeded is False
        assert runtime._last_active_ids == frozenset()  # unchanged, still the pre-boundary set


class TestRestartBehavior:
    def test_restart_never_trusts_persisted_state_recomputes_fresh(self, tmp_path):
        sched = _bedtime_schedule()
        state_path = tmp_path / "schedule_state.json"

        def on_transition(now, active_ids):
            return True

        # First "process": starts during the day (inactive).
        runtime1 = ScheduleTransitionRuntime(
            schedules=[sched], on_transition=on_transition, state_path=state_path
        )
        runtime1.on_start(datetime(2026, 8, 17, 12, 0, tzinfo=timezone.utc))
        assert state_path.exists()

        # Simulated crash + restart as a completely fresh runtime object,
        # now during bedtime -- must NOT inherit the stale "inactive"
        # assumption from before the crash; must recompute from wall clock.
        calls = []

        def on_transition2(now, active_ids):
            calls.append(active_ids)
            return True

        runtime2 = ScheduleTransitionRuntime(
            schedules=[sched], on_transition=on_transition2, state_path=state_path
        )
        result = runtime2.on_start(datetime(2026, 8, 17, 23, 0, tzinfo=timezone.utc))
        assert result.fired
        assert calls[0] == frozenset({"bedtime"})  # correct fresh state, not stale


class TestDSTTransitions:
    def test_spring_forward_next_recompile_correct(self):
        from zoneinfo import ZoneInfo

        w = make_window("22:00", "06:00", ["sat"])
        sched = Schedule("bedtime", "America/New_York", (w,))
        now = datetime(2026, 3, 7, 21, 0, tzinfo=ZoneInfo("America/New_York"))
        nxt = next_recompile_time([sched], now.astimezone(timezone.utc))
        assert nxt > now.astimezone(timezone.utc)

    def test_fall_back_transitions_still_fire_exactly_once(self):
        from zoneinfo import ZoneInfo

        w = make_window("22:00", "06:00", ["sat"])
        sched = Schedule("bedtime", "America/New_York", (w,))
        calls = []

        def on_transition(now, active_ids):
            calls.append(active_ids)
            return True

        runtime = ScheduleTransitionRuntime(schedules=[sched], on_transition=on_transition)
        before = datetime(2026, 10, 31, 21, 0, tzinfo=ZoneInfo("America/New_York")).astimezone(timezone.utc)
        runtime.on_start(before)
        during = datetime(2026, 11, 1, 5, 0, tzinfo=ZoneInfo("America/New_York")).astimezone(timezone.utc)
        result = runtime.tick(during)
        assert result.active_schedule_ids == frozenset({"bedtime"})


class TestMultipleSimultaneousSchedules:
    def test_two_schedules_transitioning_together(self):
        w1 = make_window("22:00", "06:00", ["mon"])
        w2 = make_window("22:00", "06:00", ["mon"])
        s1 = Schedule("bedtime-kids", "UTC", (w1,))
        s2 = Schedule("bedtime-guests", "UTC", (w2,))
        calls = []

        def on_transition(now, active_ids):
            calls.append(active_ids)
            return True

        runtime = ScheduleTransitionRuntime(schedules=[s1, s2], on_transition=on_transition)
        runtime.on_start(datetime(2026, 8, 17, 21, 0, tzinfo=timezone.utc))
        result = runtime.tick(datetime(2026, 8, 17, 22, 1, tzinfo=timezone.utc))
        assert result.active_schedule_ids == frozenset({"bedtime-kids", "bedtime-guests"})

    def test_no_op_transition_when_effective_policy_unchanged(self):
        # Two ticks landing in the same active state must not re-fire.
        sched = _bedtime_schedule()
        calls = []

        def on_transition(now, active_ids):
            calls.append(active_ids)
            return True

        runtime = ScheduleTransitionRuntime(schedules=[sched], on_transition=on_transition)
        runtime.on_start(datetime(2026, 8, 17, 23, 0, tzinfo=timezone.utc))
        runtime.tick(datetime(2026, 8, 17, 23, 30, tzinfo=timezone.utc))
        runtime.tick(datetime(2026, 8, 17, 23, 45, tzinfo=timezone.utc))
        assert len(calls) == 1
