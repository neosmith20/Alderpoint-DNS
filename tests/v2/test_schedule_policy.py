from datetime import datetime, timezone

import pytest

from app.v2.schedule_policy import InvalidScheduleError, Schedule, make_window


def _dt(y, m, d, h, mi, tz="UTC"):
    from zoneinfo import ZoneInfo

    return datetime(y, m, d, h, mi, tzinfo=ZoneInfo(tz))


class TestBasicWindow:
    def test_daytime_window_active(self):
        w = make_window("09:00", "17:00", ["mon", "tue", "wed", "thu", "fri"])
        sched = Schedule("work-hours", "UTC", (w,))
        assert sched.is_active(_dt(2026, 8, 17, 10, 0))  # Monday
        assert not sched.is_active(_dt(2026, 8, 17, 18, 0))

    def test_weekday_not_included_inactive(self):
        w = make_window("09:00", "17:00", ["mon"])
        sched = Schedule("mon-only", "UTC", (w,))
        assert not sched.is_active(_dt(2026, 8, 18, 10, 0))  # Tuesday


class TestOvernightWindow:
    def test_overnight_bedtime_active_late_night(self):
        w = make_window("22:00", "06:00", ["fri"])
        sched = Schedule("bedtime", "UTC", (w,))
        # Friday 23:00 -> active (start day, before midnight)
        assert sched.is_active(_dt(2026, 8, 21, 23, 0))  # Friday
        # Saturday 05:00 -> active (tail end, started Friday)
        assert sched.is_active(_dt(2026, 8, 22, 5, 0))  # Saturday
        # Saturday 07:00 -> inactive
        assert not sched.is_active(_dt(2026, 8, 22, 7, 0))
        # Friday 21:00 -> inactive (before window starts)
        assert not sched.is_active(_dt(2026, 8, 21, 21, 0))

    def test_overnight_does_not_leak_to_non_configured_start_day(self):
        w = make_window("22:00", "06:00", ["mon"])
        sched = Schedule("mon-bedtime", "UTC", (w,))
        # Wednesday 01:00 should not be active (only Monday-start configured)
        assert not sched.is_active(_dt(2026, 8, 19, 1, 0))  # Wednesday


class TestMultipleWindows:
    def test_or_semantics_across_windows(self):
        weeknight = make_window("21:00", "06:00", ["sun", "mon", "tue", "wed", "thu"])
        weekend = make_window("23:00", "08:00", ["fri", "sat"])
        sched = Schedule("bedtime", "UTC", (weeknight, weekend))
        assert sched.is_active(_dt(2026, 8, 17, 22, 0))  # Monday night, weeknight window
        assert sched.is_active(_dt(2026, 8, 21, 23, 30))  # Friday night, weekend window
        assert not sched.is_active(_dt(2026, 8, 21, 22, 0))  # Friday 22:00 - not yet 23:00


class TestDSTBoundaries:
    def test_us_spring_forward_wallclock_window_holds(self):
        # 2026-03-08 is US spring-forward (2am -> 3am) in America/New_York.
        w = make_window("22:00", "06:00", ["sat"])
        sched = Schedule("bedtime", "America/New_York", (w,))
        from zoneinfo import ZoneInfo

        # Saturday 23:00 local, before the transition night -> active
        local_active = datetime(2026, 3, 7, 23, 0, tzinfo=ZoneInfo("America/New_York"))
        assert sched.is_active(local_active.astimezone(timezone.utc))
        # Sunday 05:00 local (after spring-forward jump) still within the
        # overnight window on the wall clock, despite the UTC offset change.
        local_tail = datetime(2026, 3, 8, 5, 0, tzinfo=ZoneInfo("America/New_York"))
        assert sched.is_active(local_tail.astimezone(timezone.utc))

    def test_us_fall_back_wallclock_window_holds(self):
        # 2026-11-01 is US fall-back in America/New_York.
        from zoneinfo import ZoneInfo

        w = make_window("22:00", "06:00", ["sat"])
        sched = Schedule("bedtime", "America/New_York", (w,))
        local_tail = datetime(2026, 11, 1, 5, 30, tzinfo=ZoneInfo("America/New_York"))
        assert sched.is_active(local_tail.astimezone(timezone.utc))


class TestNextTransition:
    def test_next_transition_from_inactive_to_active(self):
        w = make_window("22:00", "23:00", ["mon"])
        sched = Schedule("short", "UTC", (w,))
        start = _dt(2026, 8, 17, 21, 0)  # Monday 21:00, inactive
        nxt = sched.next_transition(start)
        assert nxt.hour == 22 and nxt.minute == 0

    def test_next_transition_from_active_to_inactive(self):
        w = make_window("22:00", "23:00", ["mon"])
        sched = Schedule("short", "UTC", (w,))
        start = _dt(2026, 8, 17, 22, 30)
        nxt = sched.next_transition(start)
        assert nxt.hour == 23 and nxt.minute == 0

    def test_next_transition_bounded_horizon_raises_for_impossible_schedule(self):
        # A window whose weekday never recurs within a short horizon relative
        # to an already-active state that never ends is not realistic for a
        # real schedule, so instead prove the horizon bound itself using a
        # schedule that's permanently inactive far beyond the horizon.
        w = make_window("22:00", "23:00", ["mon"])
        sched = Schedule("short", "UTC", (w,))
        start = _dt(2026, 8, 17, 21, 0)
        # With a 0-day horizon there's no room to find Monday 22:00 again
        # if start is already past all transitions within the window.
        with pytest.raises(InvalidScheduleError):
            sched.next_transition(start, horizon_days=0)


class TestValidation:
    def test_invalid_time_format_rejected(self):
        with pytest.raises(InvalidScheduleError):
            make_window("22h00", "06:00", ["mon"])

    def test_empty_weekdays_rejected(self):
        with pytest.raises(InvalidScheduleError):
            make_window("22:00", "06:00", [])

    def test_invalid_weekday_rejected(self):
        with pytest.raises(InvalidScheduleError):
            make_window("22:00", "06:00", ["someday"])

    def test_zero_length_window_rejected(self):
        with pytest.raises(InvalidScheduleError):
            make_window("22:00", "22:00", ["mon"])

    def test_invalid_timezone_rejected(self):
        w = make_window("22:00", "06:00", ["mon"])
        sched = Schedule("bad-tz", "Not/AZone", (w,))
        with pytest.raises(InvalidScheduleError):
            sched.is_active(_dt(2026, 8, 17, 22, 0))

    def test_naive_datetime_rejected(self):
        w = make_window("22:00", "06:00", ["mon"])
        sched = Schedule("bedtime", "UTC", (w,))
        with pytest.raises(InvalidScheduleError):
            sched.is_active(datetime(2026, 8, 17, 22, 0))
