"""V2 schedule/bedtime evaluation (Workstream 3, §15).

Answers "is this schedule active right now" and "when does it next change"
without ever touching SQLite on the DNS hot path: a schedule is a small,
pure, timezone-aware value object; the *policy compiler* decides how often
to recompute which schedules are active (e.g. once a minute, or on a timer
event) and bakes the result into the compiled effective policy it hands to
the runtime — no per-query evaluation, let alone per-query DB lookup.

DST correctness: all evaluation happens in a ``zoneinfo.ZoneInfo`` local
time, comparing local wall-clock time-of-day against configured start/end
times *in that zone* — the wall-clock window (e.g. "22:00-06:00") stays the
same on the calendar even when the UTC offset changes under it during a DST
transition, which is what a human means by "bedtime is 10pm to 6am".
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time as dt_time, timedelta
from zoneinfo import ZoneInfo

# Monday=0 .. Sunday=6, matching datetime.weekday()
_WEEKDAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


class InvalidScheduleError(ValueError):
    pass


@dataclass(frozen=True)
class ScheduleWindow:
    """One recurring window, e.g. "every night 22:00->06:00". ``weekdays``
    is the set of weekdays (0=Mon..6=Sun) the window *starts* on — an
    overnight window starting Friday 22:00 and ending Saturday 06:00 is
    represented as weekday {4} (Friday) with start > end, and the "crosses
    midnight" case is handled explicitly in evaluation, not by requiring
    the caller to split it into two windows.
    """

    start: dt_time
    end: dt_time
    weekdays: frozenset[int]

    def crosses_midnight(self) -> bool:
        return self.end <= self.start

    def _active_for_start_day(self, local_dt: datetime, start_weekday: int) -> bool:
        if start_weekday not in self.weekdays:
            return False
        t = local_dt.time()
        if self.crosses_midnight():
            # Active from `start` to midnight on the start day.
            return t >= self.start
        return self.start <= t < self.end

    def contains(self, local_dt: datetime) -> bool:
        today_wd = local_dt.weekday()
        if self._active_for_start_day(local_dt, today_wd):
            return True
        if self.crosses_midnight():
            # Could also be the tail end (midnight -> `end`) of a window
            # that started yesterday.
            yesterday_wd = (today_wd - 1) % 7
            if yesterday_wd in self.weekdays and local_dt.time() < self.end:
                return True
        return False


def make_window(start: str, end: str, weekdays: list[str]) -> ScheduleWindow:
    def _parse_time(s: str) -> dt_time:
        try:
            h, m = s.split(":")
            return dt_time(int(h), int(m))
        except (ValueError, AttributeError) as exc:
            raise InvalidScheduleError(f"invalid time {s!r}, expected HH:MM") from exc

    wd_set = set()
    for w in weekdays:
        wl = w.strip().lower()[:3]
        if wl not in _WEEKDAY_NAMES:
            raise InvalidScheduleError(f"invalid weekday {w!r}")
        wd_set.add(_WEEKDAY_NAMES.index(wl))
    if not wd_set:
        raise InvalidScheduleError("schedule window requires at least one weekday")
    start_t = _parse_time(start)
    end_t = _parse_time(end)
    if start_t == end_t:
        raise InvalidScheduleError("start and end may not be identical (zero-length window)")
    return ScheduleWindow(start=start_t, end=end_t, weekdays=frozenset(wd_set))


@dataclass(frozen=True)
class Schedule:
    """Multiple windows (e.g. weeknight bedtime + weekend bedtime with
    different times) combine with OR semantics — active if *any* window
    is active.
    """

    schedule_id: str
    timezone: str
    windows: tuple[ScheduleWindow, ...]

    def _zone(self) -> ZoneInfo:
        try:
            return ZoneInfo(self.timezone)
        except Exception as exc:  # noqa: BLE001 - zoneinfo raises varied exc types
            raise InvalidScheduleError(f"invalid timezone {self.timezone!r}: {exc}") from exc

    def is_active(self, at_utc: datetime) -> bool:
        if at_utc.tzinfo is None:
            raise InvalidScheduleError("at_utc must be timezone-aware")
        local = at_utc.astimezone(self._zone())
        return any(w.contains(local) for w in self.windows)

    def next_transition(self, at_utc: datetime, horizon_days: int = 8) -> datetime:
        """Minute-resolution scan for the next state change (active ->
        inactive or vice versa), bounded by ``horizon_days`` so a
        misconfigured/empty schedule can't loop forever. Minute resolution
        is intentionally coarse — this is a compiler-side planning aid
        (when to next recompile), not a hot-path primitive.
        """
        current = self.is_active(at_utc)
        cursor = at_utc
        limit = at_utc + timedelta(days=horizon_days)
        step = timedelta(minutes=1)
        cursor += step
        while cursor <= limit:
            if self.is_active(cursor) != current:
                return cursor
            cursor += step
        raise InvalidScheduleError(
            f"no transition found for schedule {self.schedule_id!r} within {horizon_days} days"
        )
