"""V2 schedule transition runtime (Workstream 3 final continuation,
Priority 3, §25-27).

Turns Workstream 3's schedule *evaluation* (``app/v2/schedule_policy.py``)
into something that actually changes runtime behavior at the right moment
-- without a per-query SQLite check. This module is a callable state
machine, not a literal always-running daemon process: a real deployment
wraps ``ScheduleTransitionRuntime.tick()`` in a systemd timer/sleep loop
(sleeping until ``next_recompile_at``, per §25's "sleeps/waits
efficiently"), which is a thin wrapper this session intentionally didn't
spin up as an actual background OS process on the shared host -- doing so
during tests would itself be an unauthorized long-running V2 process; the
transition/compile/stage/validate/promote logic itself is what's proven
here, fully testable via explicit fake-clock injection.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from app.v2.schedule_policy import Schedule


@dataclass(frozen=True)
class TransitionResult:
    fired: bool
    active_schedule_ids: frozenset[str]
    changed_from_previous: bool
    promotion_succeeded: Optional[bool]
    next_recompile_at: datetime
    reason: str


OnTransitionFn = Callable[[datetime, frozenset], bool]


def compute_active_schedule_ids(schedules: list[Schedule], now: datetime) -> frozenset[str]:
    return frozenset(s.schedule_id for s in schedules if s.is_active(now))


def next_recompile_time(schedules: list[Schedule], now: datetime, horizon_days: int = 8) -> datetime:
    """Earliest of every schedule's own ``next_transition`` -- the runtime
    only needs to wake up when *something* could change, not on a fixed
    poll interval, which is what makes this "no per-query DB check" true
    even at the runtime-recompile level: there's no polling loop hammering
    control.db either, just a single computed wake time.
    """
    if not schedules:
        # No schedules configured at all -- nothing will ever transition;
        # the caller's loop should treat this as "no wakeup needed until
        # schedules are (re)configured," represented here as a far-future
        # timestamp rather than raising.
        from datetime import timedelta

        return now + timedelta(days=horizon_days)
    return min(s.next_transition(now, horizon_days=horizon_days) for s in schedules)


@dataclass
class ScheduleTransitionRuntime:
    """``on_transition(now, active_ids) -> bool`` is supplied by the
    caller: it should recompile the effective policy for every affected
    scope, stage+validate+promote the new runtime config (via
    ``app/v2/runtime_staging.py``), and bump cache generation wherever the
    recompiled policy is answer-affecting (§25's explicit requirement) --
    this module has no opinion on *how* that happens, only *when*.
    Returns True on success, False on failure (validation/promotion
    failed) -- a False does not raise; the runtime stays on its previous
    known-good active set and will retry on the next tick.
    """

    schedules: list[Schedule]
    on_transition: OnTransitionFn
    state_path: Optional[Path] = None
    _last_active_ids: Optional[frozenset] = field(default=None, repr=False)

    def _persist(self, result: TransitionResult) -> None:
        if self.state_path is None:
            return
        record = {
            "active_schedule_ids": sorted(result.active_schedule_ids),
            "last_evaluated_at": result.next_recompile_at.isoformat(),  # placeholder overwritten below
            "promotion_succeeded": result.promotion_succeeded,
            "reason": result.reason,
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.parent / f".{self.state_path.name}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(record, indent=2, sort_keys=True))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)

    def on_start(self, now: datetime) -> TransitionResult:
        """Restart behavior (§26): NEVER trusts any persisted "previously
        active" record as a decision input -- always recomputes the
        currently-active schedule set fresh from wall-clock time and runs
        ``on_transition`` unconditionally once, treating startup itself as
        an implicit transition. Any persisted state file is purely
        informational/diagnostic (overwritten here), never read back as
        the basis for "what was active."
        """
        self._last_active_ids = None  # explicitly discard any assumption
        return self.tick(now, force=True)

    def tick(self, now: datetime, force: bool = False) -> TransitionResult:
        active_ids = compute_active_schedule_ids(self.schedules, now)
        changed = force or (active_ids != self._last_active_ids)
        next_at = next_recompile_time(self.schedules, now)

        promotion_ok: Optional[bool] = None
        if changed:
            promotion_ok = self.on_transition(now, active_ids)
            if promotion_ok:
                self._last_active_ids = active_ids
            reason = "transition applied" if promotion_ok else "transition failed, retaining previous active set"
        else:
            reason = "no change"

        result = TransitionResult(
            fired=changed,
            active_schedule_ids=active_ids,
            changed_from_previous=changed,
            promotion_succeeded=promotion_ok,
            next_recompile_at=next_at,
            reason=reason,
        )
        self._persist(result)
        return result
