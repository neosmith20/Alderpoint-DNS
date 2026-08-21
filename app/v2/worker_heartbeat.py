"""Real background-worker liveness/progress tracking (owner-beta aging
hardening, closure item 1).

V2's four periodic background workers (analytics-worker, discovery-worker,
tier-b-worker, schedule-worker -- see ``scripts/v2/alderpointdns_v2_ctl.py``'s
shared ``_run_loop``) each run as their own long-lived systemd unit: the
unit's own process IS the loop, so systemd's own "active (running)" view
answers only "has this process exited", never "is its loop actually still
ticking". That gap is exactly the failure class a real V1.1.1 field report
(days of uptime, UI looks empty, a full restart -- not a targeted one --
fixes it) motivates investigating: V1's analytics ``Collector.run()`` only
ever wrote a heartbeat from its ``writer_loop`` thread (see
``app/analytics.py``'s ``_write_heartbeat``/``_writer_cycle``) -- its
``serve_tcp``/``poll_loop`` threads had no heartbeat and no supervision at
all, so either one dying to an unhandled exception (the realistic
candidate: ``server.accept()`` raising ``OSError`` after days of FD growth)
would silently stop that thread forever while the process, and everything
V1's own health story looked at, stayed "up".

This module is the generalized, tested fix for V2: every ``_run_loop``
iteration writes a small heartbeat record here, both *before* calling
``tick_fn`` (``status="running"``) and *after* it returns or raises
(``status="ok"``/``"tick_failed"``) -- so a tick that hangs forever (blocked
on a lock, a dead upstream socket, whatever) is distinguishable from one
that keeps completing but finds no work, which is in turn distinguishable
from a worker that has actually exited. ``is_stale()`` is the single
predicate a health check (``/api/health``, the soak harness, an operator)
needs: "this worker's process may well still be running, but it has
stopped making progress."
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# The real --interval-seconds each of the four shared-_run_loop workers is
# packaged/invoked with (scripts/v2/alderpointdns_v2_ctl.py's own argparse
# defaults) -- kept here, the one shared module both the health endpoint
# (app/v2/webapp.py) and the soak harness (scripts/v2/soak_harness.py) can
# import, specifically so the two can't silently drift out of sync with
# each other or with the packaged defaults.
WORKER_INTERVALS_SECONDS = {
    "analytics-worker": 15.0,
    "discovery-worker": 15.0,
    "tier-b-worker": 300.0,
    "schedule-worker": 60.0,
}

# A tick that hangs for longer than this (measured from when it started,
# against wall-clock "now") is considered stalled even though no "ok"/
# "tick_failed" heartbeat has been written yet -- this is what actually
# catches a genuinely stuck tick_fn (e.g. blocked forever on a lock),
# as opposed to a merely slow one.
DEFAULT_STALL_GRACE_SECONDS = 120


@dataclass(frozen=True)
class HeartbeatState:
    worker: str
    status: str  # "running" | "ok" | "tick_failed" | "unknown"
    tick_count: int
    tick_started_at: Optional[float]
    last_success_at: Optional[float]
    last_result: Optional[int]
    last_error: Optional[str]

    def is_stale(self, *, interval_seconds: float, now: Optional[float] = None, stall_grace_seconds: float = DEFAULT_STALL_GRACE_SECONDS) -> bool:
        """True when this worker is not making real progress right now.

        Two independent conditions, either one is enough:
        - no heartbeat file at all / unreadable (``status == "unknown"``):
          the worker has never run or its state is unavailable -- treated
          as stale rather than silently reported healthy.
        - the current tick has been running longer than
          ``max(stall_grace_seconds, 3 * interval_seconds)``: a genuinely
          hung tick_fn, not just a slow one.

        A worker sitting in ``status == "ok"`` with a recent
        ``last_success_at`` is never considered stale by wall-clock alone
        -- ticks that legitimately find no work (empty inbox, no due
        schedule) still complete and still count as progress; that is
        different from a tick that never returns.
        """
        now = time.time() if now is None else now
        if self.status == "unknown":
            return True
        grace = max(stall_grace_seconds, 3 * interval_seconds)
        if self.status == "running" and self.tick_started_at is not None:
            if now - self.tick_started_at > grace:
                return True
        # A worker that has never completed a single tick within the grace
        # window (e.g. every tick has failed, or the very first tick is
        # itself hung past the grace window) is also stale.
        if self.last_success_at is None:
            return self.tick_started_at is not None and now - self.tick_started_at > grace
        return now - self.last_success_at > grace


def _heartbeat_path(state_dir: Path, worker: str) -> Path:
    return state_dir / "worker-heartbeats" / f"{worker}.json"


def _atomic_write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp, path)


def record_tick_start(state_dir: Path, worker: str, *, tick_count: int) -> None:
    prior = read_heartbeat(state_dir, worker)
    _atomic_write(
        _heartbeat_path(state_dir, worker),
        {
            "worker": worker,
            "status": "running",
            "tick_count": tick_count,
            "tick_started_at": time.time(),
            "last_success_at": prior.last_success_at if prior else None,
            "last_result": prior.last_result if prior else None,
            "last_error": prior.last_error if prior else None,
        },
    )


def record_tick_success(state_dir: Path, worker: str, *, tick_count: int, result: int) -> None:
    now = time.time()
    _atomic_write(
        _heartbeat_path(state_dir, worker),
        {
            "worker": worker,
            "status": "ok",
            "tick_count": tick_count,
            "tick_started_at": now,
            "last_success_at": now,
            "last_result": result,
            "last_error": None,
        },
    )


def record_tick_failure(state_dir: Path, worker: str, *, tick_count: int, error: str) -> None:
    prior = read_heartbeat(state_dir, worker)
    _atomic_write(
        _heartbeat_path(state_dir, worker),
        {
            "worker": worker,
            "status": "tick_failed",
            "tick_count": tick_count,
            "tick_started_at": prior.tick_started_at if prior else None,
            "last_success_at": prior.last_success_at if prior else None,
            "last_result": prior.last_result if prior else None,
            "last_error": error,
        },
    )


def read_heartbeat(state_dir: Path, worker: str) -> Optional[HeartbeatState]:
    path = _heartbeat_path(state_dir, worker)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return HeartbeatState(
        worker=payload.get("worker", worker),
        status=payload.get("status", "unknown"),
        tick_count=int(payload.get("tick_count", 0)),
        tick_started_at=payload.get("tick_started_at"),
        last_success_at=payload.get("last_success_at"),
        last_result=payload.get("last_result"),
        last_error=payload.get("last_error"),
    )


def unknown(worker: str) -> HeartbeatState:
    return HeartbeatState(
        worker=worker, status="unknown", tick_count=0,
        tick_started_at=None, last_success_at=None, last_result=None, last_error=None,
    )
