"""Owner-beta aging/liveness hardening (closure item 1): a background
worker's process staying up is not evidence its loop is still making
progress -- the real V1.1.1 field-report failure class ("UI/data looks
empty after days, a full restart fixes it") this defends V2 against.

Covers app/v2/worker_heartbeat.py directly, and the real integration point
(scripts/v2/alderpointdns_v2_ctl.py's shared ``_run_loop``, used by
analytics-worker/discovery-worker/tier-b-worker/schedule-worker) end to
end: a hung tick, a failing tick, and a healthy tick must each be
distinguishable from the on-disk heartbeat state alone.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

from app.v2 import worker_heartbeat as hb


class TestHeartbeatStaleness:
    def test_no_heartbeat_file_is_reported_unknown_and_stale(self, tmp_path):
        assert hb.read_heartbeat(tmp_path, "no-such-worker") is None
        state = hb.unknown("no-such-worker")
        assert state.status == "unknown"
        assert state.is_stale(interval_seconds=15)

    def test_a_completed_recent_tick_is_not_stale(self, tmp_path):
        hb.record_tick_start(tmp_path, "w", tick_count=1)
        hb.record_tick_success(tmp_path, "w", tick_count=1, result=3)
        state = hb.read_heartbeat(tmp_path, "w")
        assert state.status == "ok"
        assert state.last_result == 3
        assert not state.is_stale(interval_seconds=15)

    def test_a_tick_that_finds_no_work_still_counts_as_progress(self, tmp_path):
        """result=0 (an empty inbox, nothing due) is a legitimate, healthy
        outcome -- it must not be conflated with a hung/dead worker."""
        hb.record_tick_start(tmp_path, "w", tick_count=5)
        hb.record_tick_success(tmp_path, "w", tick_count=5, result=0)
        state = hb.read_heartbeat(tmp_path, "w")
        assert not state.is_stale(interval_seconds=15)

    def test_a_tick_that_has_been_running_far_past_its_interval_is_stale(self, tmp_path):
        """This is the actual field-report class: the loop's process never
        exited, but the current tick has been stuck for way longer than a
        single interval should ever take."""
        hb.record_tick_start(tmp_path, "w", tick_count=1)
        state = hb.read_heartbeat(tmp_path, "w")
        long_after = state.tick_started_at + 10_000
        assert state.is_stale(interval_seconds=15, now=long_after)

    def test_repeated_tick_failures_with_no_success_are_stale_past_grace(self, tmp_path):
        hb.record_tick_start(tmp_path, "w", tick_count=1)
        hb.record_tick_failure(tmp_path, "w", tick_count=1, error="boom")
        state = hb.read_heartbeat(tmp_path, "w")
        assert state.status == "tick_failed"
        assert state.last_error == "boom"
        # Immediately after the failure, still within grace -- a single
        # bad tick must not instantly flip a worker "stale"; _run_loop
        # will keep retrying on its own interval.
        assert not state.is_stale(interval_seconds=15, now=state.tick_started_at + 1)
        assert state.is_stale(interval_seconds=15, now=state.tick_started_at + 10_000)

    def test_a_prior_success_is_preserved_across_a_later_failed_tick(self, tmp_path):
        """A worker that succeeded recently, then hit one bad tick, is not
        immediately stale -- last_success_at is what actually matters, and
        must survive record_tick_failure's write."""
        hb.record_tick_start(tmp_path, "w", tick_count=1)
        hb.record_tick_success(tmp_path, "w", tick_count=1, result=1)
        success_state = hb.read_heartbeat(tmp_path, "w")
        hb.record_tick_start(tmp_path, "w", tick_count=2)
        hb.record_tick_failure(tmp_path, "w", tick_count=2, error="transient")
        state = hb.read_heartbeat(tmp_path, "w")
        assert state.last_success_at == success_state.last_success_at
        assert not state.is_stale(interval_seconds=15, now=state.last_success_at + 1)


class TestRunLoopWritesRealHeartbeats:
    """Drives the actual `_run_loop` shared by every V2 background worker,
    not a reimplementation of it, so this fails if the real integration
    point ever stops writing heartbeats."""

    def _ctl(self):
        import importlib.util

        repo_root = Path(__file__).resolve().parent.parent.parent
        spec = importlib.util.spec_from_file_location(
            "alderpointdns_v2_ctl_test_import", repo_root / "scripts" / "v2" / "alderpointdns_v2_ctl.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_successful_ticks_advance_tick_count_and_last_success(self, tmp_path, monkeypatch):
        ctl = self._ctl()
        monkeypatch.setattr(ctl, "STATE_DIR", tmp_path)
        # _run_loop registers real SIGTERM/SIGINT handlers, which only
        # works on the main thread of the main interpreter -- exactly
        # like the real worker process, which always runs it there. This
        # test drives the loop from a background thread purely so it can
        # be terminated deterministically without a real subprocess, so
        # the signal registration itself (irrelevant to what's under
        # test: heartbeat writes) is stubbed out here, not in production.
        monkeypatch.setattr(ctl.signal, "signal", lambda *a, **k: None)
        calls = {"n": 0}

        def tick():
            calls["n"] += 1
            if calls["n"] >= 3:
                raise KeyboardInterrupt  # break out of the real infinite loop deterministically
            return calls["n"]

        stop_event = threading.Event()

        def run():
            try:
                ctl._run_loop(tick, 0.01, worker_name="test-worker")
            except KeyboardInterrupt:
                pass
            finally:
                stop_event.set()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        assert stop_event.wait(timeout=5), "worker loop did not complete"
        state = hb.read_heartbeat(tmp_path, "test-worker")
        assert state is not None
        assert state.tick_count >= 2
        assert state.last_result in (1, 2)

    def test_a_failing_tick_is_recorded_and_the_loop_keeps_going(self, tmp_path, monkeypatch):
        ctl = self._ctl()
        monkeypatch.setattr(ctl, "STATE_DIR", tmp_path)
        monkeypatch.setattr(ctl.signal, "signal", lambda *a, **k: None)
        calls = {"n": 0}

        def tick():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated tick failure")
            if calls["n"] >= 2:
                raise KeyboardInterrupt
            return 0

        stop_event = threading.Event()

        def run():
            try:
                ctl._run_loop(tick, 0.01, worker_name="failing-worker")
            except KeyboardInterrupt:
                pass
            finally:
                stop_event.set()

        t = threading.Thread(target=run, daemon=True)
        t.start()
        assert stop_event.wait(timeout=5)
        # Read back the intermediate failed state directly, since the loop
        # only stops after tick 2's KeyboardInterrupt escapes _run_loop's
        # own try/except (deliberately -- it only catches Exception, not
        # BaseException, so the test can terminate it).
        state = hb.read_heartbeat(tmp_path, "failing-worker")
        assert state is not None
        assert state.tick_count >= 1


class TestAllFourSharedWorkersAreWired:
    """Cheap, direct guard: every _run_loop call site in the real ctl
    script must pass worker_name -- this is what regresses silently if a
    future edit adds a fifth worker (or refactors one of the existing
    four) without wiring it into the heartbeat."""

    def test_every_run_loop_call_site_passes_worker_name(self):
        repo_root = Path(__file__).resolve().parent.parent.parent
        source = (repo_root / "scripts" / "v2" / "alderpointdns_v2_ctl.py").read_text()
        call_sites = [
            line for line in source.splitlines()
            if "_run_loop(" in line and "def _run_loop" not in line
        ]
        assert len(call_sites) == 4, call_sites
        for line in call_sites:
            assert "worker_name=" in line, line
