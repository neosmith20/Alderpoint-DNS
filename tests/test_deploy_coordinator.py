#!/usr/bin/env python3
"""Unit coverage for app.webapp._DeployCoordinator: the in-process
serialize-and-coalesce layer added for the v1.0.1 RC concurrency incident.

alderpointdns_compiler.deploy_lock() (see test_deploy_lock_concurrency.py)
already guarantees two deploy pipelines never mutate runtime config at the
same time -- but on its own that only turns "N concurrent subprocesses" into
"N queued subprocesses run back to back", which is still the "extremely
slow" UI and pile-up of full pipeline runs the incident reported (repeated
dnsdist restarts, long waits, HTTP 400s once a caller's own patience/timeout
was exceeded). _DeployCoordinator is what actually prevents the pile-up: at
most one subprocess spawn happens per burst of overlapping callers, and
every burst collapses to a single trailing run reflecting the final state.
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import webapp  # noqa: E402


class DeployCoordinatorTest(unittest.TestCase):
    def test_sequential_calls_each_run_and_return_their_own_result(self) -> None:
        calls: list[int] = []

        def run_once() -> tuple[int, str]:
            calls.append(1)
            return (0, f"run {len(calls)}")

        coordinator = webapp._DeployCoordinator(run_once)
        self.assertEqual(coordinator.run(), (0, "run 1"))
        self.assertEqual(coordinator.run(), (0, "run 2"))
        self.assertEqual(len(calls), 2)

    def test_overlapping_callers_never_run_concurrently_and_coalesce(self) -> None:
        """N callers arriving while one run is already in flight must not
        each spawn their own subprocess -- they coalesce into at most one
        extra trailing run, and no two runs ever overlap."""
        active = 0
        max_active = 0
        guard = threading.Lock()
        run_count = 0

        def run_once() -> tuple[int, str]:
            nonlocal active, max_active, run_count
            with guard:
                active += 1
                max_active = max(max_active, active)
                run_count += 1
            time.sleep(0.1)
            with guard:
                active -= 1
            return (0, "deployed")

        coordinator = webapp._DeployCoordinator(run_once)
        results: list[tuple[int, str]] = []
        errors: list[BaseException] = []
        result_guard = threading.Lock()

        def caller() -> None:
            try:
                result = coordinator.run()
                with result_guard:
                    results.append(result)
            except BaseException as exc:  # pragma: no cover
                with result_guard:
                    errors.append(exc)

        threads = [threading.Thread(target=caller) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 10, "every caller must still get a result")
        self.assertEqual(max_active, 1, "two runs executed concurrently")
        # The whole point: 10 overlapping callers must not cost 10 full
        # pipeline runs -- at most 2 (the one already running when the burst
        # arrived, plus one coalesced trailing run that picks up everyone
        # who arrived during it).
        self.assertLessEqual(run_count, 2, f"overlapping callers were not coalesced: {run_count} runs for 10 callers")
        self.assertGreaterEqual(run_count, 1)

    def test_busy_message_is_clear_and_never_mentions_sqlite(self) -> None:
        """A caller that times out waiting for an in-flight run must get an
        honest, actionable message -- never a raw sqlite "database is
        locked" error surfacing to the admin."""
        release = threading.Event()
        entered = threading.Event()

        def run_once() -> tuple[int, str]:
            entered.set()
            release.wait(timeout=5)
            return (0, "deployed")

        coordinator = webapp._DeployCoordinator(run_once, wait_timeout=0.1)

        first_result: list[tuple[int, str]] = []

        def first_caller() -> None:
            first_result.append(coordinator.run())

        t = threading.Thread(target=first_caller)
        t.start()
        self.assertTrue(entered.wait(timeout=5))

        with self.assertRaises(RuntimeError) as ctx:
            coordinator.run()
        message = str(ctx.exception).lower()
        self.assertNotIn("database is locked", message)
        self.assertNotIn("sqlite", message)
        self.assertIn("progress", message)

        release.set()
        t.join(timeout=5)
        self.assertEqual(first_result, [(0, "deployed")])

    def test_isolated_call_is_never_delayed_by_min_interval_seconds(self) -> None:
        coordinator = webapp._DeployCoordinator(lambda: (0, "deployed"), min_interval_seconds=1.0)
        start = time.monotonic()
        coordinator.run()
        self.assertLess(time.monotonic() - start, 0.2, "a call with nothing recently run before it must not be rate-limited")

    def test_min_interval_seconds_paces_a_rapid_sequential_burst_and_still_converges(self) -> None:
        """Coordinator-level reproduction of the dns1 defect: a burst of
        calls arriving faster than min_interval_seconds apart -- some
        overlapping, some each starting just as the previous call returns,
        exactly like a real burst of individually-fast HTTP requests --
        must never result in one actual run per call (that's what tripped
        systemd's StartLimitBurst restarting dnsdist live), and whatever
        runs do happen must never be closer together than
        min_interval_seconds."""
        run_times: list[float] = []
        guard = threading.Lock()

        def run_once() -> tuple[int, str]:
            with guard:
                run_times.append(time.monotonic())
            return (0, "deployed")

        coordinator = webapp._DeployCoordinator(run_once, min_interval_seconds=0.3)

        results: list[tuple[int, str]] = []
        errors: list[BaseException] = []
        result_guard = threading.Lock()

        def caller() -> None:
            try:
                result = coordinator.run()
                with result_guard:
                    results.append(result)
            except BaseException as exc:  # pragma: no cover
                with result_guard:
                    errors.append(exc)

        threads = []
        for _ in range(12):
            t = threading.Thread(target=caller)
            t.start()
            threads.append(t)
            time.sleep(0.05)  # faster than min_interval_seconds -- a real rapid-click burst
        for t in threads:
            t.join(timeout=15)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 12, "every caller must still get a result")
        self.assertLess(
            len(run_times), 12,
            f"a rapid burst of 12 calls triggered {len(run_times)} separate runs -- "
            "exactly the pile-up of dnsdist restarts that tripped systemd's StartLimitBurst on dns1",
        )
        for earlier, later in zip(run_times, run_times[1:]):
            self.assertGreaterEqual(later - earlier, 0.3 - 0.02, "two runs happened closer together than min_interval_seconds")

    def test_production_upstream_coordinator_has_restart_rate_limiting_configured(self) -> None:
        """Pins the actual production wiring: if a future change ever drops
        min_interval_seconds back to 0 (or removes it) for the upstream
        deploy coordinator specifically, this fails immediately instead of
        waiting for another live dns1 start-limit-hit to notice."""
        self.assertGreater(
            webapp._upstream_deploy_coordinator._min_interval_seconds, 0.0,
            "the upstream deploy coordinator has no restart-rate limiting -- a burst of "
            "sequential upstream UI changes can trip dnsdist's systemd StartLimitBurst again",
        )

    @staticmethod
    def _would_trip_start_limit(timestamps: list[float], interval: float, burst: int) -> bool:
        """Replicates the conservative (worst-case) reading of systemd's own
        start-rate algorithm: it trips if any `burst` consecutive start
        attempts all fall within `interval` seconds of each other."""
        for i in range(len(timestamps) - burst + 1):
            window = timestamps[i:i + burst]
            if window[-1] - window[0] <= interval:
                return True
        return False

    def test_restart_fallback_pacing_alone_stays_under_dns1s_actual_start_limit(self) -> None:
        """dns1's *actual* installed dnsdist.service policy, confirmed from
        its live systemd unit, is StartLimitBurst=5 within a 60s window --
        not systemd's generic 10s/5 default the first pass at this fix
        assumed. app.upstream_dns.deploy_upstreams() now applies ordinary
        upstream changes to the already-running dnsdist over its console
        without restarting at all (see deploy_upstreams()'s own
        _console_reconcile() docstring for the primary fix); this test
        instead proves the *backstop* -- min_interval_seconds pacing alone,
        with no console reconciliation help at all, exactly the situation
        if every deploy in a burst had to fall back to a real restart --
        still respects dns1's real policy on its own. Scaled down 100x
        (0.6s window instead of 60s, matching ratio for the spacing) to
        keep the test fast while preserving the exact margin the
        production configuration relies on: 16s spacing between restarts
        means 5 restarts span at least 64s, safely over the real 60s
        window on either side of the boundary.

        Calls are made strictly sequentially (each one fully returns before
        the next begins) rather than threaded, because that -- not
        overlapping concurrency -- is exactly what dns1's own incident was:
        ordinary one-after-another HTTP requests, each restarting dnsdist
        in turn."""
        restart_times: list[float] = []

        def run_once() -> tuple[int, str]:
            restart_times.append(time.monotonic())
            return (0, "deployed")

        # Same ratio as production (min_interval_seconds=16 / StartLimitIntervalSec=60),
        # scaled to keep the test fast: 0.16 / 0.6.
        coordinator = webapp._DeployCoordinator(run_once, min_interval_seconds=0.16)

        call_count = 9  # more than dns1's StartLimitBurst=5
        for _ in range(call_count):
            coordinator.run()

        self.assertEqual(len(restart_times), call_count, "sequential calls must never coalesce with nothing else in flight")
        self.assertFalse(
            self._would_trip_start_limit(restart_times, interval=0.6, burst=5),
            f"restart-fallback pacing alone would trip dns1's real StartLimitBurst=5/60s policy: {restart_times}",
        )

    def test_failed_run_reports_nonzero_code_and_output_to_every_coalesced_caller(self) -> None:
        def run_once() -> tuple[int, str]:
            time.sleep(0.05)
            return (1, "post-deploy upstream resolution failed")

        coordinator = webapp._DeployCoordinator(run_once)
        results: list[tuple[int, str]] = []
        result_guard = threading.Lock()

        def caller() -> None:
            result = coordinator.run()
            with result_guard:
                results.append(result)

        threads = [threading.Thread(target=caller) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(len(results), 3)
        for code, out in results:
            self.assertEqual(code, 1)
            self.assertIn("post-deploy upstream resolution failed", out)


if __name__ == "__main__":
    unittest.main()
