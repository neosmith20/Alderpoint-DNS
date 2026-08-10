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
