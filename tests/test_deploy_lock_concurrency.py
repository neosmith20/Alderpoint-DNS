#!/usr/bin/env python3
"""Regression coverage for the v1.0.1 RC concurrency incident: real UI use
(several upstream toggles clicked before the previous one's request had
returned) spawned multiple concurrent `alderpointdns_compiler.py deploy
--no-download` processes ("database is locked", "post-deploy upstream
resolution failed", repeated dnsdist restarts).

Exercises `alderpointdns_compiler.deploy_lock()` -- the single global flock()
every runtime-mutating compiler entry point now acquires: the full deploy()
pipeline, protection_enable_reuse(), and the narrower single-stage CLI
deploys (cache-deploy, cache-flush, upstream-deploy, encryption-deploy) that
used to run completely unlocked even though they write the exact same live
BIND/dnsdist runtime files deploy() also writes.

Real concurrent OS-level locking is used here (separate threads, each
opening its own file descriptor on the same lock file) rather than mocking
the lock away: flock() is per open-file-description, not per process, so two
threads each `open()`ing the same path and calling `fcntl.flock(..., LOCK_EX)`
contend exactly the way two separate `alderpointdns_compiler.py` process
invocations would in production.
"""

from __future__ import annotations

import contextlib
import shutil
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import alderpointdns_compiler as compiler  # noqa: E402


class DeployLockConcurrencyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-deploy-lock-test-"))
        self.old_lock = compiler.DEPLOY_LOCK
        compiler.DEPLOY_LOCK = self.tmp / "staging" / "deploy.lock"

    def tearDown(self) -> None:
        compiler.DEPLOY_LOCK = self.old_lock
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _hammer(self, n: int, hold_seconds: float = 0.05) -> tuple[int, list[str]]:
        active = 0
        max_active = 0
        guard = threading.Lock()
        errors: list[str] = []

        def worker() -> None:
            nonlocal active, max_active
            try:
                with compiler.deploy_lock():
                    with guard:
                        active += 1
                        max_active = max(max_active, active)
                    time.sleep(hold_seconds)
                    with guard:
                        active -= 1
            except Exception as exc:  # pragma: no cover - would fail the test below anyway
                errors.append(str(exc))

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        return max_active, errors

    def test_deploy_lock_never_allows_two_concurrent_holders(self) -> None:
        """The required invariant, directly: two full deploy() pipelines (or
        any other deploy_lock() holder) must never mutate runtime
        configuration at the same time."""
        max_active, errors = self._hammer(n=8)
        self.assertEqual(errors, [])
        self.assertEqual(max_active, 1, "two or more deploy_lock() holders were active at once")

    def test_narrow_single_stage_deploys_now_share_the_same_lock(self) -> None:
        """Before this fix, cache-deploy/cache-flush/upstream-deploy/
        encryption-deploy acquired no lock at all standing alone -- only
        deploy() and protection-enable-reuse did. A standalone upstream-only
        or cache-only change could race a concurrent full deploy() at the
        OS-process level and clobber the same live files. _locked() (used by
        every one of those CLI subcommands) must go through the identical
        deploy_lock(), so mixing "full deploy" holders and "narrow deploy"
        holders in the same hammer must still never overlap."""

        active = 0
        max_active = 0
        guard = threading.Lock()
        real_deploy_lock = compiler.deploy_lock

        @contextlib.contextmanager
        def instrumented_lock():
            nonlocal active, max_active
            with real_deploy_lock():
                with guard:
                    active += 1
                    max_active = max(max_active, active)
                time.sleep(0.05)
                try:
                    yield
                finally:
                    with guard:
                        active -= 1

        def full_deploy_holder() -> None:
            # Stands in for deploy()/protection_enable_reuse(), which call
            # deploy_lock() directly.
            with compiler.deploy_lock():
                pass

        def narrow_holder() -> None:
            # Stands in for a standalone cache-deploy/cache-flush/
            # upstream-deploy/encryption-deploy CLI invocation, which goes
            # through _locked().
            compiler._locked(lambda: "ok")

        with mock.patch.object(compiler, "deploy_lock", instrumented_lock):
            threads = [threading.Thread(target=full_deploy_holder) for _ in range(4)]
            threads += [threading.Thread(target=narrow_holder) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

        self.assertEqual(max_active, 1, "a narrow single-stage deploy overlapped a full deploy() holder")


if __name__ == "__main__":
    unittest.main()
