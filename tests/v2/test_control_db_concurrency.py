#!/usr/bin/env python3
"""Real SQLite concurrency regression coverage for the boot-time schema
write-lock contention found live during a real KVM clean-install/reboot
acceptance (see app/v2/control_db.py's own initialize() docstring and
packaging/v2/alderpointdns-v2-state-init.service's own comment for the
full root cause): several V2 worker services each independently call
their own ensure_schema() chain at their own startup, all racing to
start at once at boot -- SQLite allows only one writer at a time, and
this genuinely exceeded the 5s busy_timeout for one real worker on one
real boot.

Every test here uses real sqlite3 connections against a real on-disk
temp file and real OS threads/processes -- no mocking of
sqlite3.OperationalError or of SQLite's own locking behavior.
"""
from __future__ import annotations

import multiprocessing
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import control_db, node_identity, notification_store, observed_clients, policy_store, replication_v2  # noqa: E402


def _worker_ensure_schema(path: str, which: str, results: list, lock: threading.Lock) -> None:
    try:
        if which == "observed_clients":
            observed_clients.ensure_schema(path)
        elif which == "replication_v2":
            replication_v2.ensure_schema(path)
        elif which == "node_identity":
            node_identity.ensure_schema(path)
        elif which == "policy_store":
            policy_store.ensure_schema(path)
        elif which == "notification_store":
            notification_store.ensure_schema(path)
        with lock:
            results.append((which, "ok", None))
    except Exception as exc:  # noqa: BLE001 -- we want to see exactly what escaped
        with lock:
            results.append((which, "error", repr(exc)))


class TestConcurrentSchemaInitialization(unittest.TestCase):
    """A. Start multiple real V2 schema/state consumers simultaneously
    against a fresh control.db -- the real class of contention this
    pass's own real KVM acceptance found live (discovery.service vs.
    whichever other worker held the lock at boot)."""

    def test_concurrent_ensure_schema_from_every_real_caller_never_raises(self):
        callers = [
            "observed_clients",
            "replication_v2",
            "node_identity",
            "policy_store",
            "notification_store",
        ] * 3  # 15 real concurrent callers -- more contention than a real boot ever has
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "control.db")
            results: list = []
            lock = threading.Lock()
            threads = [
                threading.Thread(target=_worker_ensure_schema, args=(path, which, results, lock))
                for which in callers
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            errors = [r for r in results if r[1] == "error"]
            self.assertEqual(
                len(results), len(callers),
                f"not every caller finished: {len(results)}/{len(callers)}",
            )
            self.assertEqual(errors, [], f"real ensure_schema() call(s) raised under real concurrency: {errors}")

            # Schema must be fully, correctly established -- no partial
            # initialization, no missing table, regardless of which
            # caller "won" the race.
            with control_db.connect(path, create_if_missing=False) as conn:
                names = control_db._table_names(conn)
                for expected in ("schema_migrations", "admins", "policies", "clients"):
                    self.assertIn(expected, names)
            with sqlite3.connect(path) as conn:
                for expected_table in (
                    "observed_clients", "replication_peers", "node_identity",
                    "policy_layers", "notification_providers",
                ):
                    row = conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (expected_table,),
                    ).fetchone()
                    self.assertIsNotNone(row, f"expected table {expected_table!r} missing after concurrent init")

    def test_repeated_concurrent_startup_is_deterministic(self):
        """B. Repeated startup-ordering exercise: the same real
        concurrent-init scenario, run several times in a row against
        fresh databases, must succeed cleanly every single time -- not
        "usually," matching this pass's own real KVM acceptance
        standard of zero restarts across every real boot, not an
        average across several."""
        for i in range(5):
            with tempfile.TemporaryDirectory() as td:
                path = str(Path(td) / "control.db")
                results: list = []
                lock = threading.Lock()
                threads = [
                    threading.Thread(target=_worker_ensure_schema, args=(path, which, results, lock))
                    for which in ("observed_clients", "replication_v2", "node_identity")
                ]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=30)
                errors = [r for r in results if r[1] == "error"]
                self.assertEqual(errors, [], f"iteration {i}: real error(s) under concurrency: {errors}")


class TestRealLockPressure(unittest.TestCase):
    """C. Deliberately hold a real SQLite write lock (a real separate
    OS process, not a mock) open across the busy_timeout boundary while
    another real process calls ensure_schema() against the same file,
    proving the real coordination (SQLite's own busy_timeout, plus this
    pass's cheap already-current fast path -- see control_db.py's
    initialize() docstring) behaves correctly under real, deliberate
    contention rather than merely in the lucky-timing common case.
    """

    @staticmethod
    def _hold_write_lock(path: str, hold_seconds: float, ready: "multiprocessing.synchronize.Event") -> None:
        conn = sqlite3.connect(path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS _lock_pressure_marker(id INTEGER)")
        ready.set()
        time.sleep(hold_seconds)
        conn.execute("COMMIT")
        conn.close()

    def test_ensure_schema_waits_out_a_real_held_write_lock_and_succeeds(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "control.db")
            control_db.initialize(path)  # pre-establish the core schema, real fast path applies below

            ready = multiprocessing.Event()
            # Hold the real write lock for less than the real 5s
            # busy_timeout -- a real caller arriving mid-hold must wait
            # it out and still succeed, not fail immediately.
            holder = multiprocessing.Process(target=self._hold_write_lock, args=(path, 2.0, ready))
            holder.start()
            self.assertTrue(ready.wait(timeout=10), "lock-holder process never signalled ready")

            start = time.monotonic()
            try:
                # A real ensure_schema() call from a second, independent
                # process context (this test process) while the lock is
                # genuinely held elsewhere.
                observed_clients.ensure_schema(path)
            finally:
                holder.join(timeout=15)
            elapsed = time.monotonic() - start
            self.assertLess(elapsed, 5.0, "ensure_schema() should not need to wait the full holder duration once the holder commits promptly")

            with sqlite3.connect(path) as conn:
                row = conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='observed_clients'"
                ).fetchone()
                self.assertIsNotNone(row)

    def test_ensure_schema_fails_closed_not_silently_when_lock_exceeds_busy_timeout(self):
        """A real, deliberately excessive hold (well past any reasonable
        busy_timeout) must surface as a real, honest error -- never a
        silent partial/corrupt schema state."""
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td) / "control.db")
            control_db.initialize(path)

            ready = multiprocessing.Event()
            # Longer than control_db.py's own 10s busy_timeout.
            holder = multiprocessing.Process(target=self._hold_write_lock, args=(path, 13.0, ready))
            holder.start()
            self.assertTrue(ready.wait(timeout=10), "lock-holder process never signalled ready")
            try:
                # observed_clients.ensure_schema's own control_db.initialize()
                # fast path will find the schema already current and skip
                # straight to its own INSERT OR IGNORE writes, which will
                # genuinely block on the real held lock -- assert it
                # surfaces as a real sqlite3.OperationalError (busy_timeout
                # exhausted), not a hang or a silent no-op.
                with self.assertRaises(sqlite3.OperationalError):
                    observed_clients.ensure_schema(path)
            finally:
                holder.join(timeout=20)


if __name__ == "__main__":
    unittest.main()
