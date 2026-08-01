#!/usr/bin/env python3
"""Concurrency coverage for the incident scenario: web requests hitting the
FastAPI app while analytics.Collector's real writer_loop thread is
simultaneously inserting query events and running retention cleanup against
the *same* sqlite database file, with a third thread periodically holding an
exclusive write lock -- real, independent sqlite3 connections genuinely
contending for one file, rather than mocking the lock away.

The lock holds here are short enough (well under every connection's 5s
busy_timeout) that sqlite's own busy-wait absorbs the contention rather than
ever surfacing OperationalError("database is locked") to Python -- this test
is about whole-system stability under realistic concurrent load, not the
retry-on-exhaustion path itself. That path (a lock that outlasts every
retry) is covered deterministically, without any timing dependency, by
test_analytics.py's WriterResilienceTests.

What this test verifies end to end:
  * the writer thread survives concurrent write contention
  * query events keep being committed throughout
  * the writer's health/heartbeat stays accurate
  * the database file itself remains structurally valid afterward
  * concurrent web traffic doesn't accumulate stray fds against the db
"""

from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from fastapi.testclient import TestClient  # noqa: E402

from app import alderpointdns_compiler, analytics, auth, local_dns, webapp  # noqa: E402

INITIAL_PASSWORD = "initial-password-123"


def _open_fds_to(path: Path) -> int:
    targets = {str(path), str(path) + "-wal", str(path) + "-shm", str(path) + "-journal"}
    fd_dir = Path("/proc/self/fd")
    if not fd_dir.is_dir():
        raise unittest.SkipTest("/proc/self/fd is not available on this platform")
    count = 0
    for entry in fd_dir.iterdir():
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if target in targets:
            count += 1
    return count


class WebAnalyticsConcurrencyTest(unittest.TestCase):
    RUN_SECONDS = 2.5
    LOCK_HOLD_SECONDS = 0.3
    LOCK_GAP_SECONDS = 0.05

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-concurrency-test-"))
        db_path = self.tmp / "alderpointdns.db"
        self.db_path = db_path
        self.old_db_paths = {
            webapp: webapp.DB_PATH,
            alderpointdns_compiler: alderpointdns_compiler.DB_PATH,
            analytics: analytics.DB_PATH,
            local_dns: local_dns.DB_PATH,
        }
        for mod in self.old_db_paths:
            mod.DB_PATH = db_path
        self.old_migration_lock = alderpointdns_compiler.MIGRATION_LOCK
        alderpointdns_compiler.MIGRATION_LOCK = self.tmp / "staging" / "schema-migration.lock"
        analytics.SECRET_FILE = self.tmp / "analytics.secret"
        analytics.HEARTBEAT_FILE = self.tmp / "analytics-writer-heartbeat.json"
        local_dns.STAGING_DIR = self.tmp / "staging"
        local_dns.BACKUP_DIR = self.tmp / "backups"
        local_dns.COMPILED_DIR = self.tmp / "compiled" / "bind"
        local_dns.LOCAL_ZONE_DIR = local_dns.COMPILED_DIR / "local"
        local_dns.LOCAL_ZONES_CONF = local_dns.COMPILED_DIR / "local-zones.conf"
        local_dns.NAMED_LOCAL_CONF = self.tmp / "named.conf.local"
        local_dns.STAGING_DIR.mkdir(parents=True)
        local_dns.NAMED_LOCAL_CONF.write_text(
            'acl "alderpointdns_clients" { localhost; };\nzone "alderpointdns.rpz" { type primary; file "alderpointdns.rpz"; };\n'
        )
        analytics.init_analytics_db()

        self.patches = [
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(webapp, "run", lambda command: (0, "active")),
        ]
        for patcher in self.patches:
            patcher.start()

        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", auth.hash_password(INITIAL_PASSWORD), "now"),
        )
        conn.commit()
        conn.close()

        self.client = TestClient(webapp.app)
        self.client.post("/login", data={"username": "admin", "password": INITIAL_PASSWORD})

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        for mod, path in self.old_db_paths.items():
            mod.DB_PATH = path
        alderpointdns_compiler.MIGRATION_LOCK = self.old_migration_lock
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _lock_holder(self, stop: threading.Event) -> None:
        while not stop.is_set():
            conn = sqlite3.connect(self.db_path, timeout=5)
            try:
                conn.execute("BEGIN IMMEDIATE")
                time.sleep(self.LOCK_HOLD_SECONDS)
                conn.commit()
            finally:
                conn.close()
            stop.wait(self.LOCK_GAP_SECONDS)

    def _event_feeder(self, collector: analytics.Collector, stop: threading.Event) -> None:
        i = 0
        while not stop.is_set():
            collector.events.put(
                analytics.QueryEvent(analytics.utc_now(), f"10.0.0.{i % 5}", f"host{i}.example.test", "A", "UDP", "NOERROR", 1.5, False)
            )
            i += 1
            stop.wait(0.01)

    def _web_worker(self, stop: threading.Event, errors: list[Exception]) -> None:
        pages = ("/", "/status/summary", "/query-log", "/blocklists", "/system")
        i = 0
        while not stop.is_set():
            try:
                self.client.get(pages[i % len(pages)])
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)
            i += 1

    def test_web_traffic_and_analytics_writer_survive_concurrent_lock_contention(self) -> None:
        baseline_fds = _open_fds_to(self.db_path)
        collector = analytics.Collector()
        stop = threading.Event()
        web_errors: list[Exception] = []

        threads = [
            threading.Thread(target=collector.writer_loop, daemon=True),
            threading.Thread(target=self._lock_holder, args=(stop,), daemon=True),
            threading.Thread(target=self._event_feeder, args=(collector, stop), daemon=True),
            threading.Thread(target=self._web_worker, args=(stop, web_errors), daemon=True),
        ]
        for thread in threads:
            thread.start()

        time.sleep(self.RUN_SECONDS)
        stop.set()
        # Let the writer run a few more lock-free cycles so its health has a
        # chance to settle back to "ok" once contention has stopped, the same
        # way it would after a transient production lock storm clears.
        time.sleep(0.6)
        collector.stop_event.set()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(web_errors, [])
        self.assertFalse(collector.fatal_error.is_set(), "writer thread terminated during transient lock contention")

        health = analytics.writer_health()
        self.assertNotEqual(health["status"], "dead")
        self.assertEqual(health["status"], "ok", f"writer health did not recover after contention stopped: {health}")
        self.assertFalse(health["stale"])

        with alderpointdns_compiler.connect() as conn:
            total_events = conn.execute("SELECT count(*) FROM query_events").fetchone()[0]
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        self.assertGreater(total_events, 0, "no query events were committed despite concurrent lock contention")
        self.assertEqual(integrity, "ok")

        after_fds = _open_fds_to(self.db_path)
        self.assertLessEqual(after_fds, baseline_fds + 5, f"open fds to the database grew from {baseline_fds} to {after_fds}")


if __name__ == "__main__":
    unittest.main()
