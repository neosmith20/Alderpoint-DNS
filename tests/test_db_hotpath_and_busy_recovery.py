#!/usr/bin/env python3
"""Regression coverage for the beta.5 SQLite concurrency hotfix.

Root cause: app/webapp.py's db() ran alderpointdns_compiler.init_db() (a
PRAGMA journal_mode=WAL, several CREATE TABLE/ALTER-if-missing probes, and
INSERT OR IGNORE category/policy-profile seeds) on every single database
connection request -- meaning every authenticated page load or POST
attempted write-capable schema/seed operations even though the schema was
already fully initialized. If a concurrent long-running writer (a compiler
deploy, backup/restore, or blocklist update) held SQLite's single writer
lock past the 5s busy_timeout, an ordinary request raised an uncaught
sqlite3.OperationalError("database is locked") and returned HTTP 500.

This covers:
  * webapp.db() is a pure connection factory -- it never calls init_db()
  * repeated GET requests do not repeat schema/seed writes
  * init_db() is idempotent and safe after a simulated beta.5 upgrade
  * concurrent init_db() calls are serialized by an interprocess lock and
    apply the schema exactly once
  * WAL mode is preserved
  * a real concurrent long-running writer does not turn an authenticated
    read-only page into an HTTP 500
  * session last_seen_at bookkeeping retries briefly, then is skipped
    (never a failed request) when the database stays busy
  * authentication and CSRF enforcement are unaffected by a skipped
    last_seen_at update
  * a write that exhausts its busy-retry budget returns a controlled,
    traceback-free response instead of a raw 500
"""

from __future__ import annotations

import re
import shutil
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

from app import alderpointdns_compiler, auth, local_dns, webapp  # noqa: E402
from app.db_retry import DatabaseBusyError  # noqa: E402

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')
INITIAL_PASSWORD = "initial-password-123"


class WebHotPathTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-hotpath-test-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "local_dns_db": local_dns.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "compiler_migration_lock": alderpointdns_compiler.MIGRATION_LOCK,
        }
        db_path = self.tmp / "alderpointdns.db"
        self.db_path = db_path
        webapp.DB_PATH = db_path
        local_dns.DB_PATH = db_path
        alderpointdns_compiler.DB_PATH = db_path
        alderpointdns_compiler.MIGRATION_LOCK = self.tmp / "staging" / "schema-migration.lock"
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

        # Schema/seed migration happens exactly once, explicitly -- exactly
        # what the app-startup hook does, and never via webapp.db() itself.
        alderpointdns_compiler.init_db()

        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", auth.hash_password(INITIAL_PASSWORD), "now"),
        )
        conn.commit()
        conn.close()

        self.patches = [
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(webapp, "run", lambda command: (0, "active")),
        ]
        for patcher in self.patches:
            patcher.start()

        self.client = TestClient(webapp.app)
        login = self.client.post("/login", data={"username": "admin", "password": INITIAL_PASSWORD})
        self.assertIn(login.status_code, (200, 303))
        self.csrf = self._csrf()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        webapp.DB_PATH = self.old_paths["webapp_db"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        alderpointdns_compiler.MIGRATION_LOCK = self.old_paths["compiler_migration_lock"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _csrf(self) -> str:
        page = self.client.get("/system/administration")
        match = CSRF_RE.search(page.text)
        self.assertIsNotNone(match, "expected a csrf token on the administration page")
        return match.group(1)


class DbHotPathTests(WebHotPathTestBase):
    def test_db_does_not_invoke_init_db(self) -> None:
        with mock.patch.object(webapp, "init_db") as mocked_init_db:
            conn = webapp.db()
            try:
                conn.execute("SELECT 1")
            finally:
                conn.close()
        mocked_init_db.assert_not_called()

    def test_repeated_get_requests_perform_no_schema_or_seed_writes(self) -> None:
        with mock.patch.object(webapp, "init_db") as mocked_init_db, \
                mock.patch.object(alderpointdns_compiler, "_apply_schema") as mocked_apply_schema:
            for _ in range(5):
                response = self.client.get("/system/administration")
                self.assertEqual(response.status_code, 200)
        mocked_init_db.assert_not_called()
        mocked_apply_schema.assert_not_called()

    def test_wal_mode_remains_enabled(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(mode.lower(), "wal")


class InitDbIdempotencyTests(WebHotPathTestBase):
    def test_init_db_is_idempotent(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            categories_before = conn.execute("SELECT count(*) FROM categories").fetchone()[0]
            profiles_before = conn.execute("SELECT count(*) FROM policy_profiles").fetchone()[0]
            version_before = conn.execute("PRAGMA user_version").fetchone()[0]
        finally:
            conn.close()

        alderpointdns_compiler.init_db()
        alderpointdns_compiler.init_db()

        conn = sqlite3.connect(self.db_path)
        try:
            categories_after = conn.execute("SELECT count(*) FROM categories").fetchone()[0]
            profiles_after = conn.execute("SELECT count(*) FROM policy_profiles").fetchone()[0]
            version_after = conn.execute("PRAGMA user_version").fetchone()[0]
        finally:
            conn.close()

        self.assertEqual(categories_before, categories_after)
        self.assertEqual(profiles_before, profiles_after)
        self.assertEqual(version_before, version_after)
        self.assertGreaterEqual(version_after, alderpointdns_compiler.SCHEMA_VERSION)

    def test_seeds_present_after_fresh_install(self) -> None:
        conn = sqlite3.connect(self.db_path)
        try:
            categories = {row[0] for row in conn.execute("SELECT key FROM categories")}
            profiles = {row[0] for row in conn.execute("SELECT key FROM policy_profiles")}
        finally:
            conn.close()
        self.assertEqual(categories, {"malware", "ads_trackers", "adult_content", "iot_telemetry", "safesearch", "custom"})
        self.assertEqual(profiles, {"trusted", "standard", "iot", "restricted"})

    def test_seeds_present_after_simulated_beta5_upgrade(self) -> None:
        # beta.5's init_db() never set PRAGMA user_version, so an existing
        # installation upgrading into this fix starts at version 0 with its
        # schema and data already in place. init_db() must recognize that
        # and migrate it forward without wiping or duplicating anything, and
        # without clobbering any row an operator already edited.
        upgrade_db = self.tmp / "beta5-upgrade.db"
        old_db_path = alderpointdns_compiler.DB_PATH
        alderpointdns_compiler.DB_PATH = upgrade_db
        try:
            alderpointdns_compiler.init_db()
            conn = sqlite3.connect(upgrade_db)
            conn.execute("PRAGMA user_version=0")
            conn.execute("UPDATE categories SET description='operator-edited' WHERE key='malware'")
            conn.commit()
            conn.close()

            alderpointdns_compiler.init_db()

            conn = sqlite3.connect(upgrade_db)
            try:
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                categories = {row[0] for row in conn.execute("SELECT key FROM categories")}
                malware_desc = conn.execute("SELECT description FROM categories WHERE key='malware'").fetchone()[0]
            finally:
                conn.close()
        finally:
            alderpointdns_compiler.DB_PATH = old_db_path

        self.assertGreaterEqual(version, alderpointdns_compiler.SCHEMA_VERSION)
        self.assertEqual(categories, {"malware", "ads_trackers", "adult_content", "iot_telemetry", "safesearch", "custom"})
        self.assertEqual(malware_desc, "operator-edited")


class ConcurrentInitDbTests(WebHotPathTestBase):
    def test_concurrent_init_db_is_serialized_and_applies_schema_once(self) -> None:
        # A fresh, not-yet-migrated database file, so every thread races to
        # be the one that actually runs the migration.
        race_db = self.tmp / "race.db"
        old_db_path = alderpointdns_compiler.DB_PATH
        alderpointdns_compiler.DB_PATH = race_db
        calls: list[int] = []
        original_apply_schema = alderpointdns_compiler._apply_schema

        def wrapped(conn: sqlite3.Connection) -> None:
            calls.append(1)
            time.sleep(0.05)
            original_apply_schema(conn)

        try:
            with mock.patch.object(alderpointdns_compiler, "_apply_schema", side_effect=wrapped):
                threads = [threading.Thread(target=alderpointdns_compiler.init_db) for _ in range(8)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)
        finally:
            alderpointdns_compiler.DB_PATH = old_db_path

        self.assertEqual(len(calls), 1, "the migration lock should let only one thread apply the schema")
        conn = sqlite3.connect(race_db)
        try:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            categories = conn.execute("SELECT count(*) FROM categories").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(version, alderpointdns_compiler.SCHEMA_VERSION)
        self.assertEqual(categories, 6)


class ConcurrentWriterDoesNotBreakReadsTests(WebHotPathTestBase):
    def test_long_running_writer_does_not_500_an_authenticated_get(self) -> None:
        stop = threading.Event()
        errors: list[BaseException] = []

        def hold_writer_lock() -> None:
            conn = sqlite3.connect(self.db_path, timeout=5.0)
            try:
                while not stop.is_set():
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("UPDATE sources SET final_active_domains=final_active_domains")
                    time.sleep(0.3)
                    conn.commit()
                    time.sleep(0.05)
            except Exception as exc:  # pragma: no cover - diagnostic only
                errors.append(exc)
            finally:
                conn.close()

        holder = threading.Thread(target=hold_writer_lock)
        holder.start()
        try:
            time.sleep(0.05)
            statuses = [self.client.get("/system/administration").status_code for _ in range(10)]
        finally:
            stop.set()
            holder.join(timeout=5)

        self.assertFalse(errors, f"lock-holder thread raised: {errors}")
        self.assertTrue(all(status == 200 for status in statuses), statuses)


class LastSeenBusyRecoveryTests(WebHotPathTestBase):
    def test_last_seen_retried_then_skipped_when_still_busy(self) -> None:
        calls: list[int] = []
        original_execute = alderpointdns_compiler.AlderpointDNSConnection.execute

        def flaky_execute(self, sql, *params):
            if isinstance(sql, str) and sql.strip().upper().startswith("UPDATE SESSIONS SET LAST_SEEN_AT"):
                calls.append(1)
                raise sqlite3.OperationalError("database is locked")
            return original_execute(self, sql, *params)

        with mock.patch.object(alderpointdns_compiler.AlderpointDNSConnection, "execute", flaky_execute), \
                mock.patch("time.sleep", lambda *_: None):
            response = self.client.get("/system/administration")

        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(calls), 3, "expected the bounded retry budget to be exhausted, not given up on immediately")

    def test_authentication_and_csrf_enforced_while_last_seen_skipped(self) -> None:
        with mock.patch.object(webapp, "retry_on_locked", side_effect=DatabaseBusyError("simulated busy")):
            page = self.client.get("/system/administration")
            self.assertEqual(page.status_code, 200)

            accepted = self.client.post("/protection/toggle", data={"csrf": self.csrf})
            self.assertLess(accepted.status_code, 500)
            self.assertNotEqual(accepted.status_code, 403)

            forged = self.client.post("/protection/toggle", data={"csrf": "wrong-token"})
            self.assertEqual(forged.status_code, 403)

        anon_client = TestClient(webapp.app)
        unauthenticated = anon_client.get("/system/administration", follow_redirects=False)
        self.assertIn(unauthenticated.status_code, (303, 307))


class ControlledBusyResponseTests(WebHotPathTestBase):
    def test_exhausted_busy_write_returns_controlled_response_without_traceback(self) -> None:
        original_execute = alderpointdns_compiler.AlderpointDNSConnection.execute

        def flaky_execute(self, sql, *params):
            if isinstance(sql, str) and sql.strip().upper().startswith("UPDATE SOURCES SET ENABLED"):
                raise sqlite3.OperationalError("database is locked")
            return original_execute(self, sql, *params)

        with mock.patch.object(alderpointdns_compiler.AlderpointDNSConnection, "execute", flaky_execute):
            response = self.client.post("/protection/toggle", data={"csrf": self.csrf})

        self.assertEqual(response.status_code, 503)
        self.assertNotIn("Traceback", response.text)
        self.assertNotIn("OperationalError", response.text)
        self.assertIn("busy", response.text.lower())


if __name__ == "__main__":
    unittest.main()
