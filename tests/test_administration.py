#!/usr/bin/env python3
from __future__ import annotations

import re
import sqlite3
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from fastapi.testclient import TestClient  # noqa: E402

from app import alderpointdns_compiler, auth, local_dns, webapp  # noqa: E402

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')
INITIAL_PASSWORD = "initial-password-123"


class AdministrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-administration-test-"))
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
        self.patches = [
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
        ]
        for patcher in self.patches:
            patcher.start()

        # webapp.db() no longer creates schema/seeds on demand (that would
        # repeat init_db()'s work on every request); tests must trigger the
        # one-time migration explicitly, same as app-startup does.
        alderpointdns_compiler.init_db()
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", auth.hash_password(INITIAL_PASSWORD), "now"),
        )
        conn.commit()
        self.admin_id = conn.execute("SELECT id FROM admins WHERE username='admin'").fetchone()[0]
        conn.close()

        self.client = TestClient(webapp.app)
        self.client.post("/login", data={"username": "admin", "password": INITIAL_PASSWORD})

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        webapp.DB_PATH = self.old_paths["webapp_db"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        alderpointdns_compiler.MIGRATION_LOCK = self.old_paths["compiler_migration_lock"]
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _csrf(self) -> str:
        page = self.client.get("/system/administration")
        match = CSRF_RE.search(page.text)
        self.assertIsNotNone(match)
        return match.group(1)

    def _add_other_session(self) -> str:
        session_id = "other-device-session"
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES (?, ?, 'now', 'now', '1.2.3.4', 'otherbrowser', 'othercsrf')",
                (session_id, self.admin_id),
            )
            conn.commit()
        return session_id

    def test_change_password_success_revokes_other_sessions_not_current(self) -> None:
        other_session_id = self._add_other_session()
        csrf = self._csrf()
        response = self.client.post(
            "/system/administration/password",
            data={"csrf": csrf, "current_password": INITIAL_PASSWORD, "new_password": "brand-new-password-456", "confirm_new_password": "brand-new-password-456"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        with self.connect() as conn:
            remaining = {row["id"] for row in conn.execute("SELECT id FROM sessions WHERE admin_id=?", (self.admin_id,))}
        self.assertNotIn(other_session_id, remaining)
        self.assertEqual(len(remaining), 1)
        # The acting session must still be authenticated after its own
        # password change (only *other* sessions are revoked).
        still_in = self.client.get("/system/administration")
        self.assertEqual(still_in.status_code, 200)
        with self.connect() as conn:
            row = conn.execute("SELECT password_hash FROM admins WHERE id=?", (self.admin_id,)).fetchone()
        self.assertTrue(auth.verify_password(row["password_hash"], "brand-new-password-456"))

    def test_change_password_wrong_current_password_rejected(self) -> None:
        csrf = self._csrf()
        response = self.client.post(
            "/system/administration/password",
            data={"csrf": csrf, "current_password": "not-the-real-password", "new_password": "brand-new-password-456", "confirm_new_password": "brand-new-password-456"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("incorrect", response.text)
        with self.connect() as conn:
            row = conn.execute("SELECT password_hash FROM admins WHERE id=?", (self.admin_id,)).fetchone()
        self.assertTrue(auth.verify_password(row["password_hash"], INITIAL_PASSWORD))

    def test_change_password_mismatched_new_passwords_rejected(self) -> None:
        csrf = self._csrf()
        response = self.client.post(
            "/system/administration/password",
            data={"csrf": csrf, "current_password": INITIAL_PASSWORD, "new_password": "brand-new-password-456", "confirm_new_password": "totally-different-value"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("do not match", response.text)
        with self.connect() as conn:
            row = conn.execute("SELECT password_hash FROM admins WHERE id=?", (self.admin_id,)).fetchone()
        self.assertTrue(auth.verify_password(row["password_hash"], INITIAL_PASSWORD))

    def test_revoke_other_sessions_without_changing_password(self) -> None:
        other_session_id = self._add_other_session()
        csrf = self._csrf()
        response = self.client.post("/system/administration/revoke-sessions", data={"csrf": csrf}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        with self.connect() as conn:
            remaining = {row["id"] for row in conn.execute("SELECT id FROM sessions WHERE admin_id=?", (self.admin_id,))}
            row = conn.execute("SELECT password_hash FROM admins WHERE id=?", (self.admin_id,)).fetchone()
        self.assertNotIn(other_session_id, remaining)
        self.assertTrue(auth.verify_password(row["password_hash"], INITIAL_PASSWORD), "password must be unchanged")
        still_in = self.client.get("/system/administration")
        self.assertEqual(still_in.status_code, 200)

    def test_successful_and_failed_actions_recorded_in_audit_log_without_credentials(self) -> None:
        csrf = self._csrf()
        self.client.post(
            "/system/administration/password",
            data={"csrf": csrf, "current_password": "wrong-password-value", "new_password": "brand-new-password-456", "confirm_new_password": "brand-new-password-456"},
        )
        csrf2 = self._csrf()
        self.client.post(
            "/system/administration/password",
            data={"csrf": csrf2, "current_password": INITIAL_PASSWORD, "new_password": "brand-new-password-456", "confirm_new_password": "brand-new-password-456"},
        )
        with self.connect() as conn:
            rows = conn.execute("SELECT action, success, detail FROM admin_audit_log ORDER BY id").fetchall()
        self.assertGreaterEqual(len(rows), 2)
        self.assertEqual(rows[0]["action"], "password_change")
        self.assertEqual(rows[0]["success"], 0)
        self.assertEqual(rows[-1]["action"], "password_change")
        self.assertEqual(rows[-1]["success"], 1)
        for row in rows:
            self.assertNotIn("wrong-password-value", row["detail"])
            self.assertNotIn(INITIAL_PASSWORD, row["detail"])
            self.assertNotIn("brand-new-password-456", row["detail"])

    def test_session_list_never_exposes_raw_session_token(self) -> None:
        session_id = self._add_other_session()
        page = self.client.get("/system/administration")
        self.assertNotIn(session_id, page.text)
        self.assertIn("1.2.3.4", page.text)


if __name__ == "__main__":
    unittest.main()
