#!/usr/bin/env python3
from __future__ import annotations

import re
import sqlite3
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from fastapi.testclient import TestClient  # noqa: E402

from app import alderpointdns_compiler, local_dns, webapp  # noqa: E402

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


class SetupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-setup-test-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "local_dns_db": local_dns.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "compiler_migration_lock": alderpointdns_compiler.MIGRATION_LOCK,
        }
        db_path = self.tmp / "alderpointdns.db"
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
        # webapp.db() no longer creates schema/seeds on demand; tests must
        # trigger the one-time migration explicitly, same as app-startup does.
        alderpointdns_compiler.init_db()
        self.client = TestClient(webapp.app)

    def tearDown(self) -> None:
        webapp.DB_PATH = self.old_paths["webapp_db"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        alderpointdns_compiler.MIGRATION_LOCK = self.old_paths["compiler_migration_lock"]
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def admin_count(self) -> int:
        conn = sqlite3.connect(webapp.DB_PATH)
        try:
            if not conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'").fetchone():
                return 0
            return conn.execute("SELECT count(*) FROM admins").fetchone()[0]
        finally:
            conn.close()

    def _csrf(self, html: str) -> str:
        match = CSRF_RE.search(html)
        self.assertIsNotNone(match, "setup page did not render a csrf token")
        return match.group(1)

    def test_matching_passwords_creates_admin(self) -> None:
        page = self.client.get("/setup")
        csrf = self._csrf(page.text)
        response = self.client.post(
            "/setup",
            data={"csrf": csrf, "username": "admin", "password": "correct-horse-battery", "confirm_password": "correct-horse-battery", "create_local_dns": "0"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")
        self.assertEqual(self.admin_count(), 1)

    def test_mismatched_passwords_rejected_and_username_preserved(self) -> None:
        page = self.client.get("/setup")
        csrf = self._csrf(page.text)
        response = self.client.post(
            "/setup",
            data={"csrf": csrf, "username": "opsadmin", "password": "correct-horse-battery", "confirm_password": "totally-different-value", "create_local_dns": "0"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("do not match", response.text)
        self.assertIn('value="opsadmin"', response.text)
        self.assertNotIn("correct-horse-battery", response.text)
        self.assertNotIn("totally-different-value", response.text)
        self.assertEqual(self.admin_count(), 0)

    def test_empty_confirmation_rejected(self) -> None:
        page = self.client.get("/setup")
        csrf = self._csrf(page.text)
        response = self.client.post(
            "/setup",
            data={"csrf": csrf, "username": "admin", "password": "correct-horse-battery", "confirm_password": "", "create_local_dns": "0"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("do not match", response.text)
        self.assertEqual(self.admin_count(), 0)

    def test_forged_request_without_valid_session_is_rejected(self) -> None:
        # No prior GET /setup: no session cookie, so no valid csrf token
        # could ever have been issued for this value.
        response = self.client.post(
            "/setup",
            data={"csrf": "forged-token", "username": "attacker", "password": "correct-horse-battery", "confirm_password": "correct-horse-battery"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.admin_count(), 0)

    def test_forged_request_with_mismatched_csrf_after_real_visit_is_rejected(self) -> None:
        self.client.get("/setup")  # establishes a real anonymous session/csrf
        response = self.client.post(
            "/setup",
            data={"csrf": "not-the-real-token", "username": "attacker", "password": "correct-horse-battery", "confirm_password": "correct-horse-battery"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.admin_count(), 0)

    def test_password_never_appears_in_response_body_on_failure(self) -> None:
        page = self.client.get("/setup")
        csrf = self._csrf(page.text)
        secret = "unmistakable-secret-value-123"
        response = self.client.post(
            "/setup",
            data={"csrf": csrf, "username": "admin", "password": secret, "confirm_password": secret + "x", "create_local_dns": "0"},
        )
        self.assertNotIn(secret, response.text)


if __name__ == "__main__":
    unittest.main()
