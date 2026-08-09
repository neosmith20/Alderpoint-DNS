#!/usr/bin/env python3
"""Focused coverage for the /protection/toggle route's narrowed reuse
deployment path (dex/v1-performance's "Narrow protection reuse deployment
path" live-validation fix): Protection OFF -> ON must try the fast
compiled-policy-reuse path first and only fall back to a full
deploy --no-download rebuild if reuse is unavailable/fails.
Protection ON -> OFF must never attempt reuse at all.
"""
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


class ProtectionReuseRouteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-protection-reuse-test-"))
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
        self.patches = [
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
        ]
        for patcher in self.patches:
            patcher.start()

        alderpointdns_compiler.init_db()
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", auth.hash_password(INITIAL_PASSWORD), "now"),
        )
        conn.commit()
        conn.close()

        self.client = TestClient(webapp.app)
        self.client.post("/login", data={"username": "admin", "password": INITIAL_PASSWORD})
        self.csrf = self._current_csrf()

    def _current_csrf(self) -> str:
        html = self.client.get("/").text
        match = CSRF_RE.search(html)
        self.assertIsNotNone(match, "no csrf token found on dashboard")
        return match.group(1)

    def _set_active_domains(self, count: int) -> None:
        with sqlite3.connect(webapp.DB_PATH) as conn:
            conn.execute(
                "INSERT INTO deployments(started_at, finished_at, status, message, active_domains, \"trigger\") "
                "VALUES ('now', 'now', 'deployed', '', ?, 'manual')",
                (count,),
            )
            conn.commit()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        webapp.DB_PATH = self.old_paths["webapp_db"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        alderpointdns_compiler.MIGRATION_LOCK = self.old_paths["compiler_migration_lock"]
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_off_to_on_tries_reuse_first_and_skips_full_rebuild_on_success(self) -> None:
        self._set_active_domains(0)  # currently OFF -> toggling turns it ON
        with mock.patch.object(webapp, "protection_enable_reuse", return_value=(0, "reused")) as reuse, \
             mock.patch.object(webapp, "deploy_no_download") as rebuild:
            response = self.client.post("/protection/toggle", data={"csrf": self.csrf}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        reuse.assert_called_once()
        rebuild.assert_not_called()

    def test_off_to_on_falls_back_to_full_rebuild_when_reuse_unavailable(self) -> None:
        self._set_active_domains(0)
        with mock.patch.object(webapp, "protection_enable_reuse", return_value=(2, "cached policy artifact is missing")) as reuse, \
             mock.patch.object(webapp, "deploy_no_download", return_value=(0, "deployed")) as rebuild:
            response = self.client.post("/protection/toggle", data={"csrf": self.csrf}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        reuse.assert_called_once()
        rebuild.assert_called_once()

    def test_on_to_off_never_attempts_reuse(self) -> None:
        self._set_active_domains(5)  # currently ON -> toggling turns it OFF
        with mock.patch.object(webapp, "protection_enable_reuse") as reuse, \
             mock.patch.object(webapp, "deploy_no_download", return_value=(0, "deployed")) as rebuild:
            response = self.client.post("/protection/toggle", data={"csrf": self.csrf}, follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        reuse.assert_not_called()
        rebuild.assert_called_once()


if __name__ == "__main__":
    unittest.main()
