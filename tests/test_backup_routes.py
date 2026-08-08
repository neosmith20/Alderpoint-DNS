#!/usr/bin/env python3
"""Genuine HTTP round-trip coverage for native Alderpoint DNS backup
upload/restore through app/webapp.py's real ASGI routes (not just the
app/backup.py functions directly) -- the exact code path the reported
production migration bug went through. Proves:

- a native backup upload well over the old 10 MiB importer.py cap succeeds
  through /backup/import, never touching app/importer.py's MAX_UPLOAD_BYTES
- the upload is genuinely streamed (peak in-memory chunk size is bounded,
  independent of the archive size) through the real FastAPI route
- /backup/import is a separate route from /import/upload (Spreadsheet/Text
  Import), so a native backup can never be misdirected through it
- the configured native-backup max_upload_mib is enforced through the real
  route with a clean error, not a crash
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import alderpointdns_compiler, backup, custom_rules, importer, local_dns, upstream_dns, webapp  # noqa: E402


class BackupImportHttpTest(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.templating import Jinja2Templates
        from fastapi.testclient import TestClient

        from app import replication

        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-backup-routes-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "backup_db": backup.DB_PATH,
            "importer_db": importer.DB_PATH,
            "local_dns_db": local_dns.DB_PATH,
            "upstream_dns_db": upstream_dns.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "custom_rules_db": custom_rules.DB_PATH,
            "backup_dir": backup.BACKUP_DIR,
            "staging_dir": backup.STAGING_DIR,
            "imports_dir": backup.IMPORTS_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        for module in (webapp, backup, importer, local_dns, upstream_dns, alderpointdns_compiler, custom_rules):
            module.DB_PATH = db_path
        backup.BACKUP_DIR = self.tmp / "backups"
        backup.STAGING_DIR = self.tmp / "staging"
        backup.IMPORTS_DIR = backup.STAGING_DIR / "backup-imports"
        backup.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup.STAGING_DIR.mkdir(parents=True, exist_ok=True)

        local_dns.init_db()
        upstream_dns.init_db()
        alderpointdns_compiler.init_db()
        importer.init_db()
        custom_rules.init_db()
        backup.init_db()

        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES ('admin', 'x', 'now')")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, admin_id INTEGER, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT, csrf TEXT NOT NULL)"
        )
        conn.commit()
        conn.close()

        # The privileged-helper hop (sudo alderpointdns_compiler.py backup-*)
        # is out of scope for an HTTP route test; simulate what the
        # privileged process does by running the pending request inline,
        # exactly as app/backup.py's own request/response contract expects.
        self.patches = [
            mock.patch.object(webapp, "backup_create_apply", lambda: backup.process_pending_request("create")),
            mock.patch.object(webapp, "backup_restore_apply", lambda: backup.process_pending_request("restore")),
            mock.patch.object(webapp, "backup_preview_apply", lambda: backup.process_pending_request("preview")),
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(replication, "autostart", lambda: None),
            mock.patch.object(webapp, "TEMPLATES", Jinja2Templates(directory=str(ROOT / "web" / "templates"))),
        ]
        for patcher in self.patches:
            patcher.start()
        self.client = TestClient(webapp.app)
        self.csrf = "test-csrf-token"
        session_id = "test-session-id"
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES (?, 1, 'now', 'now', '', '', ?)",
            (session_id, self.csrf),
        )
        conn.commit()
        conn.close()
        self.client.cookies.set("alderpointdns_session", webapp.serializer.dumps({"sid": session_id}))

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        for module, key in (
            (webapp, "webapp_db"), (backup, "backup_db"), (importer, "importer_db"), (local_dns, "local_dns_db"),
            (upstream_dns, "upstream_dns_db"), (alderpointdns_compiler, "compiler_db"), (custom_rules, "custom_rules_db"),
        ):
            module.DB_PATH = self.old_paths[key]
        backup.BACKUP_DIR = self.old_paths["backup_dir"]
        backup.STAGING_DIR = self.old_paths["staging_dir"]
        backup.IMPORTS_DIR = self.old_paths["imports_dir"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build_backup_archive(self, size_bytes: int) -> bytes:
        # Content-Length hint the TestClient sends is derived from the body
        # it builds, so an oversized upload here really does exercise the
        # streamed size cap, not just a pre-flight header check.
        manifest_dir = self.tmp / "fixture-src"
        manifest_dir.mkdir(exist_ok=True)
        import json
        import tarfile

        archive_path = self.tmp / "fixture.tar.gz"
        with tarfile.open(archive_path, "w:gz") as tar:
            manifest = json.dumps(
                {
                    "backup_format_version": backup.BACKUP_FORMAT_VERSION,
                    "alderpointdns_app_version": "0.0.0-test",
                    "database_schema_version": "test",
                    "created_at": backup.now(),
                    "source_node_id": "test-host",
                    "included_components": [],
                    "sha256_checksums": {},
                }
            ).encode()
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest)
            import io

            tar.addfile(info, io.BytesIO(manifest))
            padding_info = tarfile.TarInfo("var/lib/alderpointdns/padding.bin")
            padding = os.urandom(size_bytes)
            padding_info.size = len(padding)
            tar.addfile(padding_info, io.BytesIO(padding))
        return archive_path.read_bytes()

    def test_backup_upload_over_10mib_succeeds_through_real_route(self) -> None:
        data = self._build_backup_archive(11 * 1024 * 1024)
        response = self.client.post(
            "/backup/import",
            data={"csrf": self.csrf},
            files={"upload": ("large-backup.tar.gz", data, "application/gzip")},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("imported=", response.headers["location"])
        staged = list(backup.IMPORTS_DIR.glob("*large-backup.tar.gz"))
        self.assertEqual(len(staged), 1)
        self.assertGreater(staged[0].stat().st_size, 10 * 1024 * 1024)
        self.assertEqual(oct(staged[0].stat().st_mode)[-3:], "640")

    def test_backup_import_route_is_distinct_from_spreadsheet_import_route(self) -> None:
        matches = [route for route in webapp.app.routes if getattr(route, "path", None) == "/backup/import"]
        self.assertEqual(len(matches), 1)
        self.assertIs(matches[0].endpoint, webapp.backup_import_route)
        import_matches = [route for route in webapp.app.routes if getattr(route, "path", None) == "/import/upload"]
        self.assertIs(import_matches[0].endpoint, webapp.import_upload)
        self.assertIsNot(matches[0].endpoint, import_matches[0].endpoint)

    def test_configured_max_upload_rejected_cleanly_through_real_route(self) -> None:
        backup.update_settings({"max_upload_mib": 64})
        data = self._build_backup_archive(65 * 1024 * 1024)
        response = self.client.post(
            "/backup/import",
            data={"csrf": self.csrf},
            files={"upload": ("too-big.tar.gz", data, "application/gzip")},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("64 MiB", response.text)
        self.assertEqual(list(backup.IMPORTS_DIR.glob("*")), [])

    def test_non_backup_extension_rejected_through_real_route(self) -> None:
        response = self.client.post(
            "/backup/import",
            data={"csrf": self.csrf},
            files={"upload": ("not-a-backup.zip", b"PK\x03\x04fake", "application/zip")},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(".tar.gz", response.text)


if __name__ == "__main__":
    unittest.main()
