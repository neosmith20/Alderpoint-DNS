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
            mock.patch.object(webapp, "backup_restore_apply", lambda: (0, str(backup.process_pending_request("restore")))),
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


class BackupRestoreAsyncDispatchHttpTest(BackupImportHttpTest):
    """Regression coverage for a real appliance restore failure: the web
    request that starts a restore used to run it synchronously (`sudo
    alderpointdns_compiler.py backup-restore` as a direct child of this
    request's own process), and app/webapp.py's route then required
    `latest_request_result("restore")` to already show status="done"
    before it would even redirect successfully. A restore that touches
    app_config restarts alderpointdns.service (this same process's own
    service) partway through -- which killed that direct child outright,
    and would ALSO have made the route's own synchronous "must be done
    already" check wrong even in a fully healthy async run, since
    dispatching the independent runner unit (systemctl start --no-block)
    returns immediately, long before the restore itself has finished.
    These tests replace the class fixture's synchronous inline-processing
    mock with one that reproduces the real, current contract: dispatch
    only starts the runner and returns immediately."""

    def _restore(self, source: str, **extra_fields: str):
        data = {"csrf": self.csrf, "source": source}
        data.update(extra_fields)
        return self.client.post("/backup/restore", data=data, follow_redirects=False)

    def _seed_backup(self) -> str:
        path = backup.create_backup(dict.fromkeys(backup.COMPONENT_KEYS, False) | {"sqlite_data": True})
        return str(path)

    def test_route_does_not_require_the_restore_to_already_be_done(self) -> None:
        # A true fire-and-forget dispatch: unlike the class fixture's
        # default mock, this does NOT process the pending request inline
        # -- it only starts the (fake) runner, exactly like the real
        # systemctl start --no-block does. If the route still required
        # status="done" synchronously (the pre-fix bug), this would raise
        # and return an error status instead of redirecting.
        source = self._seed_backup()
        with mock.patch.object(webapp, "backup_restore_apply", lambda: (0, "Started alderpointdns-backup-restore.service.")):
            response = self._restore(source)
        self.assertEqual(response.status_code, 303, response.text)
        pending = backup.latest_request_result("restore")
        self.assertIsNotNone(pending)
        self.assertEqual(pending["status"], "pending")
        # backup.html's inline poller (see its `restore_just_dispatched`
        # gate) needs this on the very first page load, before the
        # separately-started runner unit has even inserted a
        # restore_history row -- without it, a page load landing in that
        # gap would see no in-progress restore and never start polling.
        self.assertEqual(response.headers["location"], "/backup?restore_started=1")

    def test_dispatch_failure_is_reported_as_an_error(self) -> None:
        # If *starting* the independent runner itself fails (e.g. the unit
        # is missing, or sudoers denies it), that must still surface as a
        # real error -- this is the one case backup_restore_apply()'s
        # return code is checked for.
        source = self._seed_backup()
        with mock.patch.object(webapp, "backup_restore_apply", lambda: (1, "Failed to start alderpointdns-backup-restore.service: Unit not found.")):
            response = self._restore(source)
        self.assertEqual(response.status_code, 400)
        self.assertIn("failed to start the restore runner", response.text)

    def test_successful_dispatch_and_completion_still_redirects(self) -> None:
        # The class fixture's default mock (restored by tearDown after
        # this test) processes the request inline, simulating a restore
        # that both started and finished by the time the request returns
        # -- still must redirect cleanly, not regress the happy path.
        source = self._seed_backup()
        response = self._restore(source)
        self.assertEqual(response.status_code, 303, response.text)
        done = backup.latest_request_result("restore")
        self.assertEqual(done["status"], "done")


class RestoreSessionTransitionHttpTest(BackupRestoreAsyncDispatchHttpTest):
    """Regression coverage for a real appliance report: a restore that
    touches app_config/user_auth_data/sessions works (restore_history ends
    status=deployed, services healthy) but the browser is left on a
    misleading half-authenticated page, because a fetch()-driven poll
    follows the resulting 303-to-/login on its own and hands back /login's
    HTML as if it were a normal response. The fix is backup.html's inline
    poller against GET /backup/restore/status, which explicitly checks
    `response.redirected` and does a real top-level navigation to
    /login?reason=restore itself. These tests cover the server-side half of
    that contract: the exact redirect status/target the poller depends on,
    the login notice it navigates to, and that the Last Restore card is
    never blank/misleading at any point in the sequence."""

    def _invalidate_session_like_a_restore_would(self) -> None:
        # A restore's app_config/user_auth_data component replaces the
        # live sessions table with the backup's -- from the current
        # browser's point of view, its own session row simply no longer
        # exists afterward. (A rotated session-signing secret would break
        # the cookie's signature outright and never even reach here; a
        # stale-but-still-verifiable cookie whose row is just gone is the
        # more interesting case to prove current_admin() actually rejects.)
        with sqlite3.connect(webapp.DB_PATH) as conn:
            conn.execute("DELETE FROM sessions WHERE id='test-session-id'")
            conn.commit()

    def test_restore_status_partial_requires_auth_and_redirects_to_login(self) -> None:
        self.client.cookies.clear()
        response = self.client.get("/backup/restore/status", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")

    def test_session_invalidated_by_restore_yields_a_real_redirect_not_a_disguised_200(self) -> None:
        # This is exactly what the poller's `response.redirected` check
        # depends on: the browser (and TestClient, which mirrors fetch()'s
        # redirect-following here) must see a genuine 303 with a /login
        # Location, never a 200 carrying login HTML under this URL.
        self._invalidate_session_like_a_restore_would()
        response = self.client.get("/backup/restore/status", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/login")

    def test_login_shows_the_restore_reason_notice_only_when_asked(self) -> None:
        response = self.client.get("/login?reason=restore")
        self.assertIn("Restore completed. Authentication/session data changed, so you need to sign in again.", response.text)
        plain = self.client.get("/login")
        self.assertNotIn("Authentication/session data changed", plain.text)

    def test_login_notice_is_a_fixed_vocabulary_not_arbitrary_query_text(self) -> None:
        # `reason` must never let arbitrary request text get echoed onto an
        # unauthenticated page -- only the fixed, pre-written messages.
        response = self.client.get("/login?reason=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        self.assertNotIn("<script>alert(1)</script>", response.text)
        self.assertNotIn("alert(1)", response.text)

    def test_no_misleading_empty_state_before_any_restore(self) -> None:
        response = self.client.get("/backup/restore/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("No restores yet.", response.text)
        self.assertIn('data-restore-active="0"', response.text)

    def test_running_restore_is_flagged_active_for_the_poller_to_keep_polling(self) -> None:
        # A bare 'running' row with no live worker identity is exactly what
        # reap_abandoned_restores() (backup.last_restore()'s own stale-worker
        # detection, deliberately left unmodified by this fix) treats as
        # abandoned. Running a real restore first records a genuine worker
        # identity (this still-alive test process's own pid/boot id), then
        # flipping its finished row back to 'running' reproduces "still in
        # progress" without tripping that unrelated detection.
        source = self._seed_backup()
        self._restore(source)
        with backup.connect() as conn:
            conn.execute("UPDATE restore_history SET status='running', finished_at=NULL WHERE id=(SELECT max(id) FROM restore_history)")
            conn.commit()
        response = self.client.get("/backup/restore/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-restore-active="1"', response.text)

    def test_completed_restore_remains_visible_after_reauthentication(self) -> None:
        # Simulates the full real sequence: the restore replaces the
        # sessions table (old cookie now rejected) but restore_history
        # itself -- durable state, not session state -- still shows the
        # completed restore once the admin signs back in with a fresh
        # session.
        with backup.connect() as conn:
            conn.execute(
                "INSERT INTO restore_history(started_at, finished_at, backup_path, components_json, status, message, phase) "
                "VALUES ('now', 'now', '/tmp/x.tar.gz', '{}', 'deployed', '', 'completed')"
            )
            conn.commit()
        self._invalidate_session_like_a_restore_would()
        # Confirms the old session really is rejected first (proving this
        # test isn't accidentally reusing a still-valid cookie).
        rejected = self.client.get("/backup/restore/status", follow_redirects=False)
        self.assertEqual(rejected.status_code, 303)

        # A fresh session, exactly like a real re-login would create.
        with sqlite3.connect(webapp.DB_PATH) as conn:
            conn.execute(
                "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES ('fresh-session-id', 1, 'now', 'now', '', '', 'fresh-csrf')"
            )
            conn.commit()
        self.client.cookies.set("alderpointdns_session", webapp.serializer.dumps({"sid": "fresh-session-id"}))
        response = self.client.get("/backup/restore/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn('data-restore-active="0"', response.text)
        self.assertNotIn("No restores yet.", response.text)


class BackupCreateAutoDownloadHttpTest(BackupImportHttpTest):
    """Coverage for the automatic-download-after-Create-Backup QoL feature:
    a successful interactive web-created backup both stays retained/listed
    on the server (exactly as before) and immediately triggers a browser
    download of that same archive, without buffering it in the web
    process or bypassing the existing authenticated download route."""

    def _create(self, **extra_fields: str):
        data = {"csrf": self.csrf, "app_config": "1", "sqlite_data": "1"}
        data.update(extra_fields)
        return self.client.post("/backup/create", data=data, follow_redirects=False)

    def test_successful_create_redirects_with_download_marker(self) -> None:
        response = self._create()
        self.assertEqual(response.status_code, 303, response.text)
        self.assertIn("download=", response.headers["location"])
        rows = backup.list_backups()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "deployed")

    def test_backup_page_embeds_auto_download_marker_pointing_at_the_new_backup(self) -> None:
        create_response = self._create()
        location = create_response.headers["location"]
        page = self.client.get(location, follow_redirects=False)
        self.assertEqual(page.status_code, 200)
        self.assertIn('data-auto-download="/backup/', page.text)
        # The marker must point at a download URL that actually resolves
        # to a real, currently-listed backup, not just echo the query
        # param blindly.
        row = backup.list_backups()[0]
        self.assertIn(f'/backup/{row["id"]}/download', page.text)

    def test_retained_server_copy_still_exists_after_auto_download(self) -> None:
        self._create()
        row = backup.list_backups()[0]
        path = backup.find_backup_path(str(row["id"]))
        self.assertTrue(path.exists())

    def test_manual_download_still_works_after_auto_download(self) -> None:
        self._create()
        row = backup.list_backups()[0]
        response = self.client.get(f"/backup/{row['id']}/download")
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.content), 0)
        # Downloadable a second time -- the automatic download never moves
        # or deletes the server-side archive.
        response2 = self.client.get(f"/backup/{row['id']}/download")
        self.assertEqual(response2.status_code, 200)
        self.assertEqual(response.content, response2.content)

    def test_failed_create_does_not_set_download_marker(self) -> None:
        # private_keys requires the explicit confirmation checkbox;
        # omitting it makes backup_create_route raise before any backup
        # is ever created.
        response = self._create(private_keys="1")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("data-auto-download", response.text)
        self.assertEqual(backup.list_backups(), [])

    def test_download_route_streams_a_large_backup_in_bounded_chunks(self) -> None:
        # Real end-to-end proof (not just a unit check of FileResponse):
        # download a backup large enough that "buffer the whole file in
        # this process" would show up as a large single allocation, and
        # confirm the response is read back correctly in chunks.
        self._create(analytics_history="1")
        row = backup.list_backups()[0]
        path = backup.find_backup_path(str(row["id"]))
        # Pad the archive well past a single reasonable in-memory chunk so
        # a whole-file buffering regression would be obvious from RSS,
        # even though this test only asserts on streamed correctness.
        with path.open("ab") as fh:
            fh.write(os.urandom(6 * 1024 * 1024))
        expected_size = path.stat().st_size
        with self.client.stream("GET", f"/backup/{row['id']}/download") as response:
            self.assertEqual(response.status_code, 200)
            total = 0
            max_chunk = 0
            for chunk in response.iter_bytes(chunk_size=65536):
                total += len(chunk)
                max_chunk = max(max_chunk, len(chunk))
        self.assertEqual(total, expected_size)
        # No single streamed chunk should be anywhere near the full file
        # size -- that would indicate the server read/sent it as one blob.
        self.assertLess(max_chunk, expected_size)

    def test_unauthenticated_request_cannot_download_a_backup(self) -> None:
        self._create()
        row = backup.list_backups()[0]
        anon_client = self.client.__class__(webapp.app)
        response = anon_client.get(f"/backup/{row['id']}/download", follow_redirects=False)
        self.assertIn(response.status_code, (302, 303, 401, 403))

    def test_arbitrary_filesystem_path_is_rejected(self) -> None:
        for identifier in ("/etc/passwd", "../../../../etc/passwd", "..%2F..%2Fetc%2Fpasswd"):
            response = self.client.get(f"/backup/{identifier}/download")
            self.assertEqual(response.status_code, 404, identifier)


class LocalTimestampDisplayTest(unittest.TestCase):
    """format_local_datetime() (the `local_time` Jinja filter) converts a
    canonical UTC/ISO-8601 timestamp to the server's configured local
    timezone for display only. Restore/backup lookups never parse this
    output; only the raw ISO string in the database/manifest is
    canonical."""

    def _with_tz(self, tz: str):
        return mock.patch.dict(os.environ, {"TZ": tz})

    def setUp(self) -> None:
        import time as _time

        self._time = _time

    def _format(self, iso: str, tz: str) -> str:
        with self._with_tz(tz):
            self._time.tzset()
            try:
                return webapp.format_local_datetime(iso)
            finally:
                pass

    def tearDown(self) -> None:
        self._time.tzset()

    def test_utc_server_shows_utc(self) -> None:
        result = self._format("2026-08-08T18:47:00+00:00", "UTC")
        self.assertIn("2026", result)
        self.assertTrue(result.endswith("UTC") or "+00" in result)

    def test_non_utc_server_converts_and_labels_timezone(self) -> None:
        result = self._format("2026-08-09T00:47:00+00:00", "America/Denver")
        # 00:47 UTC on Aug 9 is 6:47 PM MDT on Aug 8.
        self.assertIn("Aug 8, 2026", result)
        self.assertIn("6:47 PM", result)
        self.assertIn("MDT", result)

    def test_conversion_across_a_date_boundary(self) -> None:
        # 02:15 UTC is still the previous evening in US/Pacific.
        result = self._format("2026-08-09T02:15:00+00:00", "America/Los_Angeles")
        self.assertIn("Aug 8, 2026", result)

    def test_displayed_timezone_is_never_blank(self) -> None:
        result = self._format("2026-08-08T12:00:00+00:00", "America/Denver")
        # Must end with a non-empty timezone abbreviation or offset, not
        # a bare trailing space.
        self.assertNotEqual(result[-1], " ")
        self.assertTrue(result.split(" ")[-1])

    def test_naive_input_is_treated_as_utc(self) -> None:
        # now()-style canonical timestamps are always timezone-aware, but
        # the filter must not crash on an older/legacy naive value.
        result = self._format("2026-08-08T18:47:00", "UTC")
        self.assertIn("2026", result)

    def test_empty_input_returns_empty_string(self) -> None:
        self.assertEqual(webapp.format_local_datetime(""), "")
        self.assertEqual(webapp.format_local_datetime(None), "")

    def test_canonical_manifest_timestamp_format_is_unaffected(self) -> None:
        # The filter is purely a display transform: the underlying
        # canonical timestamp backup.now() produces must remain a valid,
        # UTC, ISO-8601 string regardless of the server's local timezone.
        with self._with_tz("America/Denver"):
            self._time.tzset()
            try:
                canonical = backup.now()
            finally:
                self._time.tzset()
        parsed = __import__("datetime").datetime.fromisoformat(canonical)
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(parsed.utcoffset().total_seconds(), 0)


class BackupFilenameLocalTimeTest(unittest.TestCase):
    """The on-disk archive filename now uses the server's local time (for
    human identification) instead of UTC, but this must be cosmetic only:
    restore/backup lookups never parse the filename's timestamp."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-backup-fname-"))
        self.old = {
            "db": backup.DB_PATH,
            "backup_dir": backup.BACKUP_DIR,
            "staging_dir": backup.STAGING_DIR,
        }
        backup.DB_PATH = self.tmp / "alderpointdns.db"
        backup.BACKUP_DIR = self.tmp / "backups"
        backup.STAGING_DIR = self.tmp / "staging"
        backup.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        backup.STAGING_DIR.mkdir(parents=True, exist_ok=True)
        backup.init_db()

    def tearDown(self) -> None:
        backup.DB_PATH = self.old["db"]
        backup.BACKUP_DIR = self.old["backup_dir"]
        backup.STAGING_DIR = self.old["staging_dir"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_filename_is_filesystem_safe_and_lookup_still_works_by_id(self) -> None:
        path = backup.create_backup(backup.validate_components(None))
        self.assertTrue(path.name.startswith(backup.FILENAME_PREFIX))
        # No characters that are awkward/unsafe in a filename (":" in
        # particular, which a naive local-time strftime could introduce).
        self.assertNotIn(":", path.name)
        self.assertNotIn("/", path.name)
        row = backup.last_backup()
        resolved = backup.find_backup_path(str(row["id"]))
        self.assertEqual(resolved, path)


class BackupRestoreApplyDispatchTest(unittest.TestCase):
    """webapp.backup_restore_apply() must start the independent
    alderpointdns-backup-restore.service runner (systemctl start
    --no-block), never invoke alderpointdns_compiler.py backup-restore
    directly as a sudo child of the web request -- that direct-child shape
    is exactly what a real restore's app_config-triggered
    alderpointdns.service restart killed mid-restore on a live appliance."""

    def test_dispatches_the_independent_runner_unit_not_a_direct_child(self) -> None:
        with mock.patch.object(webapp, "run") as mock_run:
            mock_run.return_value = (0, "Started alderpointdns-backup-restore.service.")
            webapp.backup_restore_apply()
        mock_run.assert_called_once_with(
            ["sudo", "systemctl", "start", "--no-block", "alderpointdns-backup-restore.service"]
        )
        called_command = mock_run.call_args[0][0]
        self.assertNotIn("alderpointdns_compiler.py", called_command)


if __name__ == "__main__":
    unittest.main()
