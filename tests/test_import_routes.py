#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from starlette.requests import Request
from starlette.routing import Match

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import alderpointdns_compiler, custom_rules, importer, local_dns, upstream_dns, webapp  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
PIHOLE_FIXTURE = (FIXTURES / "pihole_export.txt").read_text()

ADGUARD_YAML = """
filters:
  - {name: EasyList, url: https://filters.example/list.txt, enabled: true}
user_rules:
  - '||ads.example^'
  - '@@||safe.example^'
filtering:
  rewrites:
    - {domain: nas.home.arpa, answer: 192.168.1.50}
clients:
  persistent:
    - {name: Phone, ids: ['192.168.1.77'], filtering_enabled: true}
dns:
  bootstrap_dns: ['1.1.1.1']
  upstream_dns:
    - 'https://dns.example/dns-query'
    - '[/corp.example/]10.0.0.53'
"""


class ImportRouteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-import-routes-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "importer_db": importer.DB_PATH,
            "local_dns_db": local_dns.DB_PATH,
            "upstream_dns_db": upstream_dns.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "custom_rules_db": custom_rules.DB_PATH,
            "import_dir": importer.IMPORT_UPLOAD_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        webapp.DB_PATH = db_path
        importer.DB_PATH = db_path
        local_dns.DB_PATH = db_path
        upstream_dns.DB_PATH = db_path
        alderpointdns_compiler.DB_PATH = db_path
        custom_rules.DB_PATH = db_path
        importer.IMPORT_UPLOAD_DIR = self.tmp / "imports"
        local_dns.init_db()
        upstream_dns.init_db()
        alderpointdns_compiler.init_db()
        importer.init_db()
        custom_rules.init_db()
        self.patches = [
            mock.patch.object(webapp, "deploy_no_download", lambda: (0, "ok")),
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            # create_pre_import_backup() runs the privileged
            # `sudo alderpointdns_compiler.py backup-create` command; stub the
            # single subprocess.run call site so tests never invoke real sudo.
            mock.patch.object(
                importer.subprocess, "run",
                return_value=subprocess.CompletedProcess(importer.PRE_IMPORT_BACKUP_COMMAND, 0, "backup_path=/tmp/pre-import-backup.tar\n", ""),
            ),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        webapp.DB_PATH = self.old_paths["webapp_db"]
        importer.DB_PATH = self.old_paths["importer_db"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        upstream_dns.DB_PATH = self.old_paths["upstream_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        custom_rules.DB_PATH = self.old_paths["custom_rules_db"]
        importer.IMPORT_UPLOAD_DIR = self.old_paths["import_dir"]
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _match(self, path: str, method: str = "GET"):
        scope = {"type": "http", "path": path, "method": method}
        for route in webapp.app.routes:
            match, _child_scope = route.matches(scope)
            if match == Match.FULL:
                return route
        return None

    def _create_migration_job(self) -> int:
        translation = importer.parse_adguard_yaml(ADGUARD_YAML)
        job_id = importer.create_migration_job("adguard_yaml", "AdGuardHome.yaml", translation)
        importer.migration_preview_job(job_id)
        return job_id

    def _create_pihole_migration_job(self) -> int:
        translation = importer.parse_pihole_text(PIHOLE_FIXTURE, "home.arpa")
        job_id = importer.create_migration_job("pihole", "pihole_export.txt", translation)
        importer.migration_preview_job(job_id, "home.arpa")
        return job_id

    @staticmethod
    def _fake_request(path: str) -> Request:
        return Request(
            {
                "type": "http",
                "method": "GET",
                "path": path,
                "headers": [(b"accept", b"text/html")],
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
                "client": ("127.0.0.1", 12345),
            }
        )

    def test_import_migration_literal_reaches_migration_handler(self) -> None:
        route = self._match("/import/migration")
        self.assertIsNotNone(route)
        self.assertEqual(route.endpoint, webapp.import_migration_page)
        self.assertIsNone(self._match("/import/migration", "POST"))

    def test_literal_routes_are_not_job_routes(self) -> None:
        route_paths = {getattr(route, "path", "") for route in webapp.app.routes}
        self.assertIn("/import/migration", route_paths)
        self.assertIn("/import/jobs/{job_id}", route_paths)
        self.assertNotIn("/import/{job_id}", route_paths)
        self.assertEqual(self._match("/import/migration").endpoint, webapp.import_migration_page)
        self.assertEqual(self._match("/import/upload", "POST").endpoint, webapp.import_upload)
        self.assertEqual(self._match("/import/jobs/123").endpoint, webapp.import_job_page)
        self.assertEqual(self._match("/import/jobs/123/status").endpoint, webapp.import_job_status)
        self.assertIsNotNone(self._match("/import/jobs/migration"))

    def test_browser_validation_error_is_friendly_html(self) -> None:
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/import/jobs/migration",
                "headers": [(b"accept", b"text/html")],
                "query_string": b"",
                "server": ("testserver", 80),
                "scheme": "http",
                "client": ("127.0.0.1", 12345),
            }
        )
        exc = webapp.RequestValidationError([{"loc": ("path", "job_id"), "msg": "bad", "type": "int_parsing"}])
        response = asyncio.run(webapp.validation_exception_handler(request, exc))
        body = response.body.decode()
        self.assertEqual(response.status_code, 404)
        self.assertIn("not valid", body)
        self.assertNotIn("int_parsing", body)

    def test_migration_job_status_preview_apply_duplicate_apply_and_report(self) -> None:
        job_id = self._create_migration_job()
        job = importer.get_job(job_id)
        self.assertEqual(job["status"], "previewed")
        preview = importer.migration_preview_job(job_id)
        category_names = {section["name"] for section in preview["summary"]["categories"]}
        self.assertIn("upstreams", category_names)
        result = importer.apply_migration_job(job_id)
        counts = result["counts"]
        self.assertEqual(counts["blocklists_added"], 1)
        self.assertEqual(counts["block_rules"], 1)
        self.assertEqual(counts["allow_rules"], 1)
        self.assertEqual(counts["local_dns_records"], 1)
        self.assertEqual(counts["client_aliases"], 1)
        self.assertEqual(counts["upstream_resolvers"], 1)
        with sqlite3.connect(importer.DB_PATH) as conn:
            db_counts = {
                "sources": conn.execute("SELECT count(*) FROM sources").fetchone()[0],
                "legacy_rules": conn.execute("SELECT count(*) FROM custom_rules").fetchone()[0],
                "rules": conn.execute("SELECT count(*) FROM custom_filter_rules WHERE import_job_id=?", (job_id,)).fetchone()[0],
                "records": conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0],
                "aliases": conn.execute("SELECT count(*) FROM client_aliases").fetchone()[0],
                "upstreams": conn.execute("SELECT count(*) FROM upstream_resolvers WHERE address='dns.example' AND doh_path='/dns-query'").fetchone()[0],
            }
        self.assertEqual(db_counts, {"sources": 1, "legacy_rules": 0, "rules": 2, "records": 1, "aliases": 1, "upstreams": 1})
        with self.assertRaises(importer.ImportError_):
            importer.apply_migration_job(job_id)
        self.assertEqual(importer.get_job(job_id)["status"], "applied")
        self.assertIn("counts", importer.get_job(job_id)["report_json"])

    def test_selective_apply_honors_item_and_category_deselection(self) -> None:
        job_id = self._create_migration_job()
        preview = importer.migration_preview_job(job_id)
        selected = {
            item["key"]
            for section in preview["summary"]["categories"]
            for item in section["items"]
            if item["selected"]
        }
        selected.discard("custom_allows:0")
        selected = {key for key in selected if not key.startswith("local_dns:")}
        importer.apply_migration_job(job_id, selected=selected)
        with sqlite3.connect(importer.DB_PATH) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_filter_rules WHERE action='allow'").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_filter_rules WHERE action='block'").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 1)

    def test_pihole_migration_job_status_preview_apply_and_report(self) -> None:
        # End-to-end route-layer coverage for Pi-hole, mirroring
        # test_migration_job_status_preview_apply_duplicate_apply_and_report
        # above for AdGuard: this exercises the exact same
        # /import/jobs/{id}/preview -> apply -> report pipeline against the
        # synthetic Pi-hole fixture, not just importer functions in
        # isolation.
        job_id = self._create_pihole_migration_job()
        job = importer.get_job(job_id)
        self.assertEqual(job["status"], "previewed")
        self.assertEqual(job["source_type"], "pihole")
        preview_response = webapp.import_job_preview(
            self._fake_request(f"/import/jobs/{job_id}/preview"),
            job_id=job_id,
            _=None,
        )
        self.assertEqual(preview_response.status_code, 200)
        body = preview_response.body.decode()
        self.assertIn("Pi-hole Migration Preview", body)
        result = importer.apply_migration_job(job_id, default_domain="home.arpa")
        counts = result["counts"]
        self.assertGreater(counts["blocklists_added"], 0)
        self.assertGreater(counts["block_rules"], 0)
        self.assertGreater(counts["local_dns_records"], 0)
        with sqlite3.connect(importer.DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rules = conn.execute("SELECT * FROM custom_filter_rules").fetchall()
            self.assertTrue(all(row["source_system"] == "pihole" for row in rules))
            self.assertTrue(all(row["import_job_id"] == job_id for row in rules))
        report_response = webapp.import_job_report(job_id=job_id, _=None)
        self.assertEqual(report_response.media_type, "application/json")
        self.assertIn("attachment", report_response.headers.get("content-disposition", ""))
        self.assertEqual(importer.get_job(job_id)["status"], "applied")

    def test_pihole_migration_rollback_after_apply(self) -> None:
        job_id = self._create_pihole_migration_job()
        importer.apply_migration_job(job_id, default_domain="home.arpa")
        removed = importer.rollback_job(job_id)
        self.assertGreater(removed, 0)
        self.assertEqual(importer.get_job(job_id)["status"], "rolled_back")
        with sqlite3.connect(importer.DB_PATH) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_filter_rules").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 0)

    def test_cancel_migration_job(self) -> None:
        job_id = self._create_migration_job()
        importer.cancel_job(job_id)
        self.assertEqual(importer.get_job(job_id)["status"], "canceled")

    def test_failed_parsing_leaves_no_job_or_staged_file(self) -> None:
        source_path = None
        try:
            data = b"not-a-dict"
            source_path = importer.stage_uploaded_source("AdGuardHome.yaml", data)
            importer.parse_adguard_yaml(data.decode())
        except Exception:
            if source_path and source_path.exists():
                source_path.unlink(missing_ok=True)
        self.assertEqual(importer.list_jobs(), [])
        self.assertFalse(any(importer.IMPORT_UPLOAD_DIR.glob("*")) if importer.IMPORT_UPLOAD_DIR.exists() else False)

    def test_failed_application_rolls_back_cleanly(self) -> None:
        job_id = self._create_migration_job()
        with mock.patch.object(importer, "_apply_alias_item", side_effect=RuntimeError("injected failure")):
            with self.assertRaises(ValueError):
                importer.apply_migration_job(job_id)
        job = importer.get_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIn("client alias", job["message"])
        with sqlite3.connect(importer.DB_PATH) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_rules").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_filter_rules").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM client_aliases").fetchone()[0], 0)

    def test_migration_rollback_after_apply(self) -> None:
        job_id = self._create_migration_job()
        importer.apply_migration_job(job_id)
        removed = importer.rollback_job(job_id)
        self.assertGreater(removed, 0)
        self.assertEqual(importer.get_job(job_id)["status"], "rolled_back")
        with sqlite3.connect(importer.DB_PATH) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_filter_rules").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0], 0)

    def test_report_download_is_json_attachment_and_sanitized(self) -> None:
        translation = importer.parse_adguard_yaml(ADGUARD_YAML)
        translation["blocklist_sources"].append(
            {"name": "Tokened", "url": "https://user:hunter2@lists.example/private.txt?token=tok123secret", "enabled": True}
        )
        job_id = importer.create_migration_job("adguard_yaml", "with-token", translation)
        importer.migration_preview_job(job_id)
        response = webapp.import_job_report(job_id=job_id, _=None)
        self.assertEqual(response.media_type, "application/json")
        self.assertIn("attachment", response.headers.get("content-disposition", ""))
        body = response.body.decode()
        self.assertNotIn("hunter2", body)
        self.assertNotIn("tok123secret", body)
        self.assertIn("lists.example", body)

    def test_preview_template_renders_itemized_selection(self) -> None:
        template = (ROOT / "web" / "templates" / "import_migration.html").read_text()
        for expected in (
            'name="sel"',
            'value="{{ item.key }}"',
            'name="itemized"',
            "cat-toggle",
            "migration_summary.categories",
            "<details",
        ):
            self.assertIn(expected, template)
        self.assertNotIn("group_blocklist_sources", template)
        self.assertNotIn("translation_json", template)

    def test_adguard_api_job_name_is_sanitized(self) -> None:
        self.assertEqual(
            importer.sanitize_adguard_base_url("http://admin:secretpw@192.0.2.10:3000"),
            "http://192.0.2.10:3000",
        )
        with self.assertRaises(importer.ImportError_):
            importer.sanitize_adguard_base_url("gopher://192.0.2.10")

    def test_form_actions_and_openapi_use_canonical_routes(self) -> None:
        template = (ROOT / "web" / "templates" / "import_migration.html").read_text()
        for expected in (
            'action="/import/upload"',
            'action="/import/migration/adguard/yaml"',
            'action="/import/migration/adguard/api"',
            'href="/import/jobs/{{ j.id }}"',
            'action="/import/jobs/{{ job.id }}/remap"',
            'action="/import/jobs/{{ job.id }}/apply"',
            'action="/import/jobs/{{ migration_job_id }}/apply"',
            'action="/import/jobs/{{ migration_job_id }}/cancel"',
        ):
            self.assertIn(expected, template)
        for obsolete in ('/import/{{ j.id }}', '/import/{{ job.id }}', '/import/adguard/', '/import/migration/apply'):
            self.assertNotIn(obsolete, template)
        paths = set(webapp.app.openapi()["paths"])
        for expected in (
            "/import",
            "/import/migration",
            "/import/upload",
            "/import/jobs/{job_id}",
            "/import/jobs/{job_id}/status",
            "/import/jobs/{job_id}/preview",
            "/import/jobs/{job_id}/apply",
            "/import/jobs/{job_id}/cancel",
            "/import/jobs/{job_id}/report",
            "/import/migration/adguard/yaml",
            "/import/migration/adguard/api",
        ):
            self.assertIn(expected, paths)
        self.assertNotIn("/import/{job_id}", paths)


class ImportUploadHttpTest(unittest.TestCase):
    """Genuine HTTP round-trip through /import/upload (multipart file
    upload, real ASGI request/response cycle via TestClient) -- the route
    tests above call importer/webapp functions directly and never actually
    exercise upload.read()/stage_uploaded_source() through a real request,
    for any source type. Covers both AdGuard YAML and the Pi-hole export
    fixture through the exact form the web UI submits."""

    def setUp(self) -> None:
        from fastapi.templating import Jinja2Templates
        from fastapi.testclient import TestClient

        from app import replication

        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-import-upload-http-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "importer_db": importer.DB_PATH,
            "local_dns_db": local_dns.DB_PATH,
            "upstream_dns_db": upstream_dns.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "custom_rules_db": custom_rules.DB_PATH,
            "import_dir": importer.IMPORT_UPLOAD_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        webapp.DB_PATH = db_path
        importer.DB_PATH = db_path
        local_dns.DB_PATH = db_path
        upstream_dns.DB_PATH = db_path
        alderpointdns_compiler.DB_PATH = db_path
        custom_rules.DB_PATH = db_path
        importer.IMPORT_UPLOAD_DIR = self.tmp / "imports"
        local_dns.init_db()
        upstream_dns.init_db()
        alderpointdns_compiler.init_db()
        importer.init_db()
        custom_rules.init_db()
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
        self.patches = [
            mock.patch.object(webapp, "deploy_no_download", lambda: (0, "ok")),
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(replication, "autostart", lambda: None),
            mock.patch.object(
                importer.subprocess, "run",
                return_value=subprocess.CompletedProcess(importer.PRE_IMPORT_BACKUP_COMMAND, 0, "backup_path=/tmp/pre-import-backup.tar\n", ""),
            ),
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
        self.client.cookies.set(
            "alderpointdns_session",
            webapp.serializer.dumps({"sid": session_id}),
        )

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        webapp.DB_PATH = self.old_paths["webapp_db"]
        importer.DB_PATH = self.old_paths["importer_db"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        upstream_dns.DB_PATH = self.old_paths["upstream_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        custom_rules.DB_PATH = self.old_paths["custom_rules_db"]
        importer.IMPORT_UPLOAD_DIR = self.old_paths["import_dir"]
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_pihole_file_upload_reaches_preview_with_counts(self) -> None:
        response = self.client.post(
            "/import/upload",
            data={"csrf": self.csrf, "source_type": "pihole", "default_domain": "home.arpa"},
            files={"upload": ("pihole_export.txt", PIHOLE_FIXTURE, "text/plain")},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Pi-hole Migration Preview", response.text)
        self.assertIn('name="sel"', response.text)
        with sqlite3.connect(importer.DB_PATH) as conn:
            job = conn.execute("SELECT id, source_type, status FROM import_jobs ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(job[1], "pihole")
        self.assertEqual(job[2], "previewed")

        # Applying through the same route the "Apply selected items" button
        # posts to must actually create the objects the preview promised.
        job_id = job[0]
        apply_response = self.client.post(
            f"/import/jobs/{job_id}/apply",
            data={"csrf": self.csrf},
            follow_redirects=False,
        )
        self.assertEqual(apply_response.status_code, 303)
        with sqlite3.connect(importer.DB_PATH) as conn:
            self.assertGreater(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 0)
            self.assertGreater(conn.execute("SELECT count(*) FROM custom_filter_rules").fetchone()[0], 0)

    def test_adguard_yaml_file_upload_reaches_preview(self) -> None:
        response = self.client.post(
            "/import/migration/adguard/yaml",
            data={"csrf": self.csrf},
            files={"upload": ("AdGuardHome.yaml", ADGUARD_YAML, "application/x-yaml")},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("AdGuard Home Migration Preview", response.text)
        with sqlite3.connect(importer.DB_PATH) as conn:
            job = conn.execute("SELECT source_type, status FROM import_jobs ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(job, ("adguard_yaml", "previewed"))

    def test_adguard_rewrites_apply_through_real_route_reports_local_dns_breakdown(self) -> None:
        # End-to-end regression coverage for a real-world failure: a
        # migration job reported plain "Applied" with the correct total
        # object count, but none of the uploaded AdGuardHome.yaml's DNS
        # rewrites actually showed up in Alderpoint DNS. This drives the
        # exact same upload -> preview -> apply HTTP round trip the web UI
        # uses and asserts the Local DNS records exist afterward, and that
        # the job page explicitly reports a Local DNS count rather than a
        # bare "Applied" status.
        rewrites_yaml = (FIXTURES / "adguard_rewrites.yaml").read_text()
        response = self.client.post(
            "/import/migration/adguard/yaml",
            data={"csrf": self.csrf},
            files={"upload": ("adguard_rewrites.yaml", rewrites_yaml, "application/x-yaml")},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("AdGuard Home Migration Preview", response.text)
        self.assertIn("disabled at source", response.text)
        with sqlite3.connect(importer.DB_PATH) as conn:
            job = conn.execute("SELECT id FROM import_jobs ORDER BY id DESC LIMIT 1").fetchone()
        job_id = job[0]

        apply_response = self.client.post(f"/import/jobs/{job_id}/apply", data={"csrf": self.csrf}, follow_redirects=True)
        self.assertEqual(apply_response.status_code, 200)
        self.assertIn("Local DNS: 5 created", apply_response.text)
        self.assertIn("Applied with conflicts", apply_response.text)

        with sqlite3.connect(importer.DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = {(r["fqdn"], r["record_type"], r["value"]): r["enabled"] for r in conn.execute("SELECT fqdn, record_type, value, enabled FROM local_dns_records")}
        self.assertEqual(rows[("nas.home.arpa", "A", "192.168.1.50")], 1)
        self.assertEqual(rows[("retired.home.arpa", "A", "192.168.1.60")], 0)

        # Re-uploading and re-applying the identical file through the real
        # route must not duplicate any Local DNS record.
        response2 = self.client.post(
            "/import/migration/adguard/yaml",
            data={"csrf": self.csrf},
            files={"upload": ("adguard_rewrites.yaml", rewrites_yaml, "application/x-yaml")},
            follow_redirects=True,
        )
        with sqlite3.connect(importer.DB_PATH) as conn:
            job2 = conn.execute("SELECT id FROM import_jobs ORDER BY id DESC LIMIT 1").fetchone()
        job2_id = job2[0]
        apply_response2 = self.client.post(f"/import/jobs/{job2_id}/apply", data={"csrf": self.csrf}, follow_redirects=True)
        self.assertIn("Local DNS: 0 created", apply_response2.text)
        with sqlite3.connect(importer.DB_PATH) as conn:
            record_count = conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0]
        self.assertEqual(record_count, 5, "re-importing the identical AdGuard rewrites through the real route must not duplicate Local DNS rows")

    def test_adguard_schema34_apply_keeps_rewrites_off_the_custom_rules_page(self) -> None:
        # Regression coverage for a real schema_version: 34 AdGuardHome.yaml
        # where every DNS rewrite named a host under the operator's own LAN
        # domain (not Alderpoint DNS's internal domain) -- these must land
        # on the Local DNS page, never the Custom Filtering Rules page, no
        # matter which domain they use.
        schema34_yaml = (FIXTURES / "adguard_schema34.yaml").read_text()
        response = self.client.post(
            "/import/migration/adguard/yaml",
            data={"csrf": self.csrf},
            files={"upload": ("adguard_schema34.yaml", schema34_yaml, "application/x-yaml")},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        with sqlite3.connect(importer.DB_PATH) as conn:
            job = conn.execute("SELECT id FROM import_jobs ORDER BY id DESC LIMIT 1").fetchone()
        job_id = job[0]

        apply_response = self.client.post(f"/import/jobs/{job_id}/apply", data={"csrf": self.csrf}, follow_redirects=True)
        self.assertEqual(apply_response.status_code, 200)
        self.assertIn("Blocklists: 18 created", apply_response.text)
        self.assertIn("Custom rules: 28 created", apply_response.text)
        self.assertIn("Local DNS: 44 created", apply_response.text)

        local_dns_page = self.client.get("/local-dns")
        self.assertEqual(local_dns_page.status_code, 200)
        self.assertIn("host01.internal.example", local_dns_page.text)
        self.assertIn("host44.internal.example", local_dns_page.text)

        custom_rules_page = self.client.get("/custom-rules")
        self.assertEqual(custom_rules_page.status_code, 200)
        self.assertIn("login.live.com", custom_rules_page.text)
        self.assertNotIn("internal.example", custom_rules_page.text)
        self.assertNotIn("host01", custom_rules_page.text)

    def test_pihole_import_panel_present_on_import_page(self) -> None:
        response = self.client.get("/import")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Pi-hole Migration", response.text)
        self.assertIn('value="pihole"', response.text)
        self.assertIn('action="/import/upload"', response.text)


if __name__ == "__main__":
    unittest.main()
