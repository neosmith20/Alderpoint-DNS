#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import sqlite3
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

from app import alderpointdns_compiler, importer, local_dns, upstream_dns, webapp  # noqa: E402


ADGUARD_YAML = """
filters:
  - {name: EasyList, url: https://filters.example/list.txt, enabled: true}
user_rules:
  - '||ads.example^'
  - '@@||safe.example^'
filtering:
  rewrites:
    - {domain: nas.home.arpa, answer: 172.16.43.50}
clients:
  persistent:
    - {name: Phone, ids: ['172.16.43.77'], filtering_enabled: true}
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
            "import_dir": importer.IMPORT_UPLOAD_DIR,
            "backup_script": importer.BACKUP_SCRIPT,
        }
        db_path = self.tmp / "alderpointdns.db"
        webapp.DB_PATH = db_path
        importer.DB_PATH = db_path
        local_dns.DB_PATH = db_path
        upstream_dns.DB_PATH = db_path
        alderpointdns_compiler.DB_PATH = db_path
        importer.IMPORT_UPLOAD_DIR = self.tmp / "imports"
        importer.BACKUP_SCRIPT = self.tmp / "missing-backup.sh"
        local_dns.init_db()
        upstream_dns.init_db()
        alderpointdns_compiler.init_db()
        importer.init_db()
        self.patches = [
            mock.patch.object(webapp, "deploy_no_download", lambda: (0, "ok")),
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
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
        importer.IMPORT_UPLOAD_DIR = self.old_paths["import_dir"]
        importer.BACKUP_SCRIPT = self.old_paths["backup_script"]
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
        self.assertIn("upstream Imported upstream", "\n".join(preview["summary"]["items_to_add"]))
        counts = importer.apply_migration_job(job_id, {"blocklist_sources", "custom_rules", "rewrites", "clients", "upstream_resolvers"})
        self.assertEqual(counts, {"sources": 1, "custom_allow": 1, "custom_block": 1, "local_dns": 1, "aliases": 1, "upstream_resolvers": 1})
        with sqlite3.connect(importer.DB_PATH) as conn:
            db_counts = {
                "sources": conn.execute("SELECT count(*) FROM sources").fetchone()[0],
                "rules": conn.execute("SELECT count(*) FROM custom_rules").fetchone()[0],
                "records": conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0],
                "aliases": conn.execute("SELECT count(*) FROM client_aliases").fetchone()[0],
                "upstreams": conn.execute("SELECT count(*) FROM upstream_resolvers WHERE address='dns.example' AND doh_path='/dns-query'").fetchone()[0],
            }
        self.assertEqual(db_counts, {"sources": 1, "rules": 2, "records": 1, "aliases": 1, "upstreams": 1})
        with self.assertRaises(importer.ImportError_):
            importer.apply_migration_job(job_id, {"custom_rules"})
        self.assertEqual(importer.get_job(job_id)["status"], "applied")
        self.assertIn("sources", importer.get_job(job_id)["report_json"])

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
        translation = importer.parse_adguard_yaml(ADGUARD_YAML)
        translation["clients_as_aliases"].append({"display_name": "Bad", "cidr_or_ip": "not-a-network", "all_ids": []})
        job_id = importer.create_migration_job("adguard_yaml", "bad-client", translation)
        importer.migration_preview_job(job_id)
        with self.assertRaises(ValueError):
            importer.apply_migration_job(job_id, {"blocklist_sources", "custom_rules", "rewrites", "clients"})
        self.assertEqual(importer.get_job(job_id)["status"], "failed")
        with sqlite3.connect(importer.DB_PATH) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_rules").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM client_aliases").fetchone()[0], 0)

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


if __name__ == "__main__":
    unittest.main()
