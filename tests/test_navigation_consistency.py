#!/usr/bin/env python3
"""Regression coverage for the pre-1.0 navigation cleanup:

  - Backup & Restore moved from System to Operations (Import, Backup &
    Restore, Replication), keeping its existing /backup route.
  - Network Configuration, Software Updates, and Administration remain
    direct System submenu destinations.
  - Administration no longer carries launcher cards that just point back
    to Network Configuration/Software Updates (already directly reachable
    from the System submenu one level away) -- but still owns the actual
    administrator password/session functionality.
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

INITIAL_PASSWORD = "initial-password-123"


class NavigationConsistencyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-nav-test-"))
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

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        webapp.DB_PATH = self.old_paths["webapp_db"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        alderpointdns_compiler.MIGRATION_LOCK = self.old_paths["compiler_migration_lock"]
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- Operations now contains Backup & Restore, in the required order --

    def test_operations_section_lists_import_backup_replication_in_order(self) -> None:
        html = self.client.get("/import").text
        operations_panel = re.search(r'id="nav-panel-operations"[^>]*>.*?</div>', html, re.S)
        self.assertIsNotNone(operations_panel, "Operations nav panel not found")
        panel_html = operations_panel.group(0)
        import_pos = panel_html.index('href="/import"')
        backup_pos = panel_html.index('href="/backup"')
        replication_pos = panel_html.index('href="/replication"')
        self.assertLess(import_pos, backup_pos, "Backup & Restore must come after Import")
        self.assertLess(backup_pos, replication_pos, "Backup & Restore must come before Replication")

    def test_backup_route_still_works_unchanged(self) -> None:
        response = self.client.get("/backup")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Backup and Restore", response.text)

    def test_backup_page_marks_operations_section_active_not_system(self) -> None:
        html = self.client.get("/backup").text
        self.assertIn('data-nav-section="operations"', html)
        # The Operations section's own toggle button must carry the active
        # state (aria-expanded/aria-current) that used to sit on System.
        operations_button = re.search(r'data-nav-section-toggle[^>]*aria-controls="nav-panel-operations"[^>]*', html)
        self.assertIsNotNone(operations_button)
        self.assertIn('aria-current="true"', operations_button.group(0))
        system_button = re.search(r'data-nav-section-toggle[^>]*aria-controls="nav-panel-system"[^>]*', html)
        self.assertIsNotNone(system_button)
        self.assertNotIn('aria-current="true"', system_button.group(0))

    # -- System keeps Network Configuration, Software Updates, Administration --

    def test_system_section_still_lists_network_config_software_updates_administration(self) -> None:
        html = self.client.get("/system").text
        system_panel = re.search(r'id="nav-panel-system"[^>]*>.*?</div>', html, re.S)
        self.assertIsNotNone(system_panel)
        panel_html = system_panel.group(0)
        for expected_href in ("/system/network", "/system/administration", "/system/administration/software-updates"):
            self.assertIn(f'href="{expected_href}"', panel_html)
        # Backup & Restore must no longer be listed under System.
        self.assertNotIn('href="/backup"', panel_html)

    # -- Administration keeps password/session management, drops the
    # redundant Network Configuration / Software Updates launcher cards --

    def test_administration_page_still_has_password_and_sessions(self) -> None:
        html = self.client.get("/system/administration").text
        self.assertIn('action="/system/administration/password"', html)
        self.assertIn('action="/system/administration/revoke-sessions"', html)

    def _administration_main_content(self) -> str:
        """Everything below `<main class="app-main">` -- excludes the
        sidebar nav, which legitimately links to /system/network and
        /system/administration/software-updates as System submenu items on
        every page, including this one."""
        html = self.client.get("/system/administration").text
        idx = html.index('<main class="app-main">')
        return html[idx:]

    def test_administration_page_no_longer_links_out_to_network_or_software_updates(self) -> None:
        content = self._administration_main_content()
        self.assertNotIn("Open Network Configuration", content)
        self.assertNotIn("Open Software Updates", content)
        self.assertNotIn('href="/system/network"', content)
        self.assertNotIn('href="/system/administration/software-updates"', content)

    def test_administration_page_no_longer_has_its_own_backup_launcher_card(self) -> None:
        """Same class of redundancy as the two the spec named explicitly:
        Backup & Restore is now directly one click away in Operations, so
        Administration duplicating it with its own card/buttons is exactly
        the pattern being cleaned up."""
        content = self._administration_main_content()
        self.assertNotIn("Create Backup</a>", content)
        self.assertNotIn("Restore Alderpoint Backup</a>", content)


if __name__ == "__main__":
    unittest.main()
