#!/usr/bin/env python3
"""HTTP round-trip coverage for /system/network through the real FastAPI
routes. The privileged-helper hop (sudo alderpointdns_compiler.py
network-*) is simulated the same way tests/test_backup_routes.py simulates
backup's privileged hop: by running the pending-request processor inline.
No real network interface is ever touched -- every backend-apply function
is mocked."""
from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import alderpointdns_compiler, network_config as nc, webapp  # noqa: E402


class NetworkRoutesTest(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.templating import Jinja2Templates
        from fastapi.testclient import TestClient

        from app import replication

        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-network-routes-"))
        self.old = {
            "webapp_db": webapp.DB_PATH,
            "nc_db": nc.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "STATE_DIR": nc.STATE_DIR,
            "ROLLBACK_STATE_FILE": nc.ROLLBACK_STATE_FILE,
            "NETWORKD_DROPIN_DIR": nc.NETWORKD_DROPIN_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        webapp.DB_PATH = db_path
        nc.DB_PATH = db_path
        alderpointdns_compiler.DB_PATH = db_path
        nc.STATE_DIR = self.tmp / "network"
        nc.ROLLBACK_STATE_FILE = nc.STATE_DIR / "rollback-state.json"
        nc.NETWORKD_DROPIN_DIR = self.tmp / "systemd-network"
        nc.NETWORKD_DROPIN_DIR.mkdir(parents=True)

        alderpointdns_compiler.init_db()
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

        self.backend_patch = mock.patch.object(nc, "detect_backend", return_value={"backend": nc.BACKEND_NETWORKD, "ambiguous": False, "detail": "test"})
        self.list_patch = mock.patch.object(nc, "list_interfaces", return_value=["eth0"])
        self.addr_patch = mock.patch.object(nc, "all_local_addresses", return_value=set())
        self.iface_addr_patch = mock.patch.object(nc, "interface_addresses", return_value={"ipv4": [{"address": "192.168.1.5", "prefixlen": 24}], "ipv6": []})
        self.gw_patch = mock.patch.object(nc, "default_gateway", return_value="192.168.1.1")
        self.route_iface_patch = mock.patch.object(nc, "default_route_interface", return_value="eth0")
        self.apply_networkd_patch = mock.patch.object(nc, "apply_networkd")
        self.timer_patch = mock.patch.object(nc, "schedule_rollback_timer", return_value="alderpointdns-network-rollback-test")
        self.cancel_patch = mock.patch.object(nc, "cancel_rollback_timer")

        self.patches = [
            self.backend_patch, self.list_patch, self.addr_patch, self.iface_addr_patch, self.gw_patch,
            self.route_iface_patch, self.apply_networkd_patch, self.timer_patch, self.cancel_patch,
            mock.patch.object(webapp, "network_apply_apply", lambda: nc.process_pending_request("apply")),
            mock.patch.object(webapp, "network_confirm_apply", lambda: nc.process_pending_request("confirm")),
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(replication, "autostart", lambda: None),
            mock.patch.object(webapp, "TEMPLATES", Jinja2Templates(directory=str(ROOT / "web" / "templates"))),
        ]
        for p in self.patches:
            p.start()
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
        for p in reversed(self.patches):
            p.stop()
        webapp.DB_PATH = self.old["webapp_db"]
        nc.DB_PATH = self.old["nc_db"]
        alderpointdns_compiler.DB_PATH = self.old["compiler_db"]
        nc.STATE_DIR = self.old["STATE_DIR"]
        nc.ROLLBACK_STATE_FILE = self.old["ROLLBACK_STATE_FILE"]
        nc.NETWORKD_DROPIN_DIR = self.old["NETWORKD_DROPIN_DIR"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_network_page_shows_detected_backend_and_current_state(self) -> None:
        response = self.client.get("/system/network")
        self.assertEqual(response.status_code, 200)
        self.assertIn("systemd-networkd", response.text)
        self.assertIn("192.168.1.5", response.text)

    def test_invalid_submission_rejected_before_reaching_privileged_helper(self) -> None:
        response = self.client.post(
            "/system/network/apply",
            data={"csrf": self.csrf, "interface": "eth0", "ipv4_mode": "static", "ipv4_address": "bad-ip", "ipv4_prefix": "24", "ipv4_gateway": "192.168.1.1"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("invalid IPv4 address", response.text)
        self.assertIsNone(nc.read_rollback_state())

    def test_valid_apply_arms_rollback_and_shows_confirmation_banner(self) -> None:
        response = self.client.post(
            "/system/network/apply",
            data={"csrf": self.csrf, "interface": "eth0", "ipv4_mode": "static", "ipv4_address": "192.168.1.10", "ipv4_prefix": "24", "ipv4_gateway": "192.168.1.1"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Network configuration changed", response.text)
        self.assertIn("192.168.1.10", response.text)
        state = nc.read_rollback_state()
        self.assertIsNotNone(state)
        self.assertFalse(state["confirmed"])

    def test_confirm_route_cancels_rollback_and_removes_pending_banner(self) -> None:
        self.client.post(
            "/system/network/apply",
            data={"csrf": self.csrf, "interface": "eth0", "ipv4_mode": "static", "ipv4_address": "192.168.1.10", "ipv4_prefix": "24", "ipv4_gateway": "192.168.1.1"},
        )
        self.assertIsNotNone(nc.read_rollback_state())
        response = self.client.post("/system/network/confirm", data={"csrf": self.csrf}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(nc.read_rollback_state())
        self.assertNotIn("Network configuration changed", response.text)
        nc.cancel_rollback_timer.assert_called_with("alderpointdns-network-rollback-test")


if __name__ == "__main__":
    unittest.main()
