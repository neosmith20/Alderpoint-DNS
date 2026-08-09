#!/usr/bin/env python3
"""Regression coverage for the Dashboard's "Top Clients" navigation bug:
clicking it used to land on the generic, unfiltered Query Log. It should
instead open a client-focused list, from which an individual client can
drill into the Query Log pre-filtered to that client.

  Dashboard -> Top Clients -> Clients list -> (per-client) filtered Query Log
"""
from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from app import alderpointdns_compiler as compiler  # noqa: E402
from app import analytics, local_dns, webapp  # noqa: E402


class DashboardClientsNavigationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-clients-nav-"))
        self.old = {
            "compiler_db": compiler.DB_PATH,
            "analytics_db": analytics.DB_PATH,
            "local_dns_db": local_dns.DB_PATH,
            "webapp_db": webapp.DB_PATH,
        }
        db_path = self.tmp / "alderpointdns.db"
        compiler.DB_PATH = db_path
        analytics.DB_PATH = db_path
        local_dns.DB_PATH = db_path
        webapp.DB_PATH = db_path

        analytics.init_analytics_db()

        now = int(time.time())
        with compiler.connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES ('admin', 'x', 'now')")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, admin_id INTEGER, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT, csrf TEXT NOT NULL)"
            )
            # Two clients' worth of query events, one of them alias-named
            # via local_dns so the label-vs-raw-address distinction is
            # exercised in both the dashboard panel and the clients list.
            events = [
                (now - 5, "192.168.1.50", "example.com", "A", "udp", "NOERROR", 0),
                (now - 4, "192.168.1.50", "example.org", "A", "udp", "NOERROR", 0),
                (now - 3, "192.168.1.51", "ads.example.net", "A", "udp", "NOERROR", 1),
                (now - 2, "192.168.1.51", "tracker.example.net", "A", "udp", "NOERROR", 1),
                (now - 1, "192.168.1.51", "example.com", "A", "udp", "NOERROR", 0),
            ]
            for ts, client, domain, qtype, protocol, rcode, blocked in events:
                conn.execute(
                    "INSERT INTO query_events(ts, client, domain, qtype, protocol, rcode, blocked) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ts, client, domain, qtype, protocol, rcode, blocked),
                )
            conn.commit()

        self.client = TestClient(webapp.app)
        self.csrf = "test-csrf-token"
        session_id = "test-session-id"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES (?, 1, 'now', 'now', '', '', ?)",
                (session_id, self.csrf),
            )
            conn.commit()
        self.client.cookies.set("alderpointdns_session", webapp.serializer.dumps({"sid": session_id}))

    def tearDown(self) -> None:
        compiler.DB_PATH = self.old["compiler_db"]
        analytics.DB_PATH = self.old["analytics_db"]
        local_dns.DB_PATH = self.old["local_dns_db"]
        webapp.DB_PATH = self.old["webapp_db"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- Dashboard panel no longer links to the generic Query Log --------

    def test_dashboard_top_clients_panel_links_to_clients_not_query_log(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        text = response.text
        top_clients_index = text.index("Top Clients")
        panel_head_end = text.index("</div>", top_clients_index)
        panel_head = text[top_clients_index:panel_head_end]
        self.assertIn('href="/clients', panel_head)
        self.assertNotIn('href="/query-log"', panel_head)

    def test_dashboard_still_renders_client_rows(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("192.168.1.51", response.text)

    # -- The new Clients view -------------------------------------------

    def test_clients_view_requires_authentication(self) -> None:
        anon = TestClient(webapp.app)
        response = anon.get("/clients", follow_redirects=False)
        self.assertIn(response.status_code, (302, 303, 401, 403))

    def test_clients_view_renders_ranked_client_data(self) -> None:
        response = self.client.get("/clients")
        self.assertEqual(response.status_code, 200)
        self.assertIn("192.168.1.50", response.text)
        self.assertIn("192.168.1.51", response.text)
        # The busier client (3 queries) should be ranked ahead of the
        # quieter one (2 queries).
        self.assertLess(response.text.index("192.168.1.51"), response.text.index("192.168.1.50"))

    def test_clients_view_respects_time_range(self) -> None:
        response = self.client.get("/clients?range=1h")
        self.assertEqual(response.status_code, 200)
        self.assertIn("192.168.1.50", response.text)

    def test_clients_view_alias_display_keeps_raw_client_in_link(self) -> None:
        local_dns.upsert_alias("192.168.1.50/32", "office-laptop")
        response = self.client.get("/clients")
        self.assertEqual(response.status_code, 200)
        self.assertIn("office-laptop", response.text)
        self.assertIn("/query-log?client=192.168.1.50", response.text)

    # -- Drilling into a specific client filters the Query Log -----------

    def test_individual_client_row_links_to_filtered_query_log(self) -> None:
        response = self.client.get("/clients")
        self.assertIn("/query-log?client=192.168.1.51", response.text)

    def test_query_log_filters_to_the_selected_client(self) -> None:
        response = self.client.get("/query-log?client=192.168.1.51")
        self.assertEqual(response.status_code, 200)
        self.assertIn("192.168.1.51", response.text)
        self.assertNotIn("192.168.1.50", response.text)

    # -- Unrelated dashboard navigation keeps working ---------------------

    def test_dashboard_top_blocked_domains_still_links_to_filtered_query_log(self) -> None:
        response = self.client.get("/")
        self.assertIn('href="/query-log?blocked=1"', response.text)

    def test_dashboard_recent_activity_still_links_to_query_log(self) -> None:
        response = self.client.get("/")
        self.assertIn('href="/query-log"', response.text)


if __name__ == "__main__":
    unittest.main()
