#!/usr/bin/env python3
"""Regression coverage for a live-appliance UX report: the Dashboard's
"View All" actions for Top Blocked Domains, Query Types, Response Codes,
and Protocol Usage all reached the Query Log, but with no filter/context
applied -- and no individual row (a specific blocked domain, QTYPE, rcode,
or protocol) was clickable at all, so there was no way to actually drill
into one specific value from the dashboard.

Fixed via components.html's ranked_list() macro's optional link_param/
link_extra: each row now links to /query-log with that row's exact value
in the same query-param filter Query Log's own filter form and
query_log_context()/analytics.query_log() already read -- the existing
filtering mechanism, not a second implementation of it. Query Log has no
time-window/range concept to preserve (analytics.query_log() queries
query_events with no time bound beyond LIMIT/OFFSET), so there is nothing
to carry through there.
"""
from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from app import alderpointdns_compiler as compiler  # noqa: E402
from app import analytics, local_dns, webapp  # noqa: E402


class DashboardAnalyticsDrilldownTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-analytics-drilldown-"))
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
            # Deliberately varied qtype/rcode/protocol/blocked-domain data
            # so each panel's ranking and each row's exact drill-down value
            # is unambiguous.
            events = [
                (now - 6, "10.0.0.5", "example.com", "A", "udp", "NOERROR", 0, None),
                (now - 5, "10.0.0.5", "example.org", "AAAA", "tcp", "NOERROR", 0, None),
                (now - 4, "10.0.0.6", "ads.example.net", "A", "udp", "NXDOMAIN", 1, "ads.example.net"),
                (now - 3, "10.0.0.6", "tracker.example.net", "A", "doh", "NXDOMAIN", 1, "tracker.example.net"),
                (now - 2, "10.0.0.6", "tracker.example.net", "A", "doh", "NXDOMAIN", 1, "tracker.example.net"),
                (now - 1, "10.0.0.7", "example.com", "MX", "dot", "SERVFAIL", 0, None),
            ]
            for ts, client, domain, qtype, protocol, rcode, blocked, blocked_domain in events:
                conn.execute(
                    "INSERT INTO query_events(ts, client, domain, qtype, protocol, rcode, blocked, blocked_domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (ts, client, domain, qtype, protocol, rcode, blocked, blocked_domain),
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

    # -- View All links stay/become correctly scoped ---------------------

    def test_top_blocked_domains_view_all_stays_scoped_to_blocked(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn('href="/query-log?blocked=1"', response.text)

    # -- Each panel's individual rows link to the exact matching value ---

    def test_top_blocked_domains_row_links_to_that_domain_filtered_to_blocked(self) -> None:
        response = self.client.get("/")
        # Rendered HTML entity-escapes "&" in the href attribute (correct,
        # standard Jinja autoescaping -- a browser parses "&amp;" in an
        # href back to a literal "&" when navigating).
        self.assertIn('href="/query-log?domain=tracker.example.net&amp;blocked=1"', response.text)
        self.assertIn('href="/query-log?domain=ads.example.net&amp;blocked=1"', response.text)

    def test_query_types_row_links_to_that_qtype(self) -> None:
        response = self.client.get("/")
        self.assertIn('href="/query-log?qtype=A"', response.text)
        self.assertIn('href="/query-log?qtype=AAAA"', response.text)
        self.assertIn('href="/query-log?qtype=MX"', response.text)

    def test_response_codes_row_links_to_that_rcode(self) -> None:
        response = self.client.get("/")
        self.assertIn('href="/query-log?rcode=NOERROR"', response.text)
        self.assertIn('href="/query-log?rcode=NXDOMAIN"', response.text)
        self.assertIn('href="/query-log?rcode=SERVFAIL"', response.text)

    def test_protocol_usage_row_links_to_that_protocol(self) -> None:
        response = self.client.get("/")
        self.assertIn('href="/query-log?protocol=udp"', response.text)
        self.assertIn('href="/query-log?protocol=doh"', response.text)
        self.assertIn('href="/query-log?protocol=dot"', response.text)

    def test_drilldown_value_is_url_encoded(self) -> None:
        # A blocked domain containing characters that are meaningful in a
        # query string must not corrupt the generated URL. (Blocked
        # domains are the one drill-down value realistically containing
        # such characters; qtype/rcode/protocol are always plain tokens.)
        with compiler.connect() as conn:
            conn.execute(
                "INSERT INTO query_events(ts, client, domain, qtype, protocol, rcode, blocked, blocked_domain) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (int(time.time()), "10.0.0.9", "weird&value.example", "A", "udp", "NXDOMAIN", 1, "weird&value.example"),
            )
            conn.commit()
        response = self.client.get("/")
        encoded = quote("weird&value.example", safe="")
        self.assertIn(f'href="/query-log?domain={encoded}&amp;blocked=1"', response.text)

    # -- Query Log actually applies each of those filters, using its own
    #    existing filtering mechanism (not a second implementation) -------

    def test_query_log_filters_by_domain_and_blocked(self) -> None:
        response = self.client.get("/query-log?domain=tracker.example.net&blocked=1")
        self.assertEqual(response.status_code, 200)
        self.assertIn("tracker.example.net", response.text)
        self.assertNotIn("ads.example.net", response.text)
        self.assertNotIn("example.com", response.text)

    def test_query_log_filters_by_qtype(self) -> None:
        response = self.client.get("/query-log?qtype=MX")
        self.assertEqual(response.status_code, 200)
        # MX query hit example.com from 10.0.0.7 -- the only MX row.
        self.assertIn("10.0.0.7", response.text)
        self.assertNotIn("10.0.0.5", response.text)

    def test_query_log_filters_by_rcode(self) -> None:
        response = self.client.get("/query-log?rcode=SERVFAIL")
        self.assertEqual(response.status_code, 200)
        self.assertIn("10.0.0.7", response.text)
        self.assertNotIn("10.0.0.5", response.text)
        self.assertNotIn("10.0.0.6", response.text)

    def test_query_log_filters_by_protocol(self) -> None:
        response = self.client.get("/query-log?protocol=dot")
        self.assertEqual(response.status_code, 200)
        self.assertIn("10.0.0.7", response.text)
        self.assertNotIn("10.0.0.5", response.text)
        self.assertNotIn("10.0.0.6", response.text)

    # -- Query Log's filter form itself reflects the filter it was opened
    #    with, matching this same drill-down flow end to end -------------

    def test_query_log_filter_form_shows_the_selected_qtype(self) -> None:
        response = self.client.get("/query-log?qtype=MX")
        self.assertIn('name="qtype" value="MX"', response.text)

    def test_query_log_filter_form_shows_the_selected_rcode(self) -> None:
        response = self.client.get("/query-log?rcode=SERVFAIL")
        self.assertIn('name="rcode" value="SERVFAIL"', response.text)

    def test_query_log_filter_form_shows_the_selected_protocol(self) -> None:
        response = self.client.get("/query-log?protocol=dot")
        self.assertIn('name="protocol" value="dot"', response.text)

    def test_query_log_filter_form_shows_blocked_selected(self) -> None:
        response = self.client.get("/query-log?blocked=1")
        self.assertIn('value="1" selected', response.text)


if __name__ == "__main__":
    unittest.main()
