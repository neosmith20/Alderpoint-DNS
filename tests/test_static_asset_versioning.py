#!/usr/bin/env python3
"""Regression coverage for a real appliance bug: after installing a newer
Alderpoint package at the same URL/IP, a browser tab kept executing the
*previous* build's app.js even though the installed file on disk and a
direct curl to /static/app.js both already reflected the new build. The
served bytes were correct; the URL identifying them never changed, so a
normal page load had no reason to refetch anything.

app/webapp.py's static_asset_fingerprint()/static_url()/VersionedStaticFiles
fix that by hashing the actual files under web/static/ once at process
startup and appending that hash as a cache-busting query string to every
asset URL templates emit -- a real content change always produces a new
URL a fresh page load fetches for real, while an unchanged file under an
unchanged URL keeps being served with a long-lived, immutable
Cache-Control (set only for that versioned URL, never for the bare path)
so ordinary caching still works well between upgrades.
"""
from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import webapp  # noqa: E402


class StaticAssetFingerprintTest(unittest.TestCase):
    """Pure function tests against a disposable directory -- never touches
    the real web/static/ on disk."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-static-fingerprint-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_same_content_produces_the_same_fingerprint(self) -> None:
        (self.tmp / "app.js").write_text("console.log('v1');")
        (self.tmp / "app.css").write_text("body { color: red; }")
        first = webapp.static_asset_fingerprint(self.tmp)
        second = webapp.static_asset_fingerprint(self.tmp)
        self.assertEqual(first, second)

    def test_changing_a_shipped_file_changes_the_fingerprint(self) -> None:
        # This is the exact mechanism the reported bug needed: a real
        # package upgrade that changes app.js's bytes must produce a
        # different fingerprint (and therefore a different URL), or a
        # browser has no reason to ever refetch it.
        (self.tmp / "app.js").write_text("console.log('v1');")
        before = webapp.static_asset_fingerprint(self.tmp)
        (self.tmp / "app.js").write_text("console.log('v2 -- upgraded');")
        after = webapp.static_asset_fingerprint(self.tmp)
        self.assertNotEqual(before, after)

    def test_an_unrelated_file_being_added_also_changes_the_fingerprint(self) -> None:
        (self.tmp / "app.js").write_text("console.log('v1');")
        before = webapp.static_asset_fingerprint(self.tmp)
        (self.tmp / "app.css").write_text("body { color: blue; }")
        after = webapp.static_asset_fingerprint(self.tmp)
        self.assertNotEqual(before, after)

    def test_the_currently_registered_fingerprint_matches_the_real_shipped_files(self) -> None:
        # Guards against STATIC_ASSET_FINGERPRINT ever being computed once
        # at import time and then silently going stale relative to
        # whatever is actually on disk in this checkout.
        self.assertEqual(webapp.STATIC_ASSET_FINGERPRINT, webapp.static_asset_fingerprint(webapp.STATIC_DIR))


class StaticUrlHelperTest(unittest.TestCase):
    def test_static_url_appends_the_current_fingerprint_as_a_query_string(self) -> None:
        self.assertEqual(webapp.static_url("app.js"), f"/static/app.js?v={webapp.STATIC_ASSET_FINGERPRINT}")
        self.assertEqual(webapp.static_url("app.css"), f"/static/app.css?v={webapp.STATIC_ASSET_FINGERPRINT}")


class VersionedStaticFilesHttpTest(unittest.TestCase):
    """Genuine HTTP round-trips against the real mounted /static endpoint
    (real files under web/static/, not a sandboxed copy) -- the actual
    contract a browser observes."""

    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-static-http-"))
        self.old_db_path = webapp.DB_PATH
        webapp.DB_PATH = self.tmp / "alderpointdns.db"
        with sqlite3.connect(webapp.DB_PATH) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, admin_id INTEGER, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT, csrf TEXT NOT NULL)"
            )
            # At least one admin so GET /login renders the login form
            # itself rather than redirecting to /setup.
            conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES ('admin', 'x', 'now')")
            conn.commit()
        self.client = TestClient(webapp.app)

    def tearDown(self) -> None:
        webapp.DB_PATH = self.old_db_path
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_versioned_asset_url_gets_a_long_lived_immutable_cache_control(self) -> None:
        response = self.client.get(webapp.static_url("app.js"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("cache-control"), "public, max-age=31536000, immutable")

    def test_bare_unversioned_url_does_not_get_the_long_lived_cache_control(self) -> None:
        # Static images/fonts/etc (or a stale bookmark/direct link hitting
        # the bare path) must keep Starlette's ordinary ETag/Last-Modified
        # conditional-GET behavior -- never told to cache for a year on
        # nothing but a guess.
        response = self.client.get("/static/app.js")
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(response.headers.get("cache-control"), "public, max-age=31536000, immutable")

    def test_a_random_or_stale_version_query_still_serves_the_current_real_content(self) -> None:
        # The query string is only a cache key / freshness signal to the
        # browser -- StaticFiles always serves the real current file
        # regardless of what value follows `v=`, so an old cached URL from
        # before an upgrade never serves stale content even if somehow
        # requested again.
        real = self.client.get(webapp.static_url("app.js")).text
        stale = self.client.get("/static/app.js?v=deadbeef0000").text
        self.assertEqual(real, stale)

    def test_login_page_references_the_currently_fingerprinted_asset_urls(self) -> None:
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn(webapp.static_url("app.css"), response.text)
        self.assertIn(webapp.static_url("app.js"), response.text)


if __name__ == "__main__":
    unittest.main()
