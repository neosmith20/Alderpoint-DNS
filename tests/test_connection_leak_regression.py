#!/usr/bin/env python3
"""Regression coverage for the database-connection-descriptor leak: every
`with db()`/`with connect() as conn:` call site across the web app used to
leave its sqlite3 fd open forever, because the stdlib's context-manager
protocol on a bare Connection only commits/rolls back -- it never closes.
Under sustained traffic this accumulated one open fd per request (see
app/alderpointdns_compiler.py's AlderpointDNSConnection and its per-module
copies for the fix).

This drives the real FastAPI app (the same app.webapp.app object a deployed
uvicorn process serves) through hundreds of requests across the pages named
in the incident report -- including redirects, validation errors, and
handled exceptions -- and asserts the number of open fds pointing at the
sqlite database file stays bounded near its baseline instead of growing
with request count.
"""

from __future__ import annotations

import gc
import os
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

from app import (  # noqa: E402
    alderpointdns_compiler,
    analytics,
    auth,
    backup,
    blocklist_categories,
    custom_rules,
    dns_cache,
    encryption,
    filter_schedule,
    importer,
    local_dns,
    notifications,
    replication,
    service_logs,
    upstream_dns,
    webapp,
)

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')
INITIAL_PASSWORD = "initial-password-123"

# Every module with its own DB_PATH module attribute that must point at the
# same isolated, temporary database for the duration of the test.
DB_PATH_MODULES = (
    webapp,
    alderpointdns_compiler,
    analytics,
    notifications,
    backup,
    custom_rules,
    dns_cache,
    encryption,
    filter_schedule,
    importer,
    upstream_dns,
    blocklist_categories,
    local_dns,
    replication,
)


def _open_fds_to(path: Path) -> int:
    """Counts this process's open file descriptors pointing at `path`
    (including its -wal/-shm siblings, since sqlite keeps those open for the
    lifetime of a WAL-mode connection too), via /proc/self/fd -- the same
    mechanism `lsof` uses, but without depending on it being installed."""
    targets = {str(path), str(path) + "-wal", str(path) + "-shm", str(path) + "-journal"}
    fd_dir = Path("/proc/self/fd")
    if not fd_dir.is_dir():
        raise unittest.SkipTest("/proc/self/fd is not available on this platform")
    count = 0
    for entry in fd_dir.iterdir():
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        if target in targets:
            count += 1
    return count


class ConnectionLeakRegressionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-fd-leak-test-"))
        self.old_db_paths = {mod: mod.DB_PATH for mod in DB_PATH_MODULES}
        db_path = self.tmp / "alderpointdns.db"
        self.db_path = db_path
        for mod in DB_PATH_MODULES:
            mod.DB_PATH = db_path
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
        analytics.SECRET_FILE = self.tmp / "analytics.secret"
        analytics.HEARTBEAT_FILE = self.tmp / "analytics-writer-heartbeat.json"

        # Every page under test is reachable without a real systemd/openssl/ss
        # install: stub the subprocess-backed helpers with fast, static
        # results the same way test_administration.py does, so the test
        # measures connection lifecycle, not shells out hundreds of times.
        self.patches = [
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(webapp, "run", lambda command: (0, "active")),
            mock.patch.object(webapp, "fetch_service_log_entries", lambda unit: (True, [])),
            mock.patch.object(service_logs, "fetch_unit_logs", lambda unit: []),
        ]
        for patcher in self.patches:
            patcher.start()

        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", auth.hash_password(INITIAL_PASSWORD), "now"),
        )
        conn.commit()
        conn.close()

        self.client = TestClient(webapp.app)
        login = self.client.post("/login", data={"username": "admin", "password": INITIAL_PASSWORD})
        self.assertIn(login.status_code, (200, 303))
        self.csrf = self._current_csrf()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        for mod, path in self.old_db_paths.items():
            mod.DB_PATH = path
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _current_csrf(self) -> str:
        response = self.client.get("/system/administration")
        match = CSRF_RE.search(response.text)
        return match.group(1) if match else ""

    def _hit_pages(self) -> None:
        """One sweep across the pages named in the incident report: normal
        GETs, a query-string variant, an intentionally-wrong CSRF POST (a
        handled 403), a nonexistent import job id (a handled 404/validation
        error), and the unauthenticated-redirect path -- so every kind of
        response (200, redirect, validation error, handled exception) is
        exercised on every sweep, not just the happy path."""
        for path in (
            "/status/summary",
            "/",
            "/?range=7d",
            "/query-log",
            "/query-log/partial",
            "/blocklists",
            "/custom-rules",
            "/local-dns",
            "/dns-cache",
            "/encryption",
            "/dns-settings",
            "/import",
            "/backup",
            "/replication",
            "/system",
            "/system/logs",
            "/system/administration",
            "/system/notifications",
            "/statistics-settings",
        ):
            self.client.get(path)
        # A handled validation error (nonexistent job id path param still
        # matches the route but 404s inside the handler).
        self.client.get("/import/jobs/999999")
        # A handled 403 (CSRF mismatch) on a POST route.
        self.client.post("/protection/toggle", data={"csrf": "not-the-real-token"})
        # The unauthenticated-redirect path through render()/current_admin.
        with TestClient(webapp.app) as anon:
            anon.get("/", follow_redirects=False)

    def test_repeated_requests_do_not_leak_database_file_descriptors(self) -> None:
        baseline = _open_fds_to(self.db_path)
        sweeps = 20  # ~20 pages/sweep * 20 sweeps == several hundred requests
        for _ in range(sweeps):
            self._hit_pages()
        gc.collect()
        after = _open_fds_to(self.db_path)
        # A handful of fds is normal slack (TestClient/anyio may keep a
        # request or two in flight); real growth from the pre-fix bug scaled
        # linearly with request count (hundreds of leaked fds), so a small
        # fixed bound cleanly distinguishes "leak" from "no leak" regardless
        # of exactly how many sweeps ran.
        self.assertLessEqual(
            after,
            baseline + 5,
            f"open fds to the database grew from {baseline} to {after} after {sweeps} sweeps -- a connection leak regressed",
        )


if __name__ == "__main__":
    unittest.main()
