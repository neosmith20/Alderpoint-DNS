#!/usr/bin/env python3
"""Deterministic (non-GC-timing-dependent) regression coverage for the
connection-descriptor leak: `with db() as conn:` / `with connect() as conn:`
on a bare sqlite3.Connection only commits or rolls back on exit -- it never
closes the connection, per the stdlib's documented context-manager
semantics. Every module below fixes this with a small AlderpointDNSConnection
subclass whose __exit__ also closes.

These tests hold a live reference to `conn` across the `with` block (as a
real caller's local variable naturally would not, since it normally goes
out of scope with the function) specifically so CPython's immediate
refcounting can't retire the connection on its own and mask a missing
`.close()` -- an fd-count-based test cannot reliably tell "closed
deterministically by the context manager" apart from "closed anyway once
nothing referenced it," since the latter also frees the fd almost
immediately in the common, cycle-free case. Asserting the connection is
unusable (`sqlite3.ProgrammingError: Cannot operate on a closed database`)
immediately after the `with` block exits is what actually pins the
guarantee this incident needed: every request-scoped connection is closed
by the time the block exits, not just eventually once GC gets around to it.
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import (  # noqa: E402
    alderpointdns_compiler,
    blocklist_categories,
    dns_cache,
    encryption,
    importer,
    local_dns,
    notifications,
    upstream_dns,
    webapp,
)


def assert_closed_after_with(test: unittest.TestCase, connect_fn) -> None:
    with connect_fn() as conn:
        conn.execute("SELECT 1")
    with test.assertRaises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


class ConnectionClosesDeterministicallyTest(unittest.TestCase):
    """One assertion per module with its own connect()/db() -- these are
    exactly the call sites the incident's audit named (session/admin lookup,
    blocklists, custom rules via local_dns's factory, DNS cache, encryption,
    import preview/apply, upstream resolvers, notifications)."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-conn-lifecycle-test-"))
        self.modules = (webapp, alderpointdns_compiler, notifications, encryption, dns_cache, importer, upstream_dns, blocklist_categories, local_dns)
        self.old_db_paths = {mod: mod.DB_PATH for mod in self.modules}
        db_path = self.tmp / "alderpointdns.db"
        for mod in self.modules:
            mod.DB_PATH = db_path

    def tearDown(self) -> None:
        for mod, path in self.old_db_paths.items():
            mod.DB_PATH = path
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_webapp_db_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, webapp.db)

    def test_alderpointdns_compiler_connect_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, alderpointdns_compiler.connect)

    def test_notifications_connect_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, notifications.connect)

    def test_encryption_connect_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, encryption.connect)

    def test_dns_cache_connect_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, dns_cache.connect)

    def test_importer_connect_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, importer.connect)

    def test_upstream_dns_connect_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, upstream_dns.connect)

    def test_blocklist_categories_connect_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, blocklist_categories.connect)

    def test_local_dns_connect_closes_after_with_block(self) -> None:
        assert_closed_after_with(self, local_dns.connect)

    def test_nested_with_conn_reuse_does_not_close_early(self) -> None:
        """notifications.update_settings and importer's apply flow reuse an
        already-open connection as their own nested `with conn:` transaction
        boundary (to group a subset of statements into one commit) -- the
        outer connection must survive that inner block's exit and only
        close once the outer `with` block itself exits."""
        with notifications.connect() as conn:
            with conn:
                conn.execute("SELECT 1")
            # Still open: the inner `with conn:` above must not have closed it.
            conn.execute("SELECT 1")
        with self.assertRaises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
