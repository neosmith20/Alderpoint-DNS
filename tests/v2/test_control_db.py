#!/usr/bin/env python3
"""Tests for app.v2.control_db.

Every test uses a disposable tempdir path. Nothing here ever opens
/var/lib/alderpointdns/control.db or the live alderpointdns.db.
"""
from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import control_db  # noqa: E402


class TestInitialization(unittest.TestCase):
    def test_initialize_creates_expected_tables(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            with control_db.connect(path) as conn:
                names = control_db._table_names(conn)
            self.assertIn("admins", names)
            self.assertIn("sessions", names)
            self.assertIn("clients", names)
            self.assertIn("migration_state", names)

    def test_initialize_is_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            control_db.initialize(path)  # must not raise
            self.assertEqual(control_db.schema_version(path), control_db.CONTROL_SCHEMA_VERSION)

    def test_wal_mode_enabled(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            with control_db.connect(path) as conn:
                mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            self.assertEqual(mode.lower(), "wal")


class TestNoQueryHistoryGuard(unittest.TestCase):
    def test_schema_has_no_forbidden_table_names(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            with control_db.connect(path) as conn:
                names = {n.lower() for n in control_db._table_names(conn)}
            for forbidden in ("query_events", "query_event", "raw_query_log", "query_log"):
                for name in names:
                    self.assertNotIn(
                        forbidden.rstrip("s"),
                        name,
                        msg=f"table {name!r} looks like raw query-history storage",
                    )

    def test_guard_detects_a_deliberately_bad_table(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            with control_db.connect(path) as conn:
                conn.execute("CREATE TABLE query_events (id INTEGER PRIMARY KEY)")
                with self.assertRaises(RuntimeError):
                    control_db._assert_no_forbidden_tables(conn)


class TestMigrationTransaction(unittest.TestCase):
    def test_successful_migration_bumps_version(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            control_db.apply_migration_in_transaction(
                path,
                ["CREATE TABLE widgets (id INTEGER PRIMARY KEY)"],
                new_version=2,
            )
            self.assertEqual(control_db.schema_version(path), 2)
            with control_db.connect(path) as conn:
                self.assertIn("widgets", control_db._table_names(conn))

    def test_failed_migration_rolls_back_completely(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            before_version = control_db.schema_version(path)

            with self.assertRaises(sqlite3.OperationalError):
                control_db.apply_migration_in_transaction(
                    path,
                    [
                        "CREATE TABLE gadgets (id INTEGER PRIMARY KEY)",
                        "THIS IS NOT VALID SQL",
                    ],
                    new_version=99,
                )

            self.assertEqual(control_db.schema_version(path), before_version)
            with control_db.connect(path) as conn:
                names = control_db._table_names(conn)
            self.assertNotIn("gadgets", names)  # first statement was rolled back too


class TestIntegrityCheck(unittest.TestCase):
    def test_initialize_raises_on_corrupt_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            # Write garbage that is not a valid SQLite file at all.
            path.write_bytes(b"not a sqlite database" * 100)
            with self.assertRaises(sqlite3.DatabaseError):
                control_db.initialize(path)


if __name__ == "__main__":
    unittest.main()
