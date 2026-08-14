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


class TestMigrationForbiddenSchemaGuard(unittest.TestCase):
    """Adversarial tests proving the control.db migration invariant (raw
    query-history tables must never exist in control.db, see
    docs/v2/storage-audit.md) cannot be bypassed via
    ``apply_migration_in_transaction`` — the finding from the Dex
    architecture review that blocked Workstream 1's first gate.
    """

    # A. normal allowed migration -> commits, schema version advances.
    def test_a_normal_allowed_migration_commits(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            control_db.apply_migration_in_transaction(
                path, ["CREATE TABLE widgets (id INTEGER PRIMARY KEY)"], new_version=2
            )
            self.assertEqual(control_db.schema_version(path), 2)
            with control_db.connect(path) as conn:
                self.assertIn("widgets", control_db._table_names(conn))

    # B. CREATE forbidden table -> rejected, complete rollback, version unchanged.
    def test_b_create_forbidden_table_rejected_and_rolled_back(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            before = control_db.schema_version(path)

            with self.assertRaises(control_db.ForbiddenSchemaError):
                control_db.apply_migration_in_transaction(
                    path,
                    ["CREATE TABLE query_events (id INTEGER PRIMARY KEY)"],
                    new_version=2,
                )

            self.assertEqual(control_db.schema_version(path), before)
            with control_db.connect(path) as conn:
                self.assertNotIn("query_events", control_db._table_names(conn))

    # C. allowed mutation THEN forbidden table in the same migration ->
    #    whole migration rolls back, including the earlier allowed mutation.
    def test_c_earlier_allowed_mutation_also_rolled_back(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            before = control_db.schema_version(path)

            with self.assertRaises(control_db.ForbiddenSchemaError):
                control_db.apply_migration_in_transaction(
                    path,
                    [
                        "CREATE TABLE gadgets (id INTEGER PRIMARY KEY)",
                        "INSERT INTO gadgets(id) VALUES (1)",
                        "CREATE TABLE query_events (id INTEGER PRIMARY KEY)",
                    ],
                    new_version=2,
                )

            self.assertEqual(control_db.schema_version(path), before)
            with control_db.connect(path) as conn:
                names = control_db._table_names(conn)
            self.assertNotIn("gadgets", names)  # earlier allowed CREATE also undone
            self.assertNotIn("query_events", names)

    # D. rename an allowed table into a forbidden name -> rejected, rollback.
    def test_d_rename_into_forbidden_name_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            control_db.apply_migration_in_transaction(
                path, ["CREATE TABLE staging_widgets (id INTEGER PRIMARY KEY)"], new_version=2
            )
            before = control_db.schema_version(path)

            with self.assertRaises(control_db.ForbiddenSchemaError):
                control_db.apply_migration_in_transaction(
                    path,
                    ["ALTER TABLE staging_widgets RENAME TO query_events"],
                    new_version=3,
                )

            self.assertEqual(control_db.schema_version(path), before)
            with control_db.connect(path) as conn:
                names = control_db._table_names(conn)
            self.assertIn("staging_widgets", names)  # rename undone
            self.assertNotIn("query_events", names)

    # E. failed SQL migration -> rollback, schema version unchanged.
    def test_e_failed_sql_rolls_back_version_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            before = control_db.schema_version(path)

            with self.assertRaises(sqlite3.OperationalError):
                control_db.apply_migration_in_transaction(
                    path,
                    ["CREATE TABLE gizmos (id INTEGER PRIMARY KEY)", "NOT VALID SQL AT ALL"],
                    new_version=99,
                )

            self.assertEqual(control_db.schema_version(path), before)
            with control_db.connect(path) as conn:
                self.assertNotIn("gizmos", control_db._table_names(conn))

    # F. existing forbidden schema presented to the migration primitive ->
    #    migration refuses to proceed safely, without even attempting the
    #    new (otherwise-allowed) statements.
    def test_f_preexisting_forbidden_schema_refuses_further_migration(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            # Simulate a forbidden table having gotten in some other way
            # (e.g. manual DB surgery, or a bug predating this guard) by
            # writing it directly, bypassing apply_migration_in_transaction.
            with control_db.connect(path) as conn:
                conn.execute("BEGIN")
                conn.execute("CREATE TABLE query_events (id INTEGER PRIMARY KEY)")
                conn.execute("COMMIT")

            with self.assertRaises(control_db.ForbiddenSchemaError):
                control_db.apply_migration_in_transaction(
                    path,
                    ["CREATE TABLE totally_fine_table (id INTEGER PRIMARY KEY)"],
                    new_version=2,
                )

            # The otherwise-allowed statement must not have been applied
            # either — refusal happens before the migration body runs.
            with control_db.connect(path) as conn:
                names = control_db._table_names(conn)
            self.assertNotIn("totally_fine_table", names)

    # G. initialize() still rejects forbidden control-db schemas.
    def test_g_initialize_still_rejects_forbidden_schema(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            with control_db.connect(path) as conn:
                conn.execute("BEGIN")
                conn.execute("CREATE TABLE query_events (id INTEGER PRIMARY KEY)")
                conn.execute("COMMIT")

            with self.assertRaises(control_db.ForbiddenSchemaError):
                control_db.initialize(path)  # re-running init must also refuse

    # H. allowed bounded tables remain unaffected by the guard (no false positives).
    def test_h_allowed_tables_with_query_like_words_are_not_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "control.db"
            control_db.initialize(path)
            # "query" and "statistics" appear in these names but they are
            # bounded control-plane concepts, not raw per-DNS-query history —
            # the guard must not over-broadly reject them.
            control_db.apply_migration_in_transaction(
                path,
                [
                    "CREATE TABLE saved_queries (id INTEGER PRIMARY KEY, label TEXT)",
                    "CREATE TABLE statistics_settings (key TEXT PRIMARY KEY, value TEXT)",
                ],
                new_version=2,
            )
            with control_db.connect(path) as conn:
                names = control_db._table_names(conn)
            self.assertIn("saved_queries", names)
            self.assertIn("statistics_settings", names)


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
