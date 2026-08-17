"""Gate #2 HIGH: migration source detection must reject an unsupported/
incomplete schema BEFORE backup/migration proceeds, with a clear
diagnostic naming exactly what's missing -- not a later stage's raw
traceback (Dex's exact reproduction: admins+clients-only passed
detection, then failed deep into a later stage when client_identifiers
turned out to be missing).
"""

from __future__ import annotations

import sqlite3

import pytest

from app.v2.migration_convert import (
    OPTIONAL_TABLES_AND_COLUMNS,
    REQUIRED_TABLES_AND_COLUMNS,
    MigrationConvertError,
    UnsupportedSourceSchemaError,
    detect_source,
)
from tests.v2._v1_fixture import build_v1_fixture


class TestFullSchemaAccepted:
    def test_complete_fixture_classified_supported_complete(self, tmp_path):
        source = tmp_path / "src"
        build_v1_fixture(source / "alderpointdns.db")
        info = detect_source(source)
        assert info.classification == "supported_complete"
        assert info.missing_optional == ()


class TestMissingRequiredTableRejected:
    def test_dex_exact_reproduction_admins_and_clients_only(self, tmp_path):
        """A database with only admins+clients (no client_identifiers, no
        anything else) must be rejected HERE, not pass detection and fail
        later inside a migration stage."""
        source = tmp_path / "src"
        source.mkdir()
        db_path = source / "alderpointdns.db"
        conn = sqlite3.connect(str(db_path))
        conn.executescript(
            """
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE clients (
                id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            """
        )
        conn.commit()
        conn.close()

        with pytest.raises(UnsupportedSourceSchemaError) as exc_info:
            detect_source(source)
        message = str(exc_info.value)
        assert "client_identifiers" in message
        assert "missing required table" in message

    def test_missing_table_named_explicitly_not_generic(self, tmp_path):
        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("DROP TABLE upstream_resolvers")
        conn.commit()
        conn.close()
        with pytest.raises(UnsupportedSourceSchemaError) as exc_info:
            detect_source(source)
        assert "missing required table: upstream_resolvers" in str(exc_info.value)

    def test_all_missing_tables_reported_together_not_just_first(self, tmp_path):
        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("DROP TABLE upstream_resolvers")
        conn.execute("DROP TABLE custom_filter_rules")
        conn.execute("DROP TABLE notification_providers")
        conn.commit()
        conn.close()
        with pytest.raises(UnsupportedSourceSchemaError) as exc_info:
            detect_source(source)
        message = str(exc_info.value)
        assert "upstream_resolvers" in message
        assert "custom_filter_rules" in message
        assert "notification_providers" in message


class TestMissingRequiredColumnRejected:
    def test_table_present_but_missing_a_required_column(self, tmp_path):
        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        # Simulate an older schema variant: client_identifiers without
        # the 'kind' column (as if identifiers were always plain IPs).
        conn.execute("ALTER TABLE client_identifiers RENAME TO client_identifiers_old")
        conn.execute(
            "CREATE TABLE client_identifiers (client_id INTEGER, value TEXT, created_at TEXT)"
        )
        conn.commit()
        conn.close()
        with pytest.raises(UnsupportedSourceSchemaError) as exc_info:
            detect_source(source)
        assert "client_identifiers" in str(exc_info.value)
        assert "kind" in str(exc_info.value)

    def test_extra_unknown_column_does_not_break_detection(self, tmp_path):
        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("ALTER TABLE clients ADD COLUMN future_field TEXT DEFAULT ''")
        conn.commit()
        conn.close()
        info = detect_source(source)
        assert info.classification == "supported_complete"


class TestOptionalTableGapsToleratedButClassified:
    def test_missing_optional_table_still_supported_but_flagged(self, tmp_path):
        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("DROP TABLE analytics_settings")
        conn.execute("DROP TABLE query_events")
        conn.commit()
        conn.close()
        info = detect_source(source)
        assert info.classification == "supported_with_optional_gaps"
        assert "analytics_settings" in info.missing_optional
        assert "query_events" in info.missing_optional

    def test_optional_tables_never_block_migration(self, tmp_path):
        # Full pipeline against a source missing only optional tables must
        # still complete -- classification is informational, not blocking.
        import shutil

        from app.v2 import migration as mig

        if not shutil.which("dnsdist"):
            pytest.skip("requires installed dnsdist")

        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("DROP TABLE analytics_settings")
        conn.commit()
        conn.close()

        state = mig.run_migration(source, tmp_path / "staging")
        assert state.committed


class TestCorruptAndUnknownSchema:
    def test_completely_unrelated_database_rejected(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        db_path = source / "alderpointdns.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE totally_unrelated_app_data (id INTEGER)")
        conn.commit()
        conn.close()
        with pytest.raises(UnsupportedSourceSchemaError):
            detect_source(source)

    def test_empty_database_rejected(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        db_path = source / "alderpointdns.db"
        sqlite3.connect(str(db_path)).close()
        with pytest.raises(UnsupportedSourceSchemaError):
            detect_source(source)

    def test_corrupted_file_rejected_distinctly_from_schema_error(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "alderpointdns.db").write_bytes(b"not a sqlite file at all")
        with pytest.raises(MigrationConvertError) as exc_info:
            detect_source(source)
        assert not isinstance(exc_info.value, UnsupportedSourceSchemaError)


class TestEmptyValidTablesAndNullDefaults:
    def test_empty_but_schema_complete_tables_accepted(self, tmp_path):
        source = tmp_path / "src"
        build_v1_fixture(source / "alderpointdns.db", populate=False)
        info = detect_source(source)
        assert info.classification == "supported_complete"

    def test_empty_string_historical_values_do_not_block_detection(self, tmp_path):
        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE local_dns_records SET comment = '' WHERE id = 1")
        conn.commit()
        conn.close()
        info = detect_source(source)
        assert info.classification == "supported_complete"


class TestSchemaContractIsRealAndExhaustive:
    def test_contract_covers_every_table_migration_convert_actually_reads(self):
        # Sanity: the contract lists are non-trivial and cover the tables
        # documented in migration_convert.py's own docstrings.
        assert "client_identifiers" in REQUIRED_TABLES_AND_COLUMNS
        assert "upstream_resolvers" in REQUIRED_TABLES_AND_COLUMNS
        assert "notification_providers" in REQUIRED_TABLES_AND_COLUMNS
        assert "query_events" in OPTIONAL_TABLES_AND_COLUMNS
        assert "analytics_settings" in OPTIONAL_TABLES_AND_COLUMNS
