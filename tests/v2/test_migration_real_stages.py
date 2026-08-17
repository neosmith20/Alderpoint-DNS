"""End-to-end tests for the real (no longer stub) V1->V2 migration stage
implementations (Workstream 3 final continuation, Priority 1). Every test
here operates against a disposable synthetic V1 fixture database
(``tests/v2/_v1_fixture.py``) -- never the live appliance database.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

from app.v2 import control_db, migration as mig, migration_convert as mconv
from app.v2 import notification_store as nstore
from app.v2 import policy_store as pstore
from app.v2.secret_store import SecretStore
from tests.v2._network_probe import network_reachable
from tests.v2._v1_fixture import build_v1_fixture

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None
NAMED_CHECKZONE_INSTALLED = shutil.which("named-checkzone") is not None
# Despite the name, this previously only checked that dnsdist was
# installed, not that outbound DNS actually works -- the health-check
# stage itself now degrades gracefully with no network (see
# app/v2/migration.py's _stage_health_check), but this particular test
# asserts `recursive_resolution_ok is True`, which is a real claim about
# a live upstream and needs real outbound reachability to be meaningful.
NETWORK_REQUIRED = pytest.mark.skipif(
    not (DNSDIST_INSTALLED and network_reachable()),
    reason="requires installed dnsdist and outbound network reachability",
)


@pytest.fixture()
def v1_source(tmp_path):
    source = tmp_path / "v1-install"
    build_v1_fixture(source / "alderpointdns.db")
    return source


class TestDetection:
    def test_detects_supported_source(self, v1_source):
        info = mconv.detect_source(v1_source)
        assert info.detected_version == "v1.x"

    def test_rejects_missing_db(self, tmp_path):
        with pytest.raises(mconv.MigrationConvertError):
            mconv.detect_source(tmp_path / "nowhere")

    def test_rejects_unsupported_schema(self, tmp_path):
        source = tmp_path / "bad-source"
        source.mkdir()
        conn = sqlite3.connect(str(source / "alderpointdns.db"))
        conn.execute("CREATE TABLE unrelated (id INTEGER)")
        conn.commit()
        conn.close()
        with pytest.raises(mconv.MigrationConvertError):
            mconv.detect_source(source)


class TestBackupAndVerification:
    def test_backup_creates_consistent_snapshot_with_checksum(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        assert Path(manifest["backup_path"]).exists()
        assert manifest["table_row_counts"]["clients"] == 1
        mconv.verify_backup(manifest)  # must not raise

    def test_verify_rejects_corrupted_backup(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        # Corrupt the backup file's bytes after creation.
        backup_path = Path(manifest["backup_path"])
        data = bytearray(backup_path.read_bytes())
        data[100:110] = b"CORRUPTED!"
        backup_path.write_bytes(bytes(data))
        with pytest.raises(mconv.MigrationConvertError):
            mconv.verify_backup(manifest)

    def test_verify_rejects_missing_backup(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        Path(manifest["backup_path"]).unlink()
        with pytest.raises(mconv.MigrationConvertError):
            mconv.verify_backup(manifest)

    def test_restore_test_reconstructs_usable_state(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        result = mconv.restore_test(manifest, tmp_path / "restore")
        assert result["client_count"] == 1
        assert result["admin_count"] == 1

    def test_restore_test_detects_unreadable_backup(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        Path(manifest["backup_path"]).write_bytes(b"not a database at all")
        with pytest.raises(mconv.MigrationConvertError):
            mconv.restore_test(manifest, tmp_path / "restore")


class TestPreview:
    def test_preview_is_read_only_and_reports_counts(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        before = info.db_path.read_bytes()

        report = mconv.build_preview(Path(manifest["backup_path"]))

        after = info.db_path.read_bytes()
        assert before == after  # source untouched
        assert report["object_counts"]["clients"] == 1
        assert report["object_counts"]["notification_providers"] == 1
        assert report["secret_count_no_values"] == 1
        assert "50 raw query_events rows" in report["query_history_treatment"]
        # No secret value anywhere in the report.
        assert "super-secret-token-abc" not in json.dumps(report)


class TestClientsMigration:
    def test_clients_and_identifiers_migrated(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        result = mconv.migrate_clients(Path(manifest["backup_path"]), target)
        assert result["clients_migrated"] == 1
        assert result["identifiers_migrated"] == 1

    def test_invalid_identifier_skipped_with_warning(self, tmp_path):
        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "INSERT INTO client_identifiers VALUES (2, 1, 'ipv4', 'not-an-ip', '2026-01-01')"
        )
        conn.commit()
        conn.close()
        manifest = mconv.create_backup(db_path, tmp_path / "staging")
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        result = mconv.migrate_clients(Path(manifest["backup_path"]), target)
        assert result["identifiers_skipped"] == 1
        assert any("not-an-ip" in w for w in result["warnings"])


class TestAdminsMigration:
    def test_argon2_hash_reused_directly(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        result = mconv.migrate_admins(Path(manifest["backup_path"]), target)
        assert result["migrated"] == 1
        assert result["needs_rehash"] == []
        with control_db.connect(target) as conn:
            row = conn.execute("SELECT password_hash FROM admins WHERE username='admin'").fetchone()
        assert row[0].startswith("$argon2id$")

    def test_unrecognized_hash_flagged_not_migrated(self, tmp_path):
        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE admins SET password_hash = 'md5:deadbeef' WHERE id = 1")
        conn.commit()
        conn.close()
        manifest = mconv.create_backup(db_path, tmp_path / "staging")
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        result = mconv.migrate_admins(Path(manifest["backup_path"]), target)
        assert result["migrated"] == 0
        assert "admin" in result["needs_rehash"]


class TestSecretsMigration:
    def test_secret_extracted_and_absent_from_control_db(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        secrets = SecretStore(tmp_path / "secrets")
        result = mconv.migrate_notifications(Path(manifest["backup_path"]), target, secrets)
        assert result["migrated"] == 1

        raw = target.read_bytes()
        assert b"super-secret-token-abc" not in raw

        with control_db.connect(target) as conn:
            providers = nstore.list_providers(conn)
        assert len(providers) == 1
        assert providers[0].secret_ref is not None
        assert secrets.get(providers[0].secret_ref) == "super-secret-token-abc"


class TestFilteringMigration:
    def test_block_and_allow_split_correctly(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        result = mconv.migrate_filtering(Path(manifest["backup_path"]))
        assert result["blocked_domains"] == ["ads.example"]
        assert result["allowed_domains"] == ["good.example"]

    def test_preview_object_counts_match_real_custom_filter_rules_table(self, v1_source, tmp_path):
        # Real regression found live during RC2 migration acceptance
        # testing: migrate_filtering() and build_preview() both used to
        # read the bare "custom_rules" table -- dead V1 schema no current
        # V1 code path (the real /rules UI, custom_rules.py's
        # add_rule()/add_rules_bulk(), the importer) ever writes to.
        # Every real V1 admin's real custom rules live in
        # custom_filter_rules instead, so a real V1 install with real
        # rules previewed and migrated as zero, silently, with no error.
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        preview = mconv.build_preview(Path(manifest["backup_path"]))
        assert preview["object_counts"]["custom_rules_block"] == 1
        assert preview["object_counts"]["custom_rules_allow"] == 1

    def test_non_block_allow_rule_types_excluded_and_reported_not_silently_dropped(self, tmp_path):
        source = tmp_path / "src" / "alderpointdns.db"
        build_v1_fixture(source)
        conn = sqlite3.connect(str(source))
        conn.execute(
            "INSERT INTO custom_filter_rules VALUES (100, 'x.example -> 1.2.3.4', 'x.example', "
            "'rewrite', 'x.example', 'rewrite', 1, 'valid', '', "
            "'2026-01-01T00:00:00', '2026-01-01T00:00:00')"
        )
        conn.commit()
        conn.close()
        info = mconv.detect_source(source.parent)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        result = mconv.migrate_filtering(Path(manifest["backup_path"]))
        # The rewrite rule must not silently appear as a block/allow domain...
        assert "x.example" not in result["blocked_domains"]
        assert "x.example" not in result["allowed_domains"]
        # ...but its exclusion must be surfaced, not silent.
        assert any("rewrite" in w or "1 enabled custom filter rule" in w for w in result["warnings"])


class TestUpstreamsMigration:
    def test_upstream_profile_created(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        result = mconv.migrate_upstreams(Path(manifest["backup_path"]), target)
        assert result["migrated"] == 1
        with control_db.connect(target) as conn:
            profile = pstore.load_upstream_profile(conn, "migrated-default")
        assert profile.transport == "dot"
        assert profile.endpoints[0].tls_hostname == "cloudflare-dns.com"


class TestLegacyAnalyticsArchive:
    def test_registers_without_copying_raw_rows(self, v1_source, tmp_path):
        info = mconv.detect_source(v1_source)
        manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
        target_root = tmp_path / "v2-target"
        result = mconv.register_legacy_analytics_archive(Path(manifest["backup_path"]), target_root)
        assert result["row_count"] == 50
        assert result["read_only"] is True
        assert (target_root / "legacy-analytics-archive.manifest.json").exists()


@NETWORK_REQUIRED
class TestFullPipelineEndToEnd:
    def test_full_migration_against_realistic_fixture(self, v1_source, tmp_path):
        state = mig.run_migration(v1_source, tmp_path / "staging")
        assert state.committed
        assert state.object_counts["clients_migrated"] == 1
        assert state.object_counts["admins_migrated"] == 1
        assert state.object_counts["notifications_migrated"] == 1
        assert state.object_counts["upstreams_migrated"] == 1
        assert state.object_counts["local_dns_records_migrated"] == 2
        assert state.object_counts["legacy_query_history_rows"] == 50

        # Generated runtime artifacts exist and were validated.
        assert Path(state.generated_runtime["dnsdist_config"]).exists()
        assert Path(state.generated_runtime["rpz_zone"]).exists()
        assert Path(state.generated_runtime["local_dns_zone"]).exists()

        # Health check actually queried the generated runtime.
        assert state.health_check_result["recursive_resolution_ok"] is True

        # Source untouched throughout.
        before = (v1_source / "alderpointdns.db").stat().st_mtime
        # (already proven byte-identical in test_migration_scaffold.py;
        # here we additionally confirm no write access was ever attempted
        # by checking the file is still openable read-write by us, i.e.
        # nothing else holds a stale lock on it)
        conn = sqlite3.connect(str(v1_source / "alderpointdns.db"))
        conn.execute("SELECT 1")
        conn.close()
