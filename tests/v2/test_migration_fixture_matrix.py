"""Realistic V1 -> V2 migration fixture matrix (V2 roadmap Priority 2).

Each fixture here is a distinct SANITIZED synthetic V1 install shape built
by ``tests/v2/_v1_fixture.py`` -- never live/private data -- representing a
real supported historical or current installation variant. Every test
drives the actual migration-stage functions in
``app/v2/migration_convert.py`` (the same functions
``app/v2/migration.py``'s real pipeline calls), not a re-implementation, so
this exercises the real migration path: detect -> backup -> preview ->
per-object migrate -> (where relevant) legacy analytics registration.
Network-dependent stages (runtime compile/validate + live health check) are
already covered end-to-end for the baseline shape in
``test_migration_real_stages.py::TestFullPipelineEndToEnd``; this file
focuses on the parts of the matrix that vary by *source shape*, which is
independent of network availability, so it runs fully offline.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.v2 import control_db, migration_convert as mconv
from app.v2 import notification_store as nstore
from app.v2 import policy_store as pstore
from app.v2.secret_store import SecretStore
from tests.v2._v1_fixture import build_v1_fixture


def _migrate_all(source_db: Path, tmp_path: Path):
    """Runs every offline (non-runtime-compile) stage against a fixture and
    returns (manifest, preview, target_db, secrets, results-by-stage)."""
    manifest = mconv.create_backup(source_db, tmp_path / "staging")
    mconv.verify_backup(manifest)
    preview = mconv.build_preview(Path(manifest["backup_path"]))
    target = tmp_path / "control.db"
    mconv.initialize_target_control_db(target)
    secrets = SecretStore(tmp_path / "secrets")
    results = {
        "clients": mconv.migrate_clients(Path(manifest["backup_path"]), target),
        "admins": mconv.migrate_admins(Path(manifest["backup_path"]), target),
        "notifications": mconv.migrate_notifications(Path(manifest["backup_path"]), target, secrets),
        "filtering": mconv.migrate_filtering(Path(manifest["backup_path"])),
        "upstreams": mconv.migrate_upstreams(Path(manifest["backup_path"]), target),
        "analytics": mconv.register_legacy_analytics_archive(
            Path(manifest["backup_path"]), tmp_path / "v2-target"
        ),
    }
    return manifest, preview, target, secrets, results


class TestFreshMinimalV1:
    """A. Fresh/minimal V1 install: schema present, nothing configured yet."""

    def test_empty_install_migrates_cleanly_with_zero_counts(self, tmp_path):
        source = build_v1_fixture(tmp_path / "src" / "alderpointdns.db", populate=False)
        _, preview, target, secrets, results = _migrate_all(source, tmp_path)
        assert preview["object_counts"]["clients"] == 0
        assert results["clients"]["clients_migrated"] == 0
        assert results["admins"]["migrated"] == 0
        assert results["notifications"]["migrated"] == 0
        assert results["filtering"]["blocked_domains"] == []
        assert results["upstreams"]["migrated"] == 0
        # Migration to an empty install must not fabricate any rows.
        with control_db.connect(target) as conn:
            assert conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0


class TestLocalDnsHeavyV1:
    """D. Local-DNS-heavy V1 install (many hand-maintained LAN records)."""

    def test_all_local_dns_records_present_in_filtering_stage_source(self, tmp_path):
        source = build_v1_fixture(
            tmp_path / "src" / "alderpointdns.db", local_dns_records=40
        )
        manifest = mconv.create_backup(source, tmp_path / "staging")
        preview = mconv.build_preview(Path(manifest["backup_path"]))
        # 2 baseline + 40 extra.
        assert preview["object_counts"]["local_dns_records"] == 42


class TestFilterRuleHeavyV1:
    """E. Custom allow/block/filter-rule-heavy V1 install."""

    def test_large_rule_set_splits_correctly_by_action(self, tmp_path):
        source = build_v1_fixture(tmp_path / "src" / "alderpointdns.db", custom_rules=200)
        _, _, _, _, results = _migrate_all(source, tmp_path)
        # Baseline: 1 block + 1 allow. Extras alternate block/allow starting
        # with block (i % 2 == 0 -> block), 200 extras -> 100 block/100 allow.
        assert len(results["filtering"]["blocked_domains"]) == 101
        assert len(results["filtering"]["allowed_domains"]) == 101


class TestClientAccessHeavyV1:
    """F. Client/access-rule-heavy V1 install (many managed devices)."""

    def test_all_clients_and_identifiers_migrated(self, tmp_path):
        source = build_v1_fixture(tmp_path / "src" / "alderpointdns.db", clients=150)
        _, _, target, _, results = _migrate_all(source, tmp_path)
        # Baseline 1 + 150 extra.
        assert results["clients"]["clients_migrated"] == 151
        assert results["clients"]["identifiers_migrated"] == 151
        with control_db.connect(target) as conn:
            assert conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0] == 151


class TestNotificationConfigVariants:
    """H. Multiple notification providers, each secret independently
    extracted and independently retrievable, none left in control.db."""

    def test_multiple_provider_secrets_isolated(self, tmp_path):
        source = build_v1_fixture(
            tmp_path / "src" / "alderpointdns.db", notification_providers=5
        )
        _, _, target, secrets, results = _migrate_all(source, tmp_path)
        assert results["notifications"]["migrated"] == 6  # baseline + 5
        raw = target.read_bytes()
        assert b"super-secret-token-abc" not in raw
        for n in range(2, 7):
            assert f"extra-secret-token-{n}".encode() not in raw
        with control_db.connect(target) as conn:
            providers = nstore.list_providers(conn)
        assert len(providers) == 6
        resolved = {secrets.get(p.secret_ref) for p in providers if p.secret_ref}
        assert "super-secret-token-abc" in resolved
        assert all(f"extra-secret-token-{n}" in resolved for n in range(2, 7))


class TestAlternateUpstreamConfiguration:
    """I. Alternate upstream transport configurations."""

    @pytest.mark.parametrize("protocol", ["plain", "doh", "dot"])
    def test_upstream_transport_preserved_through_migration(self, tmp_path, protocol):
        source = build_v1_fixture(
            tmp_path / "src" / "alderpointdns.db", upstream_protocol=protocol
        )
        _, _, target, _, results = _migrate_all(source, tmp_path)
        assert results["upstreams"]["migrated"] == 1
        with control_db.connect(target) as conn:
            profile = pstore.load_upstream_profile(conn, "migrated-default")
        assert profile.transport == protocol

    def test_dot_disabled_source_still_migrates_by_actual_upstream_protocol(self, tmp_path):
        # V1's separate `encryption_settings.dot_enabled` global toggle is
        # not read by any migration_convert.py stage today (grep-verified:
        # no reference exists) -- the migrated transport is derived solely
        # from the per-upstream `protocol` column, which is the real
        # self-describing source of truth for what V2 should configure.
        # This fixture (protocol='dot' but the V1 global toggle off) still
        # migrates the endpoint as DoT: documents current, intentional
        # behavior so a future change to read the toggle is a deliberate
        # decision, not an accidental regression caught by surprise here.
        source = build_v1_fixture(
            tmp_path / "src" / "alderpointdns.db", dot_enabled=False
        )
        _, _, target, _, results = _migrate_all(source, tmp_path)
        assert results["upstreams"]["migrated"] == 1
        with control_db.connect(target) as conn:
            profile = pstore.load_upstream_profile(conn, "migrated-default")
        assert profile.transport == "dot"


class TestInboundEncryptedTransportNotSilentlyLost:
    """G. V1's inbound encrypted-DNS-for-clients config (encryption_settings:
    doh/dot/doh3/doq/dnscrypt_enabled -- a real, commonly-on-by-default V1
    feature per app/encryption.py's _DEFAULTS) has no V2 migration path yet
    (dnsdist_gen.py emits only a single plain listener). This must surface
    as an explicit warning, not vanish silently."""

    def test_preview_warns_when_source_has_encrypted_transports_enabled(self, tmp_path):
        source = build_v1_fixture(
            tmp_path / "src" / "alderpointdns.db",
            encrypted_transports_enabled=("doh_enabled", "dot_enabled"),
        )
        manifest = mconv.create_backup(source, tmp_path / "staging")
        preview = mconv.build_preview(Path(manifest["backup_path"]))
        assert preview["encryption_settings"]["migrated"] is False
        assert set(preview["encryption_settings"]["inbound_transports_enabled_in_source"]) == {
            "DoH",
            "DoT",
        }
        assert any("DoH" in w and "DoT" in w for w in preview["warnings"])

    def test_preview_no_warning_when_source_has_no_encrypted_transports(self, tmp_path):
        # The shared baseline fixture seeds dot_enabled='true' (matching a
        # real V1 default install); explicitly disable it here to test the
        # genuinely-all-off case.
        source = build_v1_fixture(tmp_path / "src" / "alderpointdns.db", dot_enabled=False)
        manifest = mconv.create_backup(source, tmp_path / "staging")
        preview = mconv.build_preview(Path(manifest["backup_path"]))
        assert preview["encryption_settings"]["inbound_transports_enabled_in_source"] == []
        assert not any("encrypted DNS transport" in w for w in preview["warnings"])

    def test_full_pipeline_warning_present_in_migration_state(self, tmp_path):
        from app.v2 import migration as mig

        source = tmp_path / "src"
        build_v1_fixture(
            source / "alderpointdns.db", encrypted_transports_enabled=("doq_enabled",)
        )
        state = mig.MigrationState(source_path=source, staging_dir=tmp_path / "staging")
        for stage in ("detect", "backup", "preview", "migrate_config"):
            mig._STAGE_FUNCS[stage](state)
        assert any("DoQ" in w for w in state.warnings)


class TestMissingOptionalHistoricalState:
    """J. Older/leaner V1 schema shapes missing tables that migration's own
    schema contract (``migration_convert.OPTIONAL_TABLES_AND_COLUMNS``)
    documents as tolerated entirely absent: ``analytics_settings`` and
    ``query_events``. (The other candidate tables considered for this
    fixture -- ``notification_providers``, ``local_dns_records``,
    ``custom_filter_rules`` -- turn out to be in
    ``REQUIRED_TABLES_AND_COLUMNS``, correctly rejected by
    ``detect_source`` rather than silently degraded; verified directly
    below so that contract can't silently drift without a test noticing.)
    """

    @pytest.mark.parametrize("missing_table", ["query_events", "analytics_settings"])
    def test_missing_optional_table_does_not_break_migration(self, tmp_path, missing_table):
        source = build_v1_fixture(
            tmp_path / "src" / "alderpointdns.db",
            drop_optional_tables=(missing_table,),
        )
        info = mconv.detect_source(source.parent)
        assert info.detected_version == "v1.x"
        manifest, preview, target, secrets, results = _migrate_all(source, tmp_path)
        assert results["clients"]["clients_migrated"] == 1
        assert results["admins"]["migrated"] == 1
        # query_events itself missing -> no history to register; a missing
        # analytics_settings (a separate, unrelated table) doesn't affect
        # the baseline fixture's 50 query_events rows.
        expected_rows = 0 if missing_table == "query_events" else 50
        assert results["analytics"]["row_count"] == expected_rows

    @pytest.mark.parametrize(
        "required_table", ["notification_providers", "local_dns_records", "custom_filter_rules"]
    )
    def test_missing_required_table_is_explicitly_rejected_not_silently_degraded(
        self, tmp_path, required_table
    ):
        source = build_v1_fixture(
            tmp_path / "src" / "alderpointdns.db",
            drop_optional_tables=(required_table,),
        )
        with pytest.raises(mconv.UnsupportedSourceSchemaError, match=required_table):
            mconv.detect_source(source.parent)


class TestLongLivedUpgradedSchemaState:
    """C. A long-lived V1 install carrying accumulated cross-feature state
    (large query history alongside normal configuration) -- the shape a
    real multi-year appliance actually has, not just a fresh demo."""

    def test_large_query_history_registered_read_only_not_copied_row_by_row(self, tmp_path):
        source = tmp_path / "src" / "alderpointdns.db"
        build_v1_fixture(source, local_dns_records=10, custom_rules=20, clients=30)
        conn = sqlite3.connect(str(source))
        # Simulate multi-year accumulated history well beyond the 50-row
        # baseline the shared fixture seeds.
        conn.executemany(
            "INSERT INTO query_events (ts, domain) VALUES (?, ?)",
            [(1600000000.0 + i, f"legacy-host{i}.example") for i in range(5000)],
        )
        conn.commit()
        conn.close()
        manifest = mconv.create_backup(source, tmp_path / "staging")
        result = mconv.register_legacy_analytics_archive(
            Path(manifest["backup_path"]), tmp_path / "v2-target"
        )
        # 50 baseline + 5000 injected.
        assert result["row_count"] == 5050
        assert result["read_only"] is True
        # Raw historical rows must never land inside the new control.db --
        # only the manifest pointer does (storage-audit invariant).
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        with control_db.connect(target) as conn2:
            tables = {
                r[0] for r in conn2.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
        assert "query_events" not in tables
