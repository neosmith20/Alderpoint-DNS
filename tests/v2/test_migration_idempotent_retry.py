"""Proves migration stage functions are idempotent under retry (§21/§22
"no duplicate converted objects", "idempotent stage replay") -- calling
each real conversion function twice in a row against the same target must
never double object counts. This specifically covers the gap the
crash-boundary tests (test_migration_durable_state.py) don't reach: a
retry of a stage that had already run to completion once (not just a
crash-before-the-stage-started scenario).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app.v2 import control_db, migration_convert as mconv
from app.v2 import notification_store as nstore
from app.v2 import policy_store as pstore
from app.v2.secret_store import SecretStore
from tests.v2._v1_fixture import build_v1_fixture


@pytest.fixture()
def backup_db(tmp_path):
    source = tmp_path / "v1-install"
    build_v1_fixture(source / "alderpointdns.db")
    info = mconv.detect_source(source)
    manifest = mconv.create_backup(info.db_path, tmp_path / "staging")
    return Path(manifest["backup_path"])


class TestClientsRetryIdempotent:
    def test_running_twice_does_not_duplicate(self, backup_db, tmp_path):
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        mconv.migrate_clients(backup_db, target)
        result2 = mconv.migrate_clients(backup_db, target)
        assert result2["clients_migrated"] == 1
        with control_db.connect(target) as conn:
            count = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
            id_count = conn.execute("SELECT COUNT(*) FROM client_identifiers").fetchone()[0]
        assert count == 1  # not 2
        assert id_count == 1  # not 2


class TestAdminsRetrySafe:
    def test_running_twice_does_not_raise_or_duplicate(self, backup_db, tmp_path):
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        mconv.migrate_admins(backup_db, target)
        mconv.migrate_admins(backup_db, target)  # must not raise
        with control_db.connect(target) as conn:
            count = conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        assert count == 1


class TestPoliciesRetryIdempotent:
    def test_running_twice_does_not_duplicate_networks(self, backup_db, tmp_path):
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        mconv.migrate_policies(backup_db, target)
        mconv.migrate_policies(backup_db, target)
        with control_db.connect(target) as conn:
            count = conn.execute("SELECT COUNT(*) FROM policy_networks").fetchone()[0]
        assert count == 1


class TestUpstreamsRetryIdempotent:
    def test_running_twice_does_not_raise_or_duplicate(self, backup_db, tmp_path):
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        mconv.migrate_upstreams(backup_db, target)
        mconv.migrate_upstreams(backup_db, target)  # must not raise duplicate-id error
        with control_db.connect(target) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM upstream_profiles WHERE upstream_profile_id = 'migrated-default'"
            ).fetchone()[0]
        assert count == 1


class TestNotificationsRetryIdempotent:
    def test_running_twice_does_not_raise_or_leak_orphan_secrets(self, backup_db, tmp_path):
        target = tmp_path / "control.db"
        mconv.initialize_target_control_db(target)
        secrets = SecretStore(tmp_path / "secrets")

        mconv.migrate_notifications(backup_db, target, secrets)
        first_ids = set(secrets.list_ids())

        mconv.migrate_notifications(backup_db, target, secrets)  # must not raise
        second_ids = set(secrets.list_ids())

        with control_db.connect(target) as conn:
            providers = nstore.list_providers(conn)
        assert len(providers) == 1  # not 2
        # No orphaned secret files accumulated from the first attempt.
        assert len(second_ids) == 1
        # The secret value itself is still correct and retrievable.
        assert secrets.get(providers[0].secret_ref) == "super-secret-token-abc"
