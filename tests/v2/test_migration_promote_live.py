"""Tests for app/v2/migration.py's promote_to_live() -- the previously
missing step between "migration committed to staging" and "a real live V2
install actually has the migrated state" (§ V2 roadmap Priority 1: the
real package migration gate needs an actual promotion mechanism, not just
a staging pipeline). Real binaries (dnsdist, named-checkzone) are used;
this is exercised against isolated tmp_path "live" directories standing in
for /var/lib/alderpointdns-v2 / /etc paths -- never a real install.
"""

from __future__ import annotations

import shutil

import pytest

from app.v2 import control_db, migration as mig
from app.v2 import notification_store as nstore
from app.v2 import policy_store as pstore
from app.v2.secret_store import SecretStore
from tests.v2._v1_fixture import build_v1_fixture

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None
NAMED_CHECKZONE_INSTALLED = shutil.which("named-checkzone") is not None
REAL_BINARIES = pytest.mark.skipif(
    not (DNSDIST_INSTALLED and NAMED_CHECKZONE_INSTALLED),
    reason="requires installed dnsdist and named-checkzone",
)


def _live_paths(tmp_path):
    live_root = tmp_path / "live"
    return {
        "live_control_db": live_root / "control.db",
        "live_secrets_dir": live_root / "secrets",
        "live_compiled_dir": live_root / "compiled",
    }


def _run_committed_migration(tmp_path):
    source = tmp_path / "v1-install"
    build_v1_fixture(source / "alderpointdns.db")
    state = mig.run_migration(source, tmp_path / "staging")
    assert state.committed
    return state


@REAL_BINARIES
class TestPromoteToLive:
    def test_promote_writes_control_db_secrets_and_runtime(self, tmp_path):
        state = _run_committed_migration(tmp_path)
        live = _live_paths(tmp_path)
        result = mig.promote_to_live(state, **live)

        assert live["live_control_db"].exists()
        with control_db.connect(live["live_control_db"]) as conn:
            admins = conn.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
            providers = nstore.list_providers(conn)
        assert admins == 1
        assert len(providers) == 1

        live_secrets = SecretStore(live["live_secrets_dir"])
        assert live_secrets.get(providers[0].secret_ref) == "super-secret-token-abc"

        assert (live["live_compiled_dir"] / "dnsdist.conf").exists()
        assert result["secrets_promoted"] == 1

    def test_refuses_to_promote_uncommitted_state(self, tmp_path):
        source = tmp_path / "v1-install"
        build_v1_fixture(source / "alderpointdns.db")
        state = mig.run_migration(source, tmp_path / "staging", stop_before="commit")
        assert not state.committed
        with pytest.raises(mig.PromotionError, match="not reached commit"):
            mig.promote_to_live(state, **_live_paths(tmp_path))

    def test_refuses_to_clobber_already_configured_live_install(self, tmp_path):
        state = _run_committed_migration(tmp_path)
        live = _live_paths(tmp_path)
        live["live_control_db"].parent.mkdir(parents=True)
        pstore.ensure_schema(live["live_control_db"])
        nstore.ensure_schema(live["live_control_db"])
        with control_db.connect(live["live_control_db"]) as conn:
            conn.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES "
                "('existing-admin', '$argon2id$fake', '2026-01-01T00:00:00')"
            )
            conn.commit()

        with pytest.raises(mig.PromotionError, match="already has"):
            mig.promote_to_live(state, **live)

        # Live admin untouched by the refused promotion.
        with control_db.connect(live["live_control_db"]) as conn:
            row = conn.execute("SELECT username FROM admins").fetchone()
        assert row[0] == "existing-admin"

    def test_allow_overwrite_permits_promotion_onto_configured_install(self, tmp_path):
        state = _run_committed_migration(tmp_path)
        live = _live_paths(tmp_path)
        live["live_control_db"].parent.mkdir(parents=True)
        pstore.ensure_schema(live["live_control_db"])
        nstore.ensure_schema(live["live_control_db"])
        with control_db.connect(live["live_control_db"]) as conn:
            conn.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES "
                "('existing-admin', '$argon2id$fake', '2026-01-01T00:00:00')"
            )
            conn.commit()

        mig.promote_to_live(state, allow_overwrite=True, **live)
        with control_db.connect(live["live_control_db"]) as conn:
            row = conn.execute("SELECT username FROM admins").fetchone()
        assert row[0] == "admin"  # migrated admin now live, old one replaced

    def test_live_dnsdist_config_uses_real_listen_address_not_healthcheck_port(self, tmp_path):
        state = _run_committed_migration(tmp_path)
        live = _live_paths(tmp_path)
        mig.promote_to_live(state, live_listen_address="0.0.0.0:53", **live)
        text = (live["live_compiled_dir"] / "dnsdist.conf").read_text()
        assert "0.0.0.0:53" in text
        assert "15400" not in text  # the staging health-check's throwaway port

    def test_source_and_staging_untouched_by_promotion(self, tmp_path):
        state = _run_committed_migration(tmp_path)
        source_db = state.source_path / "alderpointdns.db"
        before = source_db.read_bytes()
        mig.promote_to_live(state, **_live_paths(tmp_path))
        after = source_db.read_bytes()
        assert before == after
