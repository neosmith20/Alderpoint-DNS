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


def _run_committed_migration(tmp_path, **fixture_kwargs):
    source = tmp_path / "v1-install"
    build_v1_fixture(source / "alderpointdns.db", **fixture_kwargs)
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

    def test_migrated_local_dns_and_filtering_actually_enforced_live(self, tmp_path):
        """Regression for the real defect the package-level migration test
        found (docs/v2/migration-real-package-gate.md): migrated local DNS
        records and block rules were generated/validated but never
        referenced by the live dnsdist.conf. Promotion now goes through
        the real per-effective-policy compiler, which must actually
        compile these into the live config."""
        state = _run_committed_migration(
            tmp_path, local_dns_records=3, custom_rules=4,
        )
        live = _live_paths(tmp_path)
        mig.promote_to_live(state, **live)
        text = (live["live_compiled_dir"] / "dnsdist.conf").read_text()

        # Baseline fixture's local DNS records ('nas'/'printer') plus 3
        # extras ('host3'..'host5') should all be compiled as SpoofAction
        # rules.
        assert 'QNameRule("nas.lan.")' in text
        assert 'SpoofAction({"10.0.0.10"})' in text
        assert 'QNameRule("host3.lan.")' in text

        # Baseline 'ads.example' block plus alternating extras should be
        # compiled as a real terminal block action (default response mode
        # is nxdomain).
        assert "ads.example" in text
        assert "RCodeAction(DNSRCode.NXDOMAIN)" in text

        with control_db.connect(live["live_control_db"]) as conn:
            layer = pstore.load_policy_layer(conn, "global", "singleton")
        assert layer.service_blocking_ruleset_id == "migrated-v1-custom-blocklist"
        assert layer.upstream_profile_id == "migrated-default"

    @REAL_BINARIES
    def test_migrated_runtime_actually_answers_for_local_dns_and_blocks(self, tmp_path):
        """End-to-end: start the real promoted dnsdist config and prove it
        answers a migrated local DNS record and refuses a migrated
        blocked domain -- not just that the Lua text contains the right
        substrings."""
        import socket
        import struct
        import subprocess
        import time as _time

        state = _run_committed_migration(tmp_path)
        live = _live_paths(tmp_path)
        mig.promote_to_live(state, live_listen_address="127.0.0.1:15360", **live)

        proc = subprocess.Popen(
            ["dnsdist", "-C", str(live["live_compiled_dir"] / "dnsdist.conf"),
             "--supervised", "--disable-syslog"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            _time.sleep(1.0)
            assert proc.poll() is None, "generated dnsdist config failed to start"

            def _query(qname: str) -> bytes:
                header = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
                qparts = b"".join(bytes([len(p)]) + p.encode() for p in qname.split("."))
                pkt = header + qparts + b"\x00" + struct.pack(">HH", 1, 1)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3)
                try:
                    s.sendto(pkt, ("127.0.0.1", 15360))
                    data, _ = s.recvfrom(4096)
                    return data
                finally:
                    s.close()

            local_answer = _query("nas.lan")
            assert (local_answer[3] & 0x0F) == 0  # NOERROR
            assert b"\x0a\x00\x00\x0a" in local_answer  # 10.0.0.10 as raw A-record bytes

            blocked_answer = _query("ads.example")
            assert (blocked_answer[3] & 0x0F) == 3  # NXDOMAIN
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
