"""Owner product decision, second beta-rescue pass: a fresh V2 appliance
must visibly start with real, editable Cloudflare/Google upstream
profiles and V1.1.1's three default blocklist subscriptions in real
control state -- not a hidden runtime-only fallback the UI never shows.
Proves scripts/v2/alderpointdns_v2_ctl.py's _seed_fresh_install_defaults:
what it seeds, that it's idempotent (never duplicates on a second call,
matching "no duplicate seeding on reinstall/upgrade"), and that it never
overwrites an operator's own already-different global upstream choice
(matching "migration/upgrade preserves customization")."""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CTL_PATH = REPO_ROOT / "scripts" / "v2" / "alderpointdns_v2_ctl.py"


@pytest.fixture()
def ctl(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "var" / "lib"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    (tmp_path / "var" / "lib").mkdir(parents=True, exist_ok=True)

    sys.modules.pop("alderpointdns_v2_ctl", None)
    spec = importlib.util.spec_from_file_location("alderpointdns_v2_ctl", CTL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["alderpointdns_v2_ctl"] = module
    spec.loader.exec_module(module)

    from app.v2 import control_db, policy_store

    control_db.initialize(module.CONTROL_DB)
    policy_store.ensure_schema(module.CONTROL_DB)
    return module


class TestFreshInstallDefaults:
    def test_seeds_cloudflare_and_google_upstreams(self, ctl):
        from app.v2 import control_db, policy_store

        with control_db.connect(ctl.CONTROL_DB) as conn:
            ctl._seed_fresh_install_defaults(conn)
            profiles = {row[0]: row for row in conn.execute("SELECT upstream_profile_id, name FROM upstream_profiles")}
            assert set(profiles) == {"cloudflare", "google"}, profiles
            global_layer = policy_store.load_policy_layer(conn, "global", "singleton")
            assert global_layer.upstream_profile_id == "cloudflare"
            cf = policy_store.load_upstream_profile(conn, "cloudflare")
            assert {e.address for e in cf.endpoints} == {"1.1.1.1:53", "1.0.0.1:53"}
            gg = policy_store.load_upstream_profile(conn, "google")
            assert {e.address for e in gg.endpoints} == {"8.8.8.8:53", "8.8.4.4:53"}

    def test_seeds_exact_v1_1_1_default_blocklists(self, ctl):
        from app.v2 import control_db

        with control_db.connect(ctl.CONTROL_DB) as conn:
            ctl._seed_fresh_install_defaults(conn)
            names = {row[0] for row in conn.execute("SELECT name FROM blocklist_subscriptions")}
        assert names == {"AdGuard DNS filter", "StevenBlack Unified Hosts", "HaGeZi Multi Normal"}, names

    def test_seeding_is_idempotent_no_duplicates_on_second_call(self, ctl):
        from app.v2 import control_db

        with control_db.connect(ctl.CONTROL_DB) as conn:
            ctl._seed_fresh_install_defaults(conn)
            ctl._seed_fresh_install_defaults(conn)
            upstream_count = conn.execute("SELECT count(*) FROM upstream_profiles").fetchone()[0]
            blocklist_count = conn.execute("SELECT count(*) FROM blocklist_subscriptions").fetchone()[0]
        assert upstream_count == 2, upstream_count
        assert blocklist_count == 3, blocklist_count

    def test_seeding_never_overwrites_an_operator_already_different_upstream(self, ctl):
        """Simulates migration/upgrade: real state already exists (an
        operator- or migration-created upstream profile assigned as the
        active default) before seeding ever runs -- it must be left
        completely alone."""
        import dataclasses

        from app.v2 import control_db, policy_store
        from app.v2.policy_store import UpstreamEndpointRecord

        with control_db.connect(ctl.CONTROL_DB) as conn:
            policy_store.create_upstream_profile(
                conn, "office-resolver", "Office Resolver", "plain",
                [UpstreamEndpointRecord("10.0.0.53:53", None, 0, 1, None)],
            )
            layer = policy_store.load_policy_layer(conn, "global", "singleton")
            policy_store.save_policy_layer(conn, "global", "singleton", dataclasses.replace(layer, upstream_profile_id="office-resolver"))

            ctl._seed_fresh_install_defaults(conn)

            ids = {row[0] for row in conn.execute("SELECT upstream_profile_id FROM upstream_profiles")}
            assert ids == {"office-resolver"}, ids
            assert policy_store.load_policy_layer(conn, "global", "singleton").upstream_profile_id == "office-resolver"
