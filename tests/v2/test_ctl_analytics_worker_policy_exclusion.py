"""Real regression: per-client query_log_enabled/statistics_enabled
exclusions must actually apply to events produced by the real
analytics-protobuf-receiver pipeline (roadmap Priority 6 continuation).

Before this fix, cmd_analytics_worker's drain loop always constructed
NormalizedQueryEvent with the dataclass's own defaults
(query_log_enabled=True, statistics_enabled=True), never consulting
control.db at all -- so a real admin-configured per-client exclusion
had no effect whatsoever on real DNS traffic through the new analytics
wiring, even though app/v2/analytics_pipeline.py already correctly
enforces these flags once they're set on the event.

Exercises the actual packaged alderpointdns_v2_ctl.py module directly
(not a synthetic reimplementation), with real control.db policy state.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CTL_PATH = REPO_ROOT / "scripts" / "v2" / "alderpointdns_v2_ctl.py"


@pytest.fixture()
def ctl_module(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "var" / "lib"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_LOG_ROOT", str(tmp_path / "var" / "log"))
    for mod in list(sys.modules):
        if mod == "alderpointdns_v2_ctl":
            del sys.modules[mod]
    spec = importlib.util.spec_from_file_location("alderpointdns_v2_ctl", CTL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["alderpointdns_v2_ctl"] = module
    spec.loader.exec_module(module)
    return module


def _write_inbox_event(ctl_module, qname: str, client: str) -> None:
    inbox = ctl_module.STATE_DIR / "analytics" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    path = inbox / f"test-{qname}.jsonl"
    record = {
        "ts": 1700000000.0, "qname": qname, "qtype": "A",
        "protocol": "udp", "client": client, "rcode": "NOERROR",
    }
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")


def _seed_control_db(ctl_module):
    from app.v2 import control_db, policy_store

    ctl_module.STATE_DIR.mkdir(parents=True, exist_ok=True)
    policy_store.ensure_schema(ctl_module.CONTROL_DB)
    return control_db


def test_client_with_query_log_disabled_is_excluded_from_parquet(ctl_module):
    from app.v2 import control_db, policy_store

    _seed_control_db(ctl_module)
    with control_db.connect(ctl_module.CONTROL_DB) as conn:
        client_id = conn.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) "
            "VALUES ('excluded-client', '', 1, '2026-01-01', '2026-01-01')"
        ).lastrowid
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) "
            "VALUES (?, 'ipv4', '10.9.9.9', '2026-01-01')",
            (client_id,),
        )
        conn.commit()
        policy_store.save_policy_layer(
            conn, "client", str(client_id), policy_store.PolicyLayer(query_log_enabled=False)
        )
        conn.commit()

    _write_inbox_event(ctl_module, "excluded-domain.example", "10.9.9.9")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    # Parquet must NOT contain this event; aggregates (statistics) still
    # should, since only query_log_enabled was disabled for this client.
    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    for f in parquet_files:
        assert b"excluded-domain" not in f.read_bytes()


def test_client_with_statistics_disabled_is_excluded_from_aggregates(ctl_module):
    from app.v2 import aggregates_db, control_db, policy_store

    _seed_control_db(ctl_module)
    with control_db.connect(ctl_module.CONTROL_DB) as conn:
        client_id = conn.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) "
            "VALUES ('stats-excluded-client', '', 1, '2026-01-01', '2026-01-01')"
        ).lastrowid
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) "
            "VALUES (?, 'ipv4', '10.9.9.8', '2026-01-01')",
            (client_id,),
        )
        conn.commit()
        policy_store.save_policy_layer(
            conn, "client", str(client_id), policy_store.PolicyLayer(statistics_enabled=False)
        )
        conn.commit()

    _write_inbox_event(ctl_module, "stats-excluded-domain.example", "10.9.9.8")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    totals = aggregates_db.query_totals(
        ctl_module.ANALYTICS_AGGREGATES_DB,
        datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp(),
        datetime(2030, 1, 1, tzinfo=timezone.utc).timestamp(),
    )
    assert sum(row[1] for row in totals) == 0  # "total" column, nothing recorded


def test_unregistered_client_falls_back_to_global_policy_not_hardcoded_default(ctl_module):
    from app.v2 import control_db, policy_store

    _seed_control_db(ctl_module)
    with control_db.connect(ctl_module.CONTROL_DB) as conn:
        policy_store.save_policy_layer(conn, "global", "singleton", policy_store.PolicyLayer(query_log_enabled=False))
        conn.commit()

    _write_inbox_event(ctl_module, "unregistered-client-domain.example", "10.9.9.7")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    for f in parquet_files:
        assert b"unregistered-client-domain" not in f.read_bytes()


def test_client_with_no_exclusions_is_logged_normally(ctl_module):
    _seed_control_db(ctl_module)
    _write_inbox_event(ctl_module, "normal-domain.example", "10.9.9.6")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    assert any(b"normal-domain" in f.read_bytes() for f in parquet_files)


def test_policy_lookup_failure_defaults_to_logged_not_silently_dropped(ctl_module, monkeypatch):
    # If the real policy lookup itself raises for some reason, the event
    # must still be processed (defaulting to logged/counted) rather than
    # an analytics worker bug silently blackholing all real traffic.
    _seed_control_db(ctl_module)
    monkeypatch.setattr(
        ctl_module, "_query_log_flags_for_client",
        lambda conn, client_ip, now: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    _write_inbox_event(ctl_module, "resilient-domain.example", "10.9.9.5")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    assert any(b"resilient-domain" in f.read_bytes() for f in parquet_files)
