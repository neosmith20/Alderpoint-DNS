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


def test_malformed_inbox_file_is_quarantined_not_retried(ctl_module):
    _seed_control_db(ctl_module)
    inbox = ctl_module.STATE_DIR / "analytics" / "inbox"
    inbox.mkdir(parents=True, exist_ok=True)
    bad_file = inbox / "bad.jsonl"
    bad_file.write_text("{not-json\n", encoding="utf-8")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    assert not bad_file.exists()
    quarantine = ctl_module.STATE_DIR / "analytics" / "quarantine"
    quarantined = [p for p in quarantine.glob("bad.jsonl.bad-*") if p.suffix != ".json"]
    assert len(quarantined) == 1
    assert list(quarantine.glob("bad.jsonl.bad-*.json"))


def test_real_client_name_is_populated_not_left_blank(ctl_module):
    # Real defect found in the same pass as cache_profile_id/action/
    # upstream_profile_id: client_name (a real projectable/sortable
    # query-log column, app/v2/analytics_query.py) was also always
    # left blank for every real event with a registered client -- the
    # client_id needed to look it up was already resolved right there
    # and simply never used for this.
    import pyarrow.parquet as pq

    from app.v2 import control_db, policy_store

    _seed_control_db(ctl_module)
    with control_db.connect(ctl_module.CONTROL_DB) as conn:
        conn.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) "
            "VALUES ('Kids Tablet', '', 1, '2026-01-01', '2026-01-01')"
        )
        client_id = conn.execute("SELECT id FROM clients WHERE name='Kids Tablet'").fetchone()[0]
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) "
            "VALUES (?, 'ipv4', '10.9.9.12', '2026-01-01')",
            (client_id,),
        )
        conn.commit()

    _write_inbox_event(ctl_module, "client-name-domain.example", "10.9.9.12")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    rows = [r for f in parquet_files for r in pq.read_table(f).to_pylist()]
    row = next(r for r in rows if r["domain"] == "client-name-domain.example")
    assert row["client_name"] == "Kids Tablet"


def test_real_upstream_profile_id_is_populated_not_left_blank(ctl_module):
    # Real defect found in the same investigation pass as
    # cache_profile_id/blocked-action (docs/v2/blocked-action-not-
    # populated-fix.md): upstream_profile_id -- also a real
    # filterable query-log column (app/v2/analytics_query.py's
    # "upstream") -- was likewise always left blank for every real
    # dnsdist-sourced event, for the exact same root cause: the
    # per-client EffectivePolicy was already compiled right there and
    # simply never read for this field either.
    import pyarrow.parquet as pq

    from app.v2 import control_db, policy_store

    _seed_control_db(ctl_module)
    with control_db.connect(ctl_module.CONTROL_DB) as conn:
        client_id = conn.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) "
            "VALUES ('upstream-profile-client', '', 1, '2026-01-01', '2026-01-01')"
        ).lastrowid
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) "
            "VALUES (?, 'ipv4', '10.9.9.11', '2026-01-01')",
            (client_id,),
        )
        conn.commit()
        policy_store.save_policy_layer(
            conn, "client", str(client_id), policy_store.PolicyLayer(upstream_profile_id="secure-dns-profile")
        )
        conn.commit()

    _write_inbox_event(ctl_module, "upstream-profile-domain.example", "10.9.9.11")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    rows = [r for f in parquet_files for r in pq.read_table(f).to_pylist()]
    row = next(r for r in rows if r["domain"] == "upstream-profile-domain.example")
    assert row["upstream"] == "secure-dns-profile"


def test_real_effective_cache_profile_id_is_populated_not_left_blank(ctl_module):
    # Real defect found live during the RC13/RC14/RC15 continuation
    # (docs/v2/cache-profile-id-not-populated-fix.md): every real
    # dnsdist-sourced analytics event's cache_profile_id was always ""
    # -- a real filterable/sortable query-log column
    # (app/v2/analytics_query.py) that was silently non-functional,
    # even though the exact per-client policy compile this worker
    # already does for query_log_enabled/statistics_enabled was one
    # call away from also producing the real answer via
    # compile_cache_profile. Proves a client with a real,
    # answer-affecting policy override gets a real, non-default,
    # non-blank cache_profile_id threaded all the way into parquet.
    import pyarrow.parquet as pq

    from app.v2 import control_db, policy_store
    from app.v2.policy_compiler import compile_cache_profile, compile_effective_policy

    _seed_control_db(ctl_module)
    with control_db.connect(ctl_module.CONTROL_DB) as conn:
        global_profile_id = compile_cache_profile(
            compile_effective_policy(global_layer=policy_store.load_policy_layer(conn, "global", "singleton"))
        ).profile_id

        client_id = conn.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) "
            "VALUES ('cache-profile-client', '', 1, '2026-01-01', '2026-01-01')"
        ).lastrowid
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) "
            "VALUES (?, 'ipv4', '10.9.9.9', '2026-01-01')",
            (client_id,),
        )
        conn.commit()
        policy_store.save_policy_layer(
            conn, "client", str(client_id), policy_store.PolicyLayer(upstream_profile_id="custom-profile")
        )
        conn.commit()

    _write_inbox_event(ctl_module, "cache-profile-domain.example", "10.9.9.9")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    profile_ids = []
    for f in parquet_files:
        table = pq.read_table(f)
        rows = table.to_pylist()
        profile_ids.extend(r["cache_profile_id"] for r in rows if r.get("domain") == "cache-profile-domain.example")
    assert profile_ids, "the event itself never landed"
    assert all(pid for pid in profile_ids), "cache_profile_id must not be blank for a client with a real override"
    assert all(pid != global_profile_id for pid in profile_ids), \
        "the client's overridden cache profile must differ from the global default, not just be non-blank"


def test_real_blocked_query_gets_action_blocked_not_silently_allowed(ctl_module):
    # Real defect found live during the RC13-RC16 continuation
    # (docs/v2/blocked-action-not-populated-fix.md): app/v2/
    # filtering_decision.py's evaluate_filtering -- the real, tested
    # "why was this blocked" decision engine -- was never actually
    # invoked anywhere in production, so every real dnsdist-sourced
    # analytics event defaulted to action="allowed" unconditionally,
    # even for a domain a real admin had explicitly configured to be
    # blocked. This proves the fix end to end: a real service-blocking
    # ruleset assigned to a client marks a real matching query as
    # action="blocked" with the real service_id as block_reason, all
    # the way through to the written Parquet segment.
    import pyarrow.parquet as pq

    from app.v2 import control_db, policy_store

    _seed_control_db(ctl_module)
    with control_db.connect(ctl_module.CONTROL_DB) as conn:
        policy_store.create_service(
            conn, "blocked-app", "Blocked App", [("exact", "blocked-app.example")], category="service"
        )
        policy_store.create_service_ruleset(conn, "blocklist-1", ["blocked-app"])
        conn.commit()

        client_id = conn.execute(
            "INSERT INTO clients(name, description, enabled, created_at, updated_at) "
            "VALUES ('blocked-ruleset-client', '', 1, '2026-01-01', '2026-01-01')"
        ).lastrowid
        conn.execute(
            "INSERT INTO client_identifiers(client_id, kind, value, created_at) "
            "VALUES (?, 'ipv4', '10.9.9.10', '2026-01-01')",
            (client_id,),
        )
        conn.commit()
        policy_store.save_policy_layer(
            conn, "client", str(client_id), policy_store.PolicyLayer(service_blocking_ruleset_id="blocklist-1")
        )
        conn.commit()

    _write_inbox_event(ctl_module, "blocked-app.example", "10.9.9.10")
    _write_inbox_event(ctl_module, "not-blocked.example", "10.9.9.10")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    rows = [r for f in parquet_files for r in pq.read_table(f).to_pylist()]
    blocked = next(r for r in rows if r["domain"] == "blocked-app.example")
    allowed = next(r for r in rows if r["domain"] == "not-blocked.example")
    assert blocked["blocked"] is True
    assert blocked["block_reason"] == "blocked-app"
    assert allowed["blocked"] is False


def test_prewarm_source_ip_is_unconditionally_excluded_from_both_sinks(ctl_module):
    # Real defect found live during the RC13/RC14 continuation
    # (docs/v2/prewarm-analytics-pollution-fix.md): Tier B prewarm
    # replays real queries through the live DNS path from client
    # "127.0.0.1" -- identical to real client traffic -- silently
    # inflating every dashboard/statistic with the appliance's own
    # self-generated re-queries. app/v2/tier_b_worker.py now sources
    # that traffic from a dedicated PREWARM_SOURCE_IP instead; this
    # pins that _effective_flags_for_client excludes it from BOTH
    # sinks unconditionally -- not via the normal per-client policy
    # chain (no control.db state is seeded for it at all here,
    # confirming it isn't a policy decision an admin could
    # accidentally leave permissive).
    from app.v2.tier_b_worker import PREWARM_SOURCE_IP

    _seed_control_db(ctl_module)
    _write_inbox_event(ctl_module, "prewarmed-domain.example", PREWARM_SOURCE_IP)

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    assert not any(b"prewarmed-domain" in f.read_bytes() for f in parquet_files), \
        "prewarm's self-generated traffic must never reach the real query log"

    import sqlite3
    if ctl_module.ANALYTICS_AGGREGATES_DB.exists():
        conn = sqlite3.connect(ctl_module.ANALYTICS_AGGREGATES_DB)
        total = conn.execute("SELECT COALESCE(SUM(total_queries), 0) FROM time_buckets").fetchone()[0]
        conn.close()
        assert total == 0, "prewarm's self-generated traffic must never inflate real statistics"


def test_policy_lookup_failure_defaults_to_logged_not_silently_dropped(ctl_module, monkeypatch):
    # If the real policy lookup itself raises for some reason, the event
    # must still be processed (defaulting to logged/counted) rather than
    # an analytics worker bug silently blackholing all real traffic.
    _seed_control_db(ctl_module)
    monkeypatch.setattr(
        ctl_module, "_effective_flags_for_client",
        lambda conn, client_ip, now: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    _write_inbox_event(ctl_module, "resilient-domain.example", "10.9.9.5")

    args = argparse.Namespace(once=True, interval_seconds=1.0, inject_test_event=False)
    rc = ctl_module.cmd_analytics_worker(args)
    assert rc == 0

    parquet_dir = ctl_module.ANALYTICS_PARQUET_DIR
    parquet_files = list(parquet_dir.rglob("*.parquet")) if parquet_dir.exists() else []
    assert any(b"resilient-domain" in f.read_bytes() for f in parquet_files)
