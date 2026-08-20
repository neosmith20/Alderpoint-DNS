"""Regression for a severe, real defect found live during a real
V1.1.1 -> V2 migration/restart acceptance test (beta-rescue
continuation): scripts/v2/alderpointdns_v2_ctl.py's `schedule-worker`
subcommand's on_transition callback used to call `cmd_generate_runtime`
-- the install-time BOOTSTRAP compiler, which unconditionally generates
an EMPTY RPZ zone and bare default dnsdist config, ignoring
control.db entirely. `ScheduleTransitionRuntime.on_start()` treats
every single service start as an implicit transition (see
app/v2/schedule_runtime.py's own §26 docstring) -- so every restart of
`alderpointdns-v2-schedule.service` (every reboot, every crash-restart)
silently wiped every real configured block domain, upstream, and
encrypted-transport setting back to nothing, with no error surfaced
anywhere.

Confirmed live: a real migrated appliance correctly blocked a migrated
domain immediately after migration, then stopped blocking it and
started leaking to real upstream resolution after nothing more than a
plain restart.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CTL_PATH = REPO_ROOT / "scripts" / "v2" / "alderpointdns_v2_ctl.py"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_LOG_ROOT", str(tmp_path / "log"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    return tmp_path


@pytest.fixture()
def seeded_control_db(env):
    from app.v2 import control_db, policy_store
    from app.v2.policy_model import PolicyLayer

    db_path = env / "state" / "control.db"
    control_db.initialize(db_path)
    policy_store.ensure_schema(db_path)
    with control_db.connect(db_path) as conn:
        policy_store.create_service(conn, "svc-1", "Blocked Service", [("exact", "blocked.schedule-worker-test.example")], category="test")
        policy_store.create_service_ruleset(conn, "schedule-worker-test-ruleset", ["svc-1"])
        policy_store.save_policy_layer(conn, "global", "singleton", PolicyLayer(service_blocking_ruleset_id="schedule-worker-test-ruleset"))
        conn.commit()
    # A real appliance's secret store is already initialized by
    # postinst's own init-state before any service (including this
    # worker) ever starts.
    (env / "state" / "secrets").mkdir(parents=True, exist_ok=True)
    return db_path


@pytest.fixture()
def ctl_module(env):
    for mod in ("alderpointdns_v2_ctl",):
        sys.modules.pop(mod, None)
    for mod in ("app.v2.webapp",):
        sys.modules.pop(mod, None)
        if hasattr(sys.modules.get("app.v2"), mod.rsplit(".", 1)[-1]):
            delattr(sys.modules["app.v2"], mod.rsplit(".", 1)[-1])
    spec = importlib.util.spec_from_file_location("alderpointdns_v2_ctl", CTL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["alderpointdns_v2_ctl"] = module
    spec.loader.exec_module(module)
    return module


def test_schedule_worker_on_start_recompiles_from_real_control_db_not_empty_bootstrap(ctl_module, seeded_control_db, env):
    """The core regression assertion: after a schedule-worker on_start
    tick (exactly what a real service restart triggers), the compiled
    dnsdist.conf -- the artifact that actually enforces blocking, first
    in the locked hot path (client -> dnsdist packet cache -> ... ->
    BIND -> upstream); BIND's RPZ zone is a separate mechanism
    recompile_and_promote does not rewrite the content of at all -- must
    contain a real addAction blocking rule for the real configured
    domain, not the bare install-time bootstrap default (no blocking
    rules, a single hardcoded loopback upstream, no reference to any
    real control.db state at all).
    """
    rc = ctl_module.cmd_generate_runtime(argparse.Namespace(dnsdist_binary="dnsdist", named_checkzone_binary="named-checkzone", named_checkconf_binary="named-checkconf"))
    assert rc == 0
    bootstrap_dnsdist_conf = (env / "state" / "compiled" / "dnsdist.conf").read_text()
    assert "PROTOTYPE" in bootstrap_dnsdist_conf  # sanity: this really is the bootstrap default

    rc = ctl_module.cmd_schedule_worker(argparse.Namespace(once=True, interval_seconds=60))
    assert rc == 0

    dnsdist_conf_path = env / "state" / "compiled" / "dnsdist.conf"
    assert dnsdist_conf_path.exists(), "schedule-worker's on_start tick must produce a compiled dnsdist.conf"
    dnsdist_conf_text = dnsdist_conf_path.read_text()
    assert "blocked.schedule-worker-test.example" in dnsdist_conf_text, (
        "schedule-worker's on_start recompile dropped the real configured blocked domain -- "
        f"got the empty install-time bootstrap config instead:\n{dnsdist_conf_text}"
    )
    assert "PROTOTYPE" not in dnsdist_conf_text, (
        "schedule-worker's on_start recompile left the install-time bootstrap default in place "
        "instead of recompiling from real control.db policy"
    )


def test_schedule_worker_does_not_call_the_empty_bootstrap_compiler(ctl_module):
    """Direct guard against the exact regression: on_transition must
    never be wired to cmd_generate_runtime (the install-time-only bootstrap
    compiler that ignores control.db) again. Checks the compiled
    bytecode's real call graph, not the source text (which legitimately
    mentions the name in its own docstring/comments), so this can't
    false-positive on prose."""
    on_transition = None
    for const in ctl_module.cmd_schedule_worker.__code__.co_consts:
        if hasattr(const, "co_name") and const.co_name == "on_transition":
            on_transition = const
            break
    assert on_transition is not None, "cmd_schedule_worker must define an on_transition closure"
    called_names = set(on_transition.co_names)
    assert "cmd_generate_runtime" not in called_names, (
        "cmd_schedule_worker's on_transition must never call cmd_generate_runtime -- "
        "that unconditionally produces an empty bootstrap RPZ/dnsdist config, "
        "ignoring real control.db policy state"
    )
    assert "_mutate_and_promote" in called_names, (
        "cmd_schedule_worker's on_transition must reuse the real, control.db-driven "
        "recompile+promote path (app.v2.webapp._mutate_and_promote), the same one "
        "every real policy mutation through the management API uses"
    )


def test_schedule_worker_survives_missing_control_db_without_crashing(ctl_module, env):
    """Real fresh-boot edge case (postinst hasn't run init-state yet, or
    a genuinely corrupted install): must log and retry, never crash the
    worker loop."""
    rc = ctl_module.cmd_schedule_worker(argparse.Namespace(once=True, interval_seconds=60))
    assert rc == 0  # cmd_schedule_worker itself always returns 0; on_transition's own failure is swallowed and logged
