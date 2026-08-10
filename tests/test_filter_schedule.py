#!/usr/bin/env python3
"""Sandboxed tests for the global Filter Update Interval.

Everything here is confined to a temporary directory: the database, the
systemd unit drop-in path, the compiler's compiled/staging/download paths, and
every subprocess call (systemctl, named-checkzone, rndc, dig) is stubbed. No
live service, unit file, or system database is touched.
"""

from __future__ import annotations

import argparse
import contextlib
import inspect
import io
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import alderpointdns_compiler as compiler  # noqa: E402
from app import dns_cache, filter_schedule, local_dns, replication, upstream_dns, webapp  # noqa: E402


EXPECTED_CHOICES = (
    ("disabled", "Disabled — No Updates"),
    ("1", "1 Hour"),
    ("12", "12 Hours"),
    ("24", "1 Day"),
    ("72", "3 Days"),
    ("168", "1 Week"),
)

REJECTED_INTERVALS = (
    "",
    "   ",
    "0",
    0,
    2,
    "2",
    "23",
    "25",
    "169",
    -24,
    "-24",
    "24.0",
    1.5,
    True,
    None,
    "1h",
    "168h",
    "1 Hour",
    "1h; rm -rf /",
    "24 && systemctl stop named",
    "$(id)",
    "`id`",
    "daily",
    "*/5 * * * *",
    "OnCalendar=daily",
    "OnUnitActiveSec=1h",
    "alderpointdns-filter-update.timer",
    "named.service",
    "/etc/systemd/system/alderpointdns-filter-update.timer.d/alderpointdns.conf",
    "../../etc/passwd",
    "disabled; enable",
    ["24"],
    {"interval_hours": "24"},
)


class FilterScheduleTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-filter-schedule-test-"))
        self.old = {
            "fs_db": filter_schedule.DB_PATH,
            "fs_systemd": filter_schedule.SYSTEMD_DIR,
            "fs_override_dir": filter_schedule.FILTER_TIMER_OVERRIDE_DIR,
            "fs_override": filter_schedule.FILTER_TIMER_OVERRIDE,
            "compiler_db": compiler.DB_PATH,
            "compiler_download": compiler.DOWNLOAD_DIR,
            "compiler_rpz": compiler.COMPILED_RPZ,
            "compiler_staging": compiler.STAGING_DIR,
            "compiler_backup": compiler.BACKUP_DIR,
            "compiler_lock": compiler.DEPLOY_LOCK,
            "webapp_db": webapp.DB_PATH,
        }
        db_path = self.tmp / "alderpointdns.db"
        filter_schedule.DB_PATH = db_path
        filter_schedule.SYSTEMD_DIR = self.tmp / "systemd"
        filter_schedule.FILTER_TIMER_OVERRIDE_DIR = filter_schedule.SYSTEMD_DIR / f"{filter_schedule.TIMER_UNIT}.d"
        filter_schedule.FILTER_TIMER_OVERRIDE = filter_schedule.FILTER_TIMER_OVERRIDE_DIR / "alderpointdns.conf"
        compiler.DB_PATH = db_path
        compiler.DOWNLOAD_DIR = self.tmp / "downloads"
        compiler.COMPILED_RPZ = self.tmp / "compiled" / "bind" / "alderpointdns.rpz"
        compiler.STAGING_DIR = self.tmp / "staging"
        compiler.BACKUP_DIR = self.tmp / "backups"
        compiler.DEPLOY_LOCK = compiler.STAGING_DIR / "deploy.lock"
        webapp.DB_PATH = db_path
        for path in (filter_schedule.SYSTEMD_DIR, compiler.DOWNLOAD_DIR, compiler.STAGING_DIR,
                     compiler.BACKUP_DIR, compiler.COMPILED_RPZ.parent):
            path.mkdir(parents=True, exist_ok=True)

        self.systemctl_calls: list[tuple[list[str], bool]] = []
        compiler.init_db()

    def tearDown(self) -> None:
        filter_schedule.DB_PATH = self.old["fs_db"]
        filter_schedule.SYSTEMD_DIR = self.old["fs_systemd"]
        filter_schedule.FILTER_TIMER_OVERRIDE_DIR = self.old["fs_override_dir"]
        filter_schedule.FILTER_TIMER_OVERRIDE = self.old["fs_override"]
        compiler.DB_PATH = self.old["compiler_db"]
        compiler.DOWNLOAD_DIR = self.old["compiler_download"]
        compiler.COMPILED_RPZ = self.old["compiler_rpz"]
        compiler.STAGING_DIR = self.old["compiler_staging"]
        compiler.BACKUP_DIR = self.old["compiler_backup"]
        compiler.DEPLOY_LOCK = self.old["compiler_lock"]
        webapp.DB_PATH = self.old["webapp_db"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_run(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        self.systemctl_calls.append((list(command), check))
        return subprocess.CompletedProcess(command, 0, "ok\n")

    def quiet(self):
        """Keeps the compiler subcommands' status output out of test output."""
        return contextlib.redirect_stdout(io.StringIO())

    def deploy_schedule(self) -> str:
        with mock.patch.object(filter_schedule, "run", self.fake_run):
            return filter_schedule.deploy_filter_schedule()


class SettingsTest(FilterScheduleTestBase):
    def test_choices_and_labels_are_the_exact_fixed_set(self) -> None:
        self.assertEqual(filter_schedule.INTERVAL_CHOICES, EXPECTED_CHOICES)

    def test_fresh_install_default_is_one_day(self) -> None:
        cfg = filter_schedule.settings()
        self.assertEqual(cfg["interval_hours"], "24")
        self.assertEqual(filter_schedule.interval_label(cfg["interval_hours"]), "1 Day")
        self.assertTrue(filter_schedule.is_enabled(cfg))

    def test_existing_setting_is_never_overwritten_by_reinit(self) -> None:
        filter_schedule.update_settings({"interval_hours": "168"})
        filter_schedule.init_db()
        compiler.init_db()
        self.assertEqual(filter_schedule.settings()["interval_hours"], "168")

    def test_existing_disabled_setting_survives_reinit(self) -> None:
        filter_schedule.update_settings({"interval_hours": "disabled"})
        compiler.init_db()
        cfg = filter_schedule.settings()
        self.assertEqual(cfg["interval_hours"], "disabled")
        self.assertFalse(filter_schedule.is_enabled(cfg))

    def test_out_of_band_stored_value_is_reset_to_default(self) -> None:
        conn = filter_schedule.connect()
        try:
            conn.execute("UPDATE filter_update_settings SET value='6h; rm -rf /' WHERE key='interval_hours'")
            conn.commit()
        finally:
            conn.close()
        filter_schedule.init_db()
        self.assertEqual(filter_schedule.settings()["interval_hours"], "24")

    def test_canonical_values_are_accepted(self) -> None:
        for value, _label in EXPECTED_CHOICES:
            self.assertEqual(filter_schedule.validate_interval(value), value)
            filter_schedule.update_settings({"interval_hours": value})
            self.assertEqual(filter_schedule.settings()["interval_hours"], value)

    def test_integer_hours_from_the_allowlist_are_accepted(self) -> None:
        self.assertEqual(filter_schedule.validate_interval(24), "24")
        self.assertEqual(filter_schedule.validate_interval(168), "168")

    def test_surrounding_whitespace_and_case_are_normalized(self) -> None:
        self.assertEqual(filter_schedule.validate_interval(" DISABLED "), "disabled")
        self.assertEqual(filter_schedule.validate_interval(" 72 "), "72")

    def test_values_outside_the_allowlist_are_rejected(self) -> None:
        for candidate in REJECTED_INTERVALS:
            with self.subTest(candidate=candidate):
                with self.assertRaises(filter_schedule.FilterScheduleError):
                    filter_schedule.validate_interval(candidate)
                with self.assertRaises(filter_schedule.FilterScheduleError):
                    filter_schedule.update_settings({"interval_hours": candidate})
        self.assertEqual(filter_schedule.settings()["interval_hours"], "24")

    def test_rejection_message_lists_the_allowed_labels(self) -> None:
        with self.assertRaises(filter_schedule.FilterScheduleError) as ctx:
            filter_schedule.validate_interval("1h; rm -rf /")
        for _value, label in EXPECTED_CHOICES:
            self.assertIn(label, str(ctx.exception))


class TimerDeploymentTest(FilterScheduleTestBase):
    def test_every_interval_maps_to_the_expected_drop_in(self) -> None:
        expected = {"1": 1, "12": 12, "24": 24, "72": 72, "168": 168}
        for value, hours in expected.items():
            with self.subTest(interval=value):
                self.systemctl_calls = []
                filter_schedule.update_settings({"interval_hours": value})
                summary = json.loads(self.deploy_schedule())
                self.assertEqual(
                    filter_schedule.FILTER_TIMER_OVERRIDE.read_text(),
                    f"[Timer]\nOnBootSec={hours}h\nOnUnitActiveSec={hours}h\n",
                )
                self.assertEqual(summary["state"], "enabled")
                self.assertEqual(summary["interval"], value)
                self.assertEqual(summary["interval_label"], dict(EXPECTED_CHOICES)[value])
                self.assertEqual(
                    self.systemctl_calls,
                    [
                        (["systemctl", "daemon-reload"], True),
                        (["systemctl", "enable", "--now", "alderpointdns-filter-update.timer"], True),
                    ],
                )

    def test_disabled_removes_the_drop_in_and_disables_the_timer(self) -> None:
        filter_schedule.update_settings({"interval_hours": "12"})
        self.deploy_schedule()
        self.assertTrue(filter_schedule.FILTER_TIMER_OVERRIDE.exists())
        self.systemctl_calls = []
        filter_schedule.update_settings({"interval_hours": "disabled"})
        summary = json.loads(self.deploy_schedule())
        self.assertEqual(summary["state"], "disabled")
        self.assertFalse(filter_schedule.FILTER_TIMER_OVERRIDE.exists())
        # A clean stop that must not fail when the timer was never enabled:
        # check=False, exactly like deploy_backup_schedule() does.
        self.assertEqual(
            self.systemctl_calls,
            [
                (["systemctl", "daemon-reload"], True),
                (["systemctl", "disable", "--now", "alderpointdns-filter-update.timer"], False),
            ],
        )

    def test_reenabling_restores_the_selected_cadence(self) -> None:
        filter_schedule.update_settings({"interval_hours": "disabled"})
        self.deploy_schedule()
        filter_schedule.update_settings({"interval_hours": "72"})
        self.deploy_schedule()
        self.assertEqual(
            filter_schedule.FILTER_TIMER_OVERRIDE.read_text(),
            "[Timer]\nOnBootSec=72h\nOnUnitActiveSec=72h\n",
        )
        self.assertIn((["systemctl", "enable", "--now", "alderpointdns-filter-update.timer"], True), self.systemctl_calls)

    def test_systemctl_only_ever_receives_fixed_arguments(self) -> None:
        for value, _label in EXPECTED_CHOICES:
            filter_schedule.update_settings({"interval_hours": value})
            self.deploy_schedule()
        allowed = {
            "systemctl", "daemon-reload", "enable", "disable", "--now",
            "alderpointdns-filter-update.timer",
        }
        for command, _check in self.systemctl_calls:
            for token in command:
                self.assertIn(token, allowed)

    def test_drop_in_content_is_rendered_only_from_the_allowlist(self) -> None:
        with self.assertRaises(KeyError):
            filter_schedule.drop_in_content("1h; rm -rf /")


class NextRunTest(FilterScheduleTestBase):
    def test_parses_a_real_systemctl_property(self) -> None:
        self.assertEqual(
            filter_schedule.parse_next_elapse("NextElapseUSecRealtime=Wed 2026-07-29 23:00:00 UTC\n"),
            "Wed 2026-07-29 23:00:00 UTC",
        )

    def test_treats_absent_and_na_values_as_unknown(self) -> None:
        for output in ("NextElapseUSecRealtime=n/a", "NextElapseUSecRealtime=0", "NextElapseUSecRealtime=", "", "NextElapseUSecMonotonic=1", "garbage"):
            with self.subTest(output=output):
                self.assertIsNone(filter_schedule.parse_next_elapse(output))

    def test_next_run_at_is_none_when_systemctl_is_unavailable(self) -> None:
        def missing(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("systemctl")

        with mock.patch.object(filter_schedule, "run", missing):
            self.assertIsNone(filter_schedule.next_run_at())

    def test_next_run_at_is_none_when_systemctl_fails(self) -> None:
        def failing(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 1, "Failed to get properties\n")

        with mock.patch.object(filter_schedule, "run", failing):
            self.assertIsNone(filter_schedule.next_run_at())

    def test_next_run_at_returns_the_parsed_timestamp(self) -> None:
        def showing(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["systemctl", "list-timers"]:
                return subprocess.CompletedProcess(command, 1, "")
            assert command == ["systemctl", "show", "alderpointdns-filter-update.timer", "--property=NextElapseUSecRealtime"]
            return subprocess.CompletedProcess(command, 0, "NextElapseUSecRealtime=Thu 2026-07-30 00:00:00 UTC\n")

        with mock.patch.object(filter_schedule, "run", showing):
            self.assertEqual(filter_schedule.next_run_at(), "Thu 2026-07-30 00:00:00 UTC")

    def test_next_run_at_prefers_list_timers_json_for_monotonic_timers(self) -> None:
        # OnBootSec/OnUnitActiveSec timers have an empty NextElapseUSecRealtime;
        # only list-timers projects the next elapse onto the wall clock.
        payload = json.dumps([
            {
                "next": 1785468006114791,
                "left": 77000000000,
                "last": 1785390054644816,
                "passed": 0,
                "unit": "alderpointdns-filter-update.timer",
                "activates": "alderpointdns-filter-update.service",
            }
        ])

        def listing(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["systemctl", "list-timers"]:
                assert command == ["systemctl", "list-timers", "alderpointdns-filter-update.timer", "--all", "-o", "json"]
                return subprocess.CompletedProcess(command, 0, payload)
            raise AssertionError("the show fallback must not run when JSON output has a next elapse")

        with mock.patch.object(filter_schedule, "run", listing):
            self.assertEqual(filter_schedule.next_run_at(), "2026-07-31T03:20:06+00:00")

    def test_parse_next_from_timers_json_rejects_garbage(self) -> None:
        for output in ("", "not json", "{}", "[]", json.dumps([{"unit": "other.timer", "next": 5}]),
                       json.dumps([{"unit": "alderpointdns-filter-update.timer", "next": None}]),
                       json.dumps([{"unit": "alderpointdns-filter-update.timer", "next": 0}])):
            with self.subTest(output=output):
                self.assertIsNone(filter_schedule.parse_next_from_timers_json(output))


class ScheduledRunTest(FilterScheduleTestBase):
    def test_success_records_attempt_success_and_sanitized_result(self) -> None:
        with mock.patch.object(compiler, "deploy", return_value=41) as deployed, self.quiet():
            compiler.filter_update_run(argparse.Namespace())
        self.assertEqual(deployed.call_args.kwargs, {"download": True, "trigger": "scheduled"})
        cfg = filter_schedule.settings()
        self.assertTrue(cfg["last_attempt"])
        self.assertTrue(cfg["last_success"])
        result = filter_schedule.last_result(cfg)
        self.assertEqual(result["status"], "deployed")
        self.assertEqual(result["deployment_id"], 41)

    def test_failure_records_attempt_but_not_success_and_exits_nonzero(self) -> None:
        with mock.patch.object(compiler, "deploy", side_effect=RuntimeError("post-deploy ordinary resolution failed")), self.quiet():
            with self.assertRaises(SystemExit) as ctx:
                compiler.filter_update_run(argparse.Namespace())
        self.assertEqual(ctx.exception.code, 1)
        cfg = filter_schedule.settings()
        self.assertTrue(cfg["last_attempt"])
        self.assertEqual(cfg["last_success"], "")
        result = filter_schedule.last_result(cfg)
        self.assertEqual(result["status"], "failed")
        self.assertIn("resolution failed", result["error"])

    def test_recorded_result_never_stores_urls_or_credentials(self) -> None:
        message = "Private List: HTTP Error 401 for https://user:s3cret@lists.example.invalid/list.txt?token=abc"
        with mock.patch.object(compiler, "deploy", side_effect=RuntimeError(message)), self.quiet():
            with self.assertRaises(SystemExit):
                compiler.filter_update_run(argparse.Namespace())
        stored = filter_schedule.settings()["last_result"]
        for secret in ("https://", "s3cret", "token=abc", "lists.example.invalid"):
            self.assertNotIn(secret, stored)
        self.assertIn("[url removed]", stored)

    def test_result_summary_is_truncated(self) -> None:
        long_error = "x" * 5000
        self.assertLessEqual(len(filter_schedule.sanitize_message(long_error)), filter_schedule.MAX_RESULT_CHARS + 3)

    def test_delegates_to_the_locked_deploy_pipeline_with_download(self) -> None:
        with mock.patch.object(compiler, "deploy", return_value=1) as deployed, self.quiet():
            compiler.filter_update_run(argparse.Namespace())
        self.assertEqual(deployed.call_count, 1)
        self.assertEqual(deployed.call_args.args, ())
        self.assertEqual(deployed.call_args.kwargs, {"download": True, "trigger": "scheduled"})
        # The scheduled run must not reimplement or bypass deploy()'s
        # exclusive lock, source-enablement filter, or rollback handling.
        source = inspect.getsource(compiler.filter_update_run)
        self.assertIn("deploy(download=True, trigger=\"scheduled\")", source)
        # Compare against the executable body only, not the docstring that
        # explains why the lock lives in deploy().
        code = source.split('"""')[-1]
        for bypassed in ("collect_rules", "flock", "render_rpz", "reload_bind", "os.replace"):
            self.assertNotIn(bypassed, code)
        deploy_source = inspect.getsource(compiler.deploy)
        self.assertIn("fcntl.flock(lock_handle, fcntl.LOCK_EX)", deploy_source)
        self.assertIn("enabled_sources", inspect.getsource(compiler.collect_rules))

    def test_main_wires_both_subcommands(self) -> None:
        with mock.patch.object(filter_schedule, "deploy_filter_schedule", return_value="{}") as deployed, self.quiet():
            self.assertEqual(compiler.main(["filter-schedule-deploy"]), 0)
        self.assertEqual(deployed.call_count, 1)
        with mock.patch.object(compiler, "deploy", return_value=7) as deployed_filters, self.quiet():
            self.assertEqual(compiler.main(["filter-update-run"]), 0)
        self.assertEqual(deployed_filters.call_args.kwargs, {"download": True, "trigger": "scheduled"})


class DeploymentTriggerTest(FilterScheduleTestBase):
    """Exercises the real deploy() pipeline with only its external side
    effects (named-checkzone, rndc, dig, generated-config writers) stubbed."""

    def run_real_deploy(self, **kwargs) -> int:
        patches = [
            mock.patch.object(compiler, "validate_rpz", lambda path: None),
            mock.patch.object(compiler, "validate_bind", lambda: None),
            mock.patch.object(compiler, "reload_bind", lambda: None),
            mock.patch.object(compiler, "resolves", lambda domain: True),
            mock.patch.object(compiler, "is_blocked", lambda domain: True),
            mock.patch.object(local_dns, "deploy_zones", lambda conn=None: 0),
            mock.patch.object(dns_cache, "deploy_cache_options", lambda conn=None: 0),
            mock.patch.object(upstream_dns, "deploy_upstreams", lambda conn=None: 0),
            mock.patch.object(replication, "on_deploy_success", lambda conn=None: None),
        ]
        for patcher in patches:
            patcher.start()
        try:
            return compiler.deploy(**kwargs)
        finally:
            for patcher in reversed(patches):
                patcher.stop()

    def deployment(self, deployment_id: int) -> sqlite3.Row:
        with compiler.connect() as conn:
            return conn.execute("SELECT * FROM deployments WHERE id=?", (deployment_id,)).fetchone()

    def test_trigger_column_migration_is_idempotent(self) -> None:
        for _ in range(3):
            compiler.init_db()
        with compiler.connect() as conn:
            columns = [row["name"] for row in conn.execute("PRAGMA table_info(deployments)")]
        self.assertEqual(columns.count("trigger"), 1)

    def test_trigger_column_is_added_to_a_preexisting_database(self) -> None:
        legacy = self.tmp / "legacy.db"
        conn = sqlite3.connect(legacy)
        conn.execute(
            """
            CREATE TABLE deployments (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                active_domains INTEGER NOT NULL DEFAULT 0,
                blocked_test_domain TEXT,
                allowed_test_domain TEXT,
                message TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute("INSERT INTO deployments(started_at, status) VALUES ('2026-01-01T00:00:00+00:00', 'deployed')")
        conn.commit()
        conn.close()
        compiler.DB_PATH = legacy
        filter_schedule.DB_PATH = legacy
        compiler.init_db()
        with compiler.connect() as conn:
            row = conn.execute('SELECT "trigger" FROM deployments WHERE id=1').fetchone()
        self.assertIsNone(row["trigger"])

    def test_manual_deploy_leaves_trigger_null(self) -> None:
        deployment_id = self.run_real_deploy(download=False)
        row = self.deployment(deployment_id)
        self.assertEqual(row["status"], "deployed")
        self.assertIsNone(row["trigger"])

    def test_scheduled_run_marks_the_deployment_row(self) -> None:
        patches = [
            mock.patch.object(compiler, "validate_rpz", lambda path: None),
            mock.patch.object(compiler, "validate_bind", lambda: None),
            mock.patch.object(compiler, "reload_bind", lambda: None),
            mock.patch.object(compiler, "resolves", lambda domain: True),
            mock.patch.object(compiler, "is_blocked", lambda domain: True),
            mock.patch.object(local_dns, "deploy_zones", lambda conn=None: 0),
            mock.patch.object(dns_cache, "deploy_cache_options", lambda conn=None: 0),
            mock.patch.object(upstream_dns, "deploy_upstreams", lambda conn=None: 0),
            mock.patch.object(replication, "on_deploy_success", lambda conn=None: None),
        ]
        for patcher in patches:
            patcher.start()
        try:
            with self.quiet():
                compiler.filter_update_run(argparse.Namespace())
        finally:
            for patcher in reversed(patches):
                patcher.stop()
        with compiler.connect() as conn:
            row = conn.execute('SELECT status, "trigger" FROM deployments ORDER BY id DESC LIMIT 1').fetchone()
        self.assertEqual(row["trigger"], "scheduled")
        self.assertEqual(row["status"], "deployed")
        cfg = filter_schedule.settings()
        self.assertTrue(cfg["last_success"])
        self.assertEqual(filter_schedule.last_result(cfg)["status"], "deployed")


class LegacyArchiveRestoreTest(FilterScheduleTestBase):
    """The trigger-column migration must not break restoring a backup archive
    created before the column existed."""

    def setUp(self) -> None:
        super().setUp()
        from app import backup

        self.backup = backup
        self.old_backup_db = backup.DB_PATH
        backup.DB_PATH = compiler.DB_PATH

    def tearDown(self) -> None:
        self.backup.DB_PATH = self.old_backup_db
        super().tearDown()

    def test_premigration_archive_merges_into_a_migrated_database(self) -> None:
        staged = self.tmp / "archived.db"
        archive = sqlite3.connect(staged)
        archive.execute(
            """
            CREATE TABLE deployments (
                id INTEGER PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                active_domains INTEGER NOT NULL DEFAULT 0,
                blocked_test_domain TEXT,
                allowed_test_domain TEXT,
                message TEXT NOT NULL DEFAULT ''
            )
            """
        )
        archive.execute(
            "INSERT INTO deployments(id, started_at, status, active_domains) VALUES (5, '2026-01-01T00:00:00+00:00', 'deployed', 3)"
        )
        archive.commit()
        archive.close()

        merged = self.backup._merge_database(staged, {"sqlite_data": True}, target_db_path=self.backup.DB_PATH)
        self.assertIn("deployments", merged)
        with compiler.connect() as conn:
            row = conn.execute('SELECT active_domains, "trigger" FROM deployments WHERE id=5').fetchone()
        self.assertEqual(row["active_domains"], 3)
        self.assertIsNone(row["trigger"])


class WebRouteTest(FilterScheduleTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.request = SimpleNamespace(url=SimpleNamespace(path="/blocklists"), query_params={}, cookies={})
        self.rendered: list[tuple[str, dict]] = []
        self.commands: list[list[str]] = []
        self.csrf_patch = mock.patch.object(webapp, "check_csrf", lambda request, token: None)
        self.render_patch = mock.patch.object(webapp, "render", self.fake_render)
        self.csrf_patch.start()
        self.render_patch.start()

    def tearDown(self) -> None:
        self.render_patch.stop()
        self.csrf_patch.stop()
        super().tearDown()

    def fake_render(self, request, template, status_code: int = 200, **context):
        self.rendered.append((template, context))
        return SimpleNamespace(status_code=status_code, context=context)

    def fake_webapp_run(self, command: list[str]) -> tuple[int, str]:
        self.commands.append(list(command))
        return 0, "ok"

    def failing_webapp_run(self, command: list[str]) -> tuple[int, str]:
        self.commands.append(list(command))
        return 1, "systemctl enable failed"

    def test_save_applies_the_schedule_immediately(self) -> None:
        with mock.patch.object(webapp, "run", self.fake_webapp_run):
            response = webapp.blocklist_schedule(self.request, csrf="token", interval="72")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(
            self.commands,
            [["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "filter-schedule-deploy"]],
        )
        self.assertEqual(filter_schedule.settings()["interval_hours"], "72")

    def test_disabling_saves_and_applies(self) -> None:
        with mock.patch.object(webapp, "run", self.fake_webapp_run):
            webapp.blocklist_schedule(self.request, csrf="token", interval="disabled")
        self.assertEqual(filter_schedule.settings()["interval_hours"], "disabled")
        self.assertEqual(len(self.commands), 1)

    def test_helper_failure_is_surfaced_as_a_page_error(self) -> None:
        with mock.patch.object(webapp, "run", self.failing_webapp_run):
            response = webapp.blocklist_schedule(self.request, csrf="token", interval="12")
        self.assertEqual(response.status_code, 400)
        template, context = self.rendered[-1]
        self.assertEqual(template, "blocklists.html")
        self.assertIn("systemctl enable failed", context["category_error"])

    def test_invalid_interval_is_rejected_before_any_helper_runs(self) -> None:
        for candidate in ("1h; rm -rf /", "5", "OnCalendar=daily", "alderpointdns-filter-update.timer"):
            with self.subTest(candidate=candidate):
                self.commands = []
                with mock.patch.object(webapp, "run", self.fake_webapp_run):
                    response = webapp.blocklist_schedule(self.request, csrf="token", interval=candidate)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.commands, [])
                self.assertEqual(filter_schedule.settings()["interval_hours"], "24")

    def test_context_hides_next_run_when_disabled(self) -> None:
        filter_schedule.update_settings({"interval_hours": "disabled"})

        def unexpected() -> str | None:
            raise AssertionError("next_run_at must not be queried while disabled")

        with mock.patch.object(filter_schedule, "next_run_at", unexpected):
            context = webapp.filter_schedule_context()
        self.assertFalse(context["enabled"])
        self.assertIsNone(context["next_run"])
        self.assertEqual(context["interval_label"], "Disabled — No Updates")

    def test_context_reports_next_run_when_enabled(self) -> None:
        filter_schedule.update_settings({"interval_hours": "24"})
        with mock.patch.object(filter_schedule, "next_run_at", lambda: "Thu 2026-07-30 00:00:00 UTC"):
            context = webapp.filter_schedule_context()
        self.assertTrue(context["enabled"])
        self.assertEqual(context["next_run"], "Thu 2026-07-30 00:00:00 UTC")
        self.assertEqual(context["interval_label"], "1 Day")
        self.assertEqual(context["options"], EXPECTED_CHOICES)


class TemplateRenderTest(FilterScheduleTestBase):
    """Renders the real Blocklists template from this checkout with a mock
    page context, the same way the web smoke test does."""

    @classmethod
    def setUpClass(cls) -> None:
        from fastapi.templating import Jinja2Templates

        cls.templates = Jinja2Templates(directory=str(ROOT / "web" / "templates"))
        # base.html (extended by blocklists.html) calls static_url() --
        # a fresh Jinja2Templates instance built here (not through
        # webapp.render(), which registers this defensively) needs it too.
        cls.templates.env.globals["static_url"] = webapp.static_url

    def render(self, filter_schedule_context: dict | None, sources: list | None = None, automatic_update_banner: dict | None = None) -> str:
        request = SimpleNamespace(url=SimpleNamespace(path="/blocklists"), query_params={})
        context = {
            "request": request,
            "admin": "tester",
            "setup_required": False,
            "csrf": "token",
            "protection": {"label": "Active", "tone": "healthy"},
            "global_status": {"label": "Active", "tone": "healthy", "detail": "all core services active"},
            "sources": sources if sources is not None else [],
            "categories": [{"key": "uncategorized", "name": "Uncategorized", "description": "", "source_count": 0}],
            "category_error": None,
            "category_filter": "",
            "status_filter": "",
            "search": "",
            "sort": "name",
            "automatic_update_banner": automatic_update_banner,
        }
        if filter_schedule_context is not None:
            context["filter_schedule"] = filter_schedule_context
        return self.templates.get_template("blocklists.html").render(**context)

    def enabled_context(self) -> dict:
        filter_schedule.update_settings({"interval_hours": "12"})
        with mock.patch.object(filter_schedule, "next_run_at", lambda: "Thu 2026-07-30 00:00:00 UTC"):
            return webapp.filter_schedule_context()

    def disabled_context(self) -> dict:
        filter_schedule.update_settings({"interval_hours": "disabled"})
        return webapp.filter_schedule_context()

    def test_enabled_panel_shows_status_selection_and_next_run(self) -> None:
        html = self.render(self.enabled_context())
        for expected in (
            "Automatic Updates",
            "Filter Update Interval",
            'action="/blocklists/schedule"',
            'value="12" selected',
            "Last automatic attempt",
            "Last successful automatic update",
            "Next scheduled update",
            "Thu 2026-07-30 00:00:00 UTC",
            "Update All Now",
            "status-badge--healthy",
        ):
            self.assertIn(expected, html)
        self.assertNotIn("Automatic updates disabled", html)

    def test_every_label_is_offered_verbatim(self) -> None:
        html = self.render(self.enabled_context())
        for value, label in EXPECTED_CHOICES:
            self.assertIn(f'value="{value}"', html)
            self.assertIn(label, html)

    def test_disabled_panel_shows_no_next_run(self) -> None:
        html = self.render(self.disabled_context())
        self.assertIn("Automatic updates disabled", html)
        self.assertIn('value="disabled" selected', html)
        self.assertIn("Update All Now", html)
        self.assertNotIn("Next scheduled update</span>\n          <p class=\"mono", html)
        self.assertNotIn("Unknown until timer deploys", html)

    def test_page_renders_without_a_schedule_context(self) -> None:
        # Defensive: a render that predates this panel must never crash the
        # Blocklists page.
        html = self.render(None)
        self.assertIn("Automatic Updates", html)

    def test_last_automatic_result_error_is_shown_sanitized_and_still_current(self) -> None:
        # A degraded source (still in error) makes the historical automatic
        # failure genuinely current -- shown with the "bad"/alarming tone.
        degraded_source = {"enabled": True, "health": {"state": "error"}}
        banner = webapp.automatic_update_banner(
            [degraded_source],
            {"last_result": {"status": "rolled_back", "finished_at": "2026-07-30T00:00:00+00:00", "active_domains": 0, "error": "Private List: HTTP Error 401 for [url removed]"}},
        )
        html = self.render(self.enabled_context(), automatic_update_banner=banner)
        self.assertIn("Last automatic update on 2026-07-30T00:00:00+00:00 (rolled_back)", html)
        self.assertIn("[url removed]", html)
        self.assertIn("bad", html)

    def test_last_automatic_result_error_is_downgraded_once_resolved(self) -> None:
        # This is the exact real-appliance bug: an automatic run's failure
        # (e.g. a transient DNS resolution error) stayed on screen worded as
        # a current problem even after every source had since updated
        # successfully. Once nothing enabled is currently degraded, the
        # historical error must still be shown (never erased) but not
        # framed as ongoing.
        healthy_source = {"enabled": True, "health": {"state": "healthy"}}
        banner = webapp.automatic_update_banner(
            [healthy_source],
            {"last_result": {"status": "deployed", "finished_at": "2026-07-30T00:00:00+00:00", "active_domains": 100, "error": "Windows Spy Blocker: <urlopen error [Errno -5] No address associated with hostname>"}},
        )
        self.assertTrue(banner["resolved"])
        html = self.render(self.enabled_context(), automatic_update_banner=banner)
        self.assertIn("2026-07-30T00:00:00+00:00", html)
        self.assertIn("No address associated with hostname", html)
        self.assertIn("since updated successfully", html)
        self.assertNotIn('class="bad', html)

    def test_no_banner_when_nothing_has_ever_failed(self) -> None:
        html = self.render(self.enabled_context(), automatic_update_banner=None)
        self.assertNotIn("Last automatic update on", html)

    def test_source_warning_reason_is_visible_without_hovering(self) -> None:
        # The reason must be an actual visible text node in the row, not
        # only a title= tooltip attribute -- touch devices have no hover.
        source = {
            "id": 1,
            "name": "Windows Spy Blocker",
            "url": "https://raw.githubusercontent.com/example/list.txt",
            "category": "ads_trackers",
            "enabled": True,
            "using_cached_copy": False,
            "last_error": "urlopen error [Errno -5] No address associated with hostname",
            "last_warning": "",
            "last_success": "",
            "last_attempt": "2026-08-08T12:00:00+00:00",
            "last_compile_success": "",
            "parsed_rules": 0,
            "duplicate_domains": 0,
            "invalid_rules": 0,
            "unsupported_rules": 0,
            "unique_active_domains": 0,
            "downloaded_entries": 0,
            "rejected_samples_parsed": [],
            "health": {"state": "error", "label": "Error", "tone": "down"},
        }
        html = self.render(self.enabled_context(), sources=[source])
        # Strip the title="..." tooltip attribute before searching, so the
        # assertion can only pass on the visible text, never the tooltip.
        visible = re.sub(r'title="[^"]*"', "", html)
        self.assertIn("No address associated with hostname", visible)
        self.assertIn("2026-08-08T12:00:00+00:00", visible)

    def test_manual_update_routes_are_not_gated_by_the_schedule(self) -> None:
        html = self.render(self.disabled_context())
        self.assertIn('action="/blocklists/update"', html)
        self.assertIn("Sources", html)


class PackagingTest(unittest.TestCase):
    def test_service_unit(self) -> None:
        text = (ROOT / "packaging" / "alderpointdns-filter-update.service").read_text()
        self.assertIn("Type=oneshot", text)
        self.assertIn("ExecStart=/opt/alderpointdns/app/alderpointdns_compiler.py filter-update-run", text)
        self.assertIn("After=alderpointdns.service", text)

    def test_timer_unit(self) -> None:
        text = (ROOT / "packaging" / "alderpointdns-filter-update.timer").read_text()
        self.assertIn("OnBootSec=24h", text)
        self.assertIn("OnUnitActiveSec=24h", text)
        self.assertIn("Persistent=true", text)
        self.assertIn("WantedBy=timers.target", text)
        self.assertIn("/etc/systemd/system/alderpointdns-filter-update.timer.d/alderpointdns.conf", text)

    def test_sudoers_has_exact_literal_entries_without_wildcards(self) -> None:
        text = (ROOT / "packaging" / "sudoers-alderpointdns").read_text()
        for entry in (
            "/opt/alderpointdns/app/alderpointdns_compiler.py filter-schedule-deploy",
            "/opt/alderpointdns/app/alderpointdns_compiler.py filter-update-run",
        ):
            self.assertIn(entry, text)
        self.assertNotIn("filter-schedule-deploy *", text)
        self.assertNotIn("filter-update-run *", text)

    def test_installer_and_upgrade_install_the_units(self) -> None:
        install_sh = (ROOT / "scripts" / "install.sh").read_text()
        upgrade_sh = (ROOT / "scripts" / "upgrade.sh").read_text()
        for text in (install_sh, upgrade_sh):
            self.assertIn("packaging/alderpointdns-filter-update.service", text)
            self.assertIn("packaging/alderpointdns-filter-update.timer", text)
            self.assertIn("filter-schedule-deploy", text)

    def test_debian_packaging_covers_the_timer_lifecycle(self) -> None:
        debian = ROOT / "packaging" / "debian"
        install = (debian / "install").read_text()
        self.assertIn("packaging/alderpointdns-filter-update.service lib/systemd/system/", install)
        self.assertIn("packaging/alderpointdns-filter-update.timer lib/systemd/system/", install)
        self.assertIn("filter-schedule-deploy", (debian / "postinst").read_text())
        self.assertIn("alderpointdns-filter-update.timer", (debian / "prerm").read_text())
        self.assertIn("alderpointdns-filter-update.timer.d", (debian / "postrm").read_text())

    def test_documentation_describes_the_setting(self) -> None:
        configuration = (ROOT / "docs" / "configuration.md").read_text()
        self.assertIn("Filter Update Interval", configuration)
        for _value, label in EXPECTED_CHOICES:
            self.assertIn(label, configuration)
        self.assertIn("alderpointdns-filter-update.timer", configuration)
        self.assertIn("/blocklists/schedule", (ROOT / "docs" / "web.md").read_text())
        self.assertIn("alderpointdns-filter-update.timer", (ROOT / "docs" / "packaging.md").read_text())


if __name__ == "__main__":
    unittest.main()
