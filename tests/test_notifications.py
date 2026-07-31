#!/usr/bin/env python3
from __future__ import annotations

import re
import sqlite3
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import alderpointdns_compiler, analytics, auth, backup, local_dns, notifications, notify_check, replication, upstream_dns, webapp  # noqa: E402

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')


class FakeHTTPResponse:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHTTPClient:
    """Records every POST instead of making a real network call."""

    calls: list[dict] = []

    def __init__(self, timeout: int = 10) -> None:
        pass

    def __enter__(self) -> "FakeHTTPClient":
        return self

    def __exit__(self, *args) -> None:
        return None

    def post(self, url, json=None, headers=None, content=None, data=None):
        FakeHTTPClient.calls.append({"url": url, "json": json, "headers": headers, "content": content, "data": data})
        return FakeHTTPResponse(200)


class FakeSMTP:
    sent: list[dict] = []
    login_calls: list[tuple] = []

    def __init__(self, host, port, timeout=10) -> None:
        self.host, self.port = host, port

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, *args) -> None:
        return None

    def starttls(self) -> None:
        pass

    def login(self, username, password) -> None:
        FakeSMTP.login_calls.append((username, password))

    def send_message(self, msg, to_addrs=None) -> None:
        FakeSMTP.sent.append({"msg": msg, "to_addrs": to_addrs})


class NotificationsCoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-notifications-test-"))
        self.old_db_path = notifications.DB_PATH
        notifications.DB_PATH = self.tmp / "alderpointdns.db"
        notifications.init_db()
        FakeHTTPClient.calls = []
        FakeSMTP.sent = []
        FakeSMTP.login_calls = []

    def tearDown(self) -> None:
        notifications.DB_PATH = self.old_db_path
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- provider validation --------------------------------------------

    def test_smtp_provider_requires_host_and_addresses(self) -> None:
        with self.assertRaises(notifications.NotificationError):
            notifications.add_provider("smtp", "Broken", {"from_addr": "a@example.com", "to_addrs": "b@example.com"}, "")
        with self.assertRaises(notifications.NotificationError):
            notifications.add_provider("smtp", "Broken", {"host": "smtp.example.com"}, "")

    def test_smtp_provider_rejects_bad_port(self) -> None:
        with self.assertRaises(notifications.NotificationError):
            notifications.add_provider("smtp", "Broken", {"host": "smtp.example.com", "port": 99999, "from_addr": "a@example.com", "to_addrs": "b@example.com"}, "")

    def test_webhook_provider_requires_url_secret(self) -> None:
        with self.assertRaises(notifications.NotificationError):
            notifications.add_provider("webhook", "Broken", {"preset": "generic"}, "")

    def test_webhook_provider_rejects_unknown_preset(self) -> None:
        with self.assertRaises(notifications.NotificationError):
            notifications.add_provider("webhook", "Broken", {"preset": "not-a-real-service"}, "https://example.invalid/hook")

    def test_unknown_provider_kind_rejected(self) -> None:
        with self.assertRaises(notifications.NotificationError):
            notifications.add_provider("carrier-pigeon", "Broken", {}, "secret")

    # -- secret masking ----------------------------------------------------

    def test_secret_never_appears_in_public_provider_listing(self) -> None:
        secret = "https://discord.example/webhooks/unmistakable-secret-token"
        notifications.add_provider("webhook", "Discord", {"preset": "discord"}, secret)
        providers = notifications.list_providers()
        self.assertEqual(len(providers), 1)
        self.assertNotIn("secret", providers[0])
        self.assertTrue(providers[0]["has_secret"])
        self.assertNotIn(secret, str(providers[0]))

    def test_updating_provider_without_secret_preserves_existing_secret(self) -> None:
        secret = "https://discord.example/webhooks/original-secret"
        pid = notifications.add_provider("webhook", "Discord", {"preset": "discord"}, secret)
        notifications.update_provider(pid, name="Discord (renamed)", config={"preset": "discord"})
        row = notifications.get_provider_row(pid)
        self.assertEqual(row["secret"], secret)
        self.assertEqual(row["name"], "Discord (renamed)")

    # -- delivery: mocked SMTP and webhook ----------------------------------

    def test_smtp_test_notification_uses_mocked_smtp_and_reports_success(self) -> None:
        pid = notifications.add_provider(
            "smtp", "Ops Email",
            {"host": "smtp.example.com", "port": 587, "use_tls": True, "from_addr": "alerts@example.com", "to_addrs": "oncall@example.com", "username": "alerts"},
            "smtp-password-value",
        )
        with mock.patch.object(notifications.smtplib, "SMTP", FakeSMTP):
            ok, error = notifications.send_test(pid)
        self.assertTrue(ok, error)
        self.assertEqual(len(FakeSMTP.sent), 1)
        self.assertEqual(FakeSMTP.login_calls, [("alerts", "smtp-password-value")])
        history = notifications.history()
        self.assertEqual(history[0]["status"], "sent")

    def test_webhook_test_notification_uses_mocked_http_and_reports_success(self) -> None:
        pid = notifications.add_provider("webhook", "Generic Hook", {"preset": "generic"}, "https://example.invalid/hook")
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            ok, error = notifications.send_test(pid)
        self.assertTrue(ok, error)
        self.assertEqual(len(FakeHTTPClient.calls), 1)
        self.assertEqual(FakeHTTPClient.calls[0]["url"], "https://example.invalid/hook")
        self.assertEqual(FakeHTTPClient.calls[0]["json"]["event_category"], "test")

    def test_failed_delivery_recorded_and_provider_failure_state_set(self) -> None:
        pid = notifications.add_provider("webhook", "Generic Hook", {"preset": "generic"}, "https://example.invalid/hook")

        def _raise(*args, **kwargs):
            raise RuntimeError("connection refused")

        with mock.patch.object(notifications.httpx, "Client", side_effect=_raise):
            ok, error = notifications.send_test(pid)
        self.assertFalse(ok)
        self.assertIn("connection refused", error)
        provider = notifications.get_provider_row(pid)
        self.assertIsNotNone(provider["last_failure_at"])
        self.assertIn("connection refused", provider["last_failure_error"])
        notifications.clear_provider_failure(pid)
        provider2 = notifications.get_provider_row(pid)
        self.assertIsNone(provider2["last_failure_at"])
        self.assertEqual(provider2["last_failure_error"], "")

    def test_discord_preset_formats_content_payload(self) -> None:
        pid = notifications.add_provider("webhook", "Discord", {"preset": "discord"}, "https://discord.example/hook")
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notifications.send_test(pid)
        self.assertIn("content", FakeHTTPClient.calls[-1]["json"])

    def test_ntfy_preset_sends_plain_text_body_with_headers(self) -> None:
        pid = notifications.add_provider("webhook", "ntfy", {"preset": "ntfy"}, "https://ntfy.example/mytopic")
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notifications.send_test(pid)
        call = FakeHTTPClient.calls[-1]
        self.assertIsNone(call["json"])
        self.assertIsNotNone(call["content"])
        self.assertIn("Title", call["headers"])

    def test_pushover_preset_sends_form_with_token_and_user_from_secret(self) -> None:
        pid = notifications.add_provider("webhook", "Pushover", {"preset": "pushover"}, "myuserkey:myapptoken")
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notifications.send_test(pid)
        call = FakeHTTPClient.calls[-1]
        self.assertEqual(call["url"], "https://api.pushover.net/1/messages.json")
        self.assertEqual(call["data"]["token"], "myapptoken")
        self.assertEqual(call["data"]["user"], "myuserkey")

    # -- dispatch: subscriptions, severity threshold, cooldown, dedup, recovery, history --

    def test_dispatch_respects_minimum_severity_threshold(self) -> None:
        pid = notifications.add_provider("webhook", "Hook", {"preset": "generic"}, "https://example.invalid/hook")
        notifications.set_subscription(pid, "backup_failure", "critical", True)
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            results = notifications.dispatch("backup_failure", "warning", "Backup", "backup failed")
        self.assertEqual(results, [])
        self.assertEqual(FakeHTTPClient.calls, [])

    def test_dispatch_cooldown_suppresses_duplicate_then_recovery_bypasses_it(self) -> None:
        pid = notifications.add_provider("webhook", "Hook", {"preset": "generic"}, "https://example.invalid/hook")
        notifications.set_subscription(pid, "backup_failure", "warning", True)
        notifications.update_settings({"cooldown_minutes": 30})
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            r1 = notifications.dispatch("backup_failure", "warning", "Backup", "backup failed")
            r2 = notifications.dispatch("backup_failure", "warning", "Backup", "backup failed again")
            r3 = notifications.dispatch("backup_failure", "warning", "Backup", "backup recovered", recovered=True)
        self.assertEqual(r1[0]["status"], "sent")
        self.assertEqual(r2[0]["status"], "suppressed")
        self.assertEqual(r3[0]["status"], "sent")
        self.assertEqual(len(FakeHTTPClient.calls), 2)
        statuses = [row["status"] for row in notifications.history()]
        self.assertEqual(statuses.count("sent"), 2)
        self.assertEqual(statuses.count("suppressed"), 1)

    def test_dispatch_dedup_is_per_component_not_global(self) -> None:
        pid = notifications.add_provider("webhook", "Hook", {"preset": "generic"}, "https://example.invalid/hook")
        notifications.set_subscription(pid, "service_unavailable", "warning", True)
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            r1 = notifications.dispatch("service_unavailable", "critical", "named", "named is down")
            r2 = notifications.dispatch("service_unavailable", "critical", "dnsdist", "dnsdist is down")
        self.assertEqual(r1[0]["status"], "sent")
        self.assertEqual(r2[0]["status"], "sent")
        self.assertEqual(len(FakeHTTPClient.calls), 2)

    def test_disabled_provider_or_subscription_never_dispatches(self) -> None:
        pid = notifications.add_provider("webhook", "Hook", {"preset": "generic"}, "https://example.invalid/hook", enabled=False)
        notifications.set_subscription(pid, "backup_failure", "warning", True)
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            results = notifications.dispatch("backup_failure", "warning", "Backup", "backup failed")
        self.assertEqual(results, [])
        self.assertEqual(FakeHTTPClient.calls, [])

    def test_dispatch_never_includes_raw_secret_in_message_payload(self) -> None:
        secret = "https://discord.example/webhooks/unmistakable-secret-token"
        pid = notifications.add_provider("webhook", "Discord", {"preset": "discord"}, secret)
        notifications.set_subscription(pid, "backup_failure", "warning", True)
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notifications.dispatch("backup_failure", "warning", "Backup", "backup failed")
        self.assertNotIn(secret, str(FakeHTTPClient.calls[-1]["json"]))


class NotifyCheckTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-notify-check-test-"))
        self.old_paths = {mod: mod.DB_PATH for mod in (notifications, alderpointdns_compiler, backup, replication, upstream_dns, analytics)}
        db_path = self.tmp / "alderpointdns.db"
        for mod in self.old_paths:
            mod.DB_PATH = db_path
        notifications.init_db()
        self.provider_id = notifications.add_provider("webhook", "Hook", {"preset": "generic"}, "https://example.invalid/hook")
        for category in notifications.EVENT_CATEGORIES:
            notifications.set_subscription(self.provider_id, category, "info", True)
        FakeHTTPClient.calls = []

    def tearDown(self) -> None:
        for mod, path in self.old_paths.items():
            mod.DB_PATH = path
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_service_down_and_recovered_fires_once_each(self) -> None:
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            with mock.patch.object(notify_check, "_systemctl", return_value=(1, "inactive")):
                notify_check.check_service_availability()
                notify_check.check_service_availability()  # still down: must not re-fire
            self.assertEqual(len(FakeHTTPClient.calls), len(notify_check.SERVICE_UNITS))
            with mock.patch.object(notify_check, "_systemctl", return_value=(0, "active")):
                notify_check.check_service_availability()
        recovered_calls = [c for c in FakeHTTPClient.calls if c["json"]["recovered"]]
        self.assertEqual(len(recovered_calls), len(notify_check.SERVICE_UNITS))

    def test_analytics_writer_active_but_stale_heartbeat_fires_and_recovers(self) -> None:
        old_heartbeat = analytics.HEARTBEAT_FILE
        analytics.HEARTBEAT_FILE = self.tmp / "analytics-writer-heartbeat.json"
        try:
            with mock.patch.object(notify_check, "_systemctl", return_value=(0, "active")):
                with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
                    # No heartbeat yet (fresh install/upgrade): must not fire.
                    notify_check.check_analytics_writer()
                    self.assertEqual(FakeHTTPClient.calls, [])

                    analytics._write_heartbeat("dead", "writer thread terminated")
                    notify_check.check_analytics_writer()
                    self.assertTrue(any(
                        c["json"]["event_category"] == "service_unavailable" and not c["json"]["recovered"]
                        for c in FakeHTTPClient.calls
                    ))

                    FakeHTTPClient.calls = []
                    analytics._write_heartbeat("ok")
                    notify_check.check_analytics_writer()
                    self.assertTrue(any(
                        c["json"]["event_category"] == "service_unavailable" and c["json"]["recovered"]
                        for c in FakeHTTPClient.calls
                    ))
        finally:
            analytics.HEARTBEAT_FILE = old_heartbeat

    def test_analytics_writer_service_down_is_left_to_service_availability_check(self) -> None:
        old_heartbeat = analytics.HEARTBEAT_FILE
        analytics.HEARTBEAT_FILE = self.tmp / "analytics-writer-heartbeat.json"
        try:
            analytics._write_heartbeat("dead", "writer thread terminated")
            with mock.patch.object(notify_check, "_systemctl", return_value=(1, "inactive")):
                with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
                    notify_check.check_analytics_writer()
            self.assertEqual(FakeHTTPClient.calls, [])
        finally:
            analytics.HEARTBEAT_FILE = old_heartbeat

    def test_deploy_failure_detected_from_deployments_table(self) -> None:
        alderpointdns_compiler.init_db()
        with alderpointdns_compiler.connect() as conn:
            conn.execute(
                "INSERT INTO deployments(started_at, finished_at, status, active_domains, message) VALUES ('now', 'now', 'rolled_back', 0, 'post-deploy check failed')"
            )
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_deploy_and_blocklist()
        self.assertTrue(any(c["json"]["event_category"] == "deploy_failure" and not c["json"]["recovered"] for c in FakeHTTPClient.calls))

    def test_backup_failure_detected_from_backup_history_table(self) -> None:
        with backup.connect() as conn:
            backup.init_db(conn)
            with conn:
                conn.execute(
                    "INSERT INTO backup_history(created_at, path, size_bytes, components_json, manifest_json, status, message) VALUES ('now', NULL, 0, '{}', '{}', 'failed', 'disk full')"
                )
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_backup()
        self.assertTrue(any(c["json"]["event_category"] == "backup_failure" for c in FakeHTTPClient.calls))

    def test_backup_with_no_history_never_fires(self) -> None:
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_backup()
        self.assertEqual(FakeHTTPClient.calls, [])

    def test_blocklist_source_hard_failure_identifies_source_and_reason(self) -> None:
        alderpointdns_compiler.init_db()
        with alderpointdns_compiler.connect() as conn:
            conn.execute(
                """
                INSERT INTO sources(name, url, enabled, category, last_success, last_error, using_cached_copy)
                VALUES ('Windows Spy Blocker', 'https://example.invalid/spy.txt', 1, 'ads_trackers', NULL, 'Temporary DNS resolution failure', 0)
                """
            )
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_blocklist_sources()
        calls = [c for c in FakeHTTPClient.calls if c["json"]["event_category"] == "blocklist_update_failure"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["json"]["component"], "Windows Spy Blocker")
        self.assertIn("Temporary DNS resolution failure", calls[0]["json"]["summary"])
        self.assertFalse(calls[0]["json"]["recovered"])

    def test_blocklist_source_using_cached_copy_reports_cached_note(self) -> None:
        alderpointdns_compiler.init_db()
        with alderpointdns_compiler.connect() as conn:
            conn.execute(
                """
                INSERT INTO sources(name, url, enabled, category, last_success, last_error, using_cached_copy, parsed_rules, unique_active_domains)
                VALUES ('Windows Spy Blocker', 'https://example.invalid/spy.txt', 1, 'ads_trackers', 'now', 'Temporary DNS resolution failure', 1, 347, 347)
                """
            )
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_blocklist_sources()
        calls = [c for c in FakeHTTPClient.calls if c["json"]["event_category"] == "blocklist_update_failure"]
        self.assertEqual(len(calls), 1)
        self.assertIn("Previous compiled copy remains active", calls[0]["json"]["summary"])

    def test_blocklist_source_unsupported_format_fires_warning(self) -> None:
        alderpointdns_compiler.init_db()
        with alderpointdns_compiler.connect() as conn:
            conn.execute(
                """
                INSERT INTO sources(
                    name, url, enabled, category, last_success, last_error,
                    downloaded_entries, parsed_rules, unsupported_rules)
                VALUES ('AdGuard DNS Popup Hosts filter', 'https://example.invalid/popup.txt', 1, 'ads_trackers', 'now', NULL, 1083, 0, 1083)
                """
            )
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_blocklist_sources()
        calls = [c for c in FakeHTTPClient.calls if c["json"]["event_category"] == "blocklist_update_failure"]
        self.assertEqual(len(calls), 1)
        self.assertFalse(calls[0]["json"]["recovered"])

    def test_blocklist_source_healthy_never_fires(self) -> None:
        alderpointdns_compiler.init_db()
        with alderpointdns_compiler.connect() as conn:
            conn.execute(
                """
                INSERT INTO sources(name, url, enabled, category, last_success, parsed_rules, unique_active_domains)
                VALUES ('AdGuard DNS filter', 'https://example.invalid/filter.txt', 1, 'ads_trackers', 'now', 100, 100)
                """
            )
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_blocklist_sources()
        self.assertEqual(FakeHTTPClient.calls, [])

    def test_blocklist_source_recovered_fires_once(self) -> None:
        alderpointdns_compiler.init_db()
        with alderpointdns_compiler.connect() as conn:
            source_id = conn.execute(
                """
                INSERT INTO sources(name, url, enabled, category, last_success, last_error)
                VALUES ('Windows Spy Blocker', 'https://example.invalid/spy.txt', 1, 'ads_trackers', NULL, 'Connection refused')
                """
            ).lastrowid
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_blocklist_sources()
            with alderpointdns_compiler.connect() as conn:
                conn.execute(
                    "UPDATE sources SET last_success='now', last_error=NULL, parsed_rules=1, unique_active_domains=1 WHERE id=?",
                    (source_id,),
                )
            notify_check.check_blocklist_sources()
        recovered = [c for c in FakeHTTPClient.calls if c["json"]["event_category"] == "blocklist_update_failure" and c["json"]["recovered"]]
        self.assertEqual(len(recovered), 1)

    def test_resolver_degraded_and_all_unavailable(self) -> None:
        upstream_dns.init_db()
        r1 = upstream_dns.add_resolver({"name": "R1", "protocol": "plain", "address": "1.1.1.1", "port": 53, "enabled": True})
        r2 = upstream_dns.add_resolver({"name": "R2", "protocol": "plain", "address": "8.8.8.8", "port": 53, "enabled": True})
        analytics.init_analytics_db()
        with alderpointdns_compiler.connect() as conn:
            for resolver_id, state in ((r1, "down"), (r2, "up")):
                conn.execute(
                    """
                    INSERT INTO upstream_resolver_aggregate_buckets(
                        bucket_start, resolver_id, resolver_name, protocol, endpoint, enabled, health_state,
                        queries_attempted, successful_responses, failures, timeouts, latency_sum_ms, latency_count,
                        recent_latency_ms, last_success_at, last_failure_at, updated_at
                    ) VALUES (0, ?, 'r', 'plain', 'e', 1, ?, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, 'now')
                    """,
                    (resolver_id, state),
                )
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_upstream_resolvers()
        degraded = [c for c in FakeHTTPClient.calls if c["json"]["event_category"] == "resolver_degraded"]
        all_down = [c for c in FakeHTTPClient.calls if c["json"]["event_category"] == "resolver_all_unavailable"]
        self.assertTrue(degraded)
        self.assertFalse(all_down)

    def test_replication_delayed_only_evaluated_for_replica_role(self) -> None:
        replication.init_db()
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_replication()
        self.assertEqual(FakeHTTPClient.calls, [], "standalone role must never fire replication alerts")

        replication.update_settings({"role": "replica", "last_sync_status": "error", "drift_detected": "0"})
        with mock.patch.object(notifications.httpx, "Client", FakeHTTPClient):
            notify_check.check_replication()
        self.assertTrue(any(c["json"]["event_category"] == "replication_delayed" for c in FakeHTTPClient.calls))


class NotificationsWebRouteTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-notifications-web-test-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "local_dns_db": local_dns.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "notifications_db": notifications.DB_PATH,
        }
        db_path = self.tmp / "alderpointdns.db"
        webapp.DB_PATH = db_path
        local_dns.DB_PATH = db_path
        alderpointdns_compiler.DB_PATH = db_path
        notifications.DB_PATH = db_path
        local_dns.STAGING_DIR = self.tmp / "staging"
        local_dns.BACKUP_DIR = self.tmp / "backups"
        local_dns.COMPILED_DIR = self.tmp / "compiled" / "bind"
        local_dns.LOCAL_ZONE_DIR = local_dns.COMPILED_DIR / "local"
        local_dns.LOCAL_ZONES_CONF = local_dns.COMPILED_DIR / "local-zones.conf"
        local_dns.NAMED_LOCAL_CONF = self.tmp / "named.conf.local"
        local_dns.STAGING_DIR.mkdir(parents=True)
        local_dns.NAMED_LOCAL_CONF.write_text(
            'acl "alderpointdns_clients" { localhost; };\nzone "alderpointdns.rpz" { type primary; file "alderpointdns.rpz"; };\n'
        )
        self.patches = [mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"})]
        for patcher in self.patches:
            patcher.start()

        from fastapi.testclient import TestClient

        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)", ("admin", auth.hash_password("initial-password-123"), "now"))
        conn.commit()
        conn.close()
        self.client = TestClient(webapp.app)
        self.client.post("/login", data={"username": "admin", "password": "initial-password-123"})

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        webapp.DB_PATH = self.old_paths["webapp_db"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        notifications.DB_PATH = self.old_paths["notifications_db"]
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _csrf(self) -> str:
        page = self.client.get("/system/notifications")
        match = CSRF_RE.search(page.text)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_add_webhook_provider_via_http_and_secret_never_rendered(self) -> None:
        secret = "https://discord.example/webhooks/route-test-secret"
        r = self.client.post(
            "/system/notifications/providers/webhook",
            data={"csrf": self._csrf(), "name": "Discord", "webhook_preset": "discord", "secret": secret},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        page = self.client.get("/system/notifications")
        self.assertIn("Discord", page.text)
        self.assertNotIn(secret, page.text)

    def test_add_provider_without_csrf_rejected(self) -> None:
        r = self.client.post(
            "/system/notifications/providers/webhook",
            data={"csrf": "forged", "name": "Discord", "webhook_preset": "discord", "secret": "https://discord.example/hook"},
        )
        self.assertEqual(r.status_code, 403)

    def test_test_notification_route_uses_mocked_send(self) -> None:
        self.client.post(
            "/system/notifications/providers/webhook",
            data={"csrf": self._csrf(), "name": "Hook", "webhook_preset": "generic", "secret": "https://example.invalid/hook"},
        )
        provider_id = sqlite3.connect(webapp.DB_PATH).execute("SELECT id FROM notification_providers").fetchone()[0]
        with mock.patch.object(notifications, "send_provider", lambda provider, message: (True, "")):
            r = self.client.post(f"/system/notifications/providers/{provider_id}/test", data={"csrf": self._csrf()}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)

    def test_subscription_add_and_remove(self) -> None:
        self.client.post(
            "/system/notifications/providers/webhook",
            data={"csrf": self._csrf(), "name": "Hook", "webhook_preset": "generic", "secret": "https://example.invalid/hook"},
        )
        provider_id = sqlite3.connect(webapp.DB_PATH).execute("SELECT id FROM notification_providers").fetchone()[0]
        r = self.client.post(
            "/system/notifications/subscriptions",
            data={"csrf": self._csrf(), "provider_id": provider_id, "event_category": "backup_failure", "min_severity": "warning", "enabled": "1"},
            follow_redirects=False,
        )
        self.assertEqual(r.status_code, 303)
        subs = notifications.list_subscriptions()
        self.assertEqual(len(subs), 1)
        r2 = self.client.post(f"/system/notifications/subscriptions/{subs[0]['id']}/delete", data={"csrf": self._csrf()}, follow_redirects=False)
        self.assertEqual(r2.status_code, 303)
        self.assertEqual(notifications.list_subscriptions(), [])


if __name__ == "__main__":
    unittest.main()
