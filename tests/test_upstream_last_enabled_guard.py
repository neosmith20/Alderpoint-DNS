#!/usr/bin/env python3
"""Regression coverage for the v1.0.1 RC #3 blocker found during live
packaged-appliance acceptance on dns1: disabling the last enabled upstream
resolver through the UI returned "At least one upstream resolver must be
enabled." as expected, but `upstream_dns.set_enabled(resolver_id, False)`
had already *committed* the all-disabled desired state before
`deploy_upstreams()` ever ran and rejected it. deploy_upstreams()'s own
check only ever protected the *runtime* dnsdist/BIND config (it always
refused to promote an empty upstream set), but by the time it fired, the
DB already disagreed with that protected runtime state -- and nothing ever
put it back. That left the appliance with `enabled=1` nowhere in
upstream_resolvers, a desired state that:

  - no future deploy of *any* kind (scoped or full) could ever succeed
    from without an admin first re-enabling a resolver directly, and
  - was untruthful to the UI/admin, since the on-disk dnsdist config (and
    therefore live DNS resolution) still reflected whatever was enabled
    *before* the rejected click, not what the database now claimed.

The fix (app/upstream_dns.py: `_would_leave_zero_enabled`, wired into
set_enabled/delete_resolver/update_resolver) makes each of those three
entry points check, in the same transaction and before the mutating
statement runs, whether the change they are about to commit would leave
zero enabled resolvers -- and refuses to commit if so. This closes the gap
deploy_upstreams()'s post-hoc check could never close on its own.
"""

from __future__ import annotations

import re
import shutil
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

from fastapi.testclient import TestClient  # noqa: E402

from app import alderpointdns_compiler, auth, upstream_dns, webapp  # noqa: E402

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')
INITIAL_PASSWORD = "initial-password-123"


class LastEnabledGuardUnitTest(unittest.TestCase):
    """Exercises upstream_dns's mutating functions directly -- no HTTP, no
    subprocess -- to pin the exact commit-time invariant."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-last-enabled-test-"))
        self.old = {
            "DB_PATH": upstream_dns.DB_PATH,
            "COMPILED_DIR": upstream_dns.COMPILED_DIR,
            "BIND_FORWARDERS_CONF": upstream_dns.BIND_FORWARDERS_CONF,
            "DNSDIST_UPSTREAM_CONF": upstream_dns.DNSDIST_UPSTREAM_CONF,
            "NAMED_OPTIONS_CONF": upstream_dns.NAMED_OPTIONS_CONF,
            "DNSDIST_CONF": upstream_dns.DNSDIST_CONF,
            "DNSDIST_PACKAGING_CONF": upstream_dns.DNSDIST_PACKAGING_CONF,
            "BACKUP_DIR": upstream_dns.BACKUP_DIR,
            "STAGING_DIR": upstream_dns.STAGING_DIR,
        }
        upstream_dns.DB_PATH = self.tmp / "alderpointdns.db"
        upstream_dns.COMPILED_DIR = self.tmp / "compiled"
        upstream_dns.BIND_FORWARDERS_CONF = self.tmp / "compiled" / "bind" / "upstream-forwarders.conf"
        upstream_dns.DNSDIST_UPSTREAM_CONF = self.tmp / "compiled" / "dnsdist" / "upstream-forwarder.conf"
        upstream_dns.NAMED_OPTIONS_CONF = self.tmp / "named.conf.options"
        upstream_dns.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        upstream_dns.DNSDIST_PACKAGING_CONF = self.tmp / "packaging-dnsdist.conf"
        upstream_dns.BACKUP_DIR = self.tmp / "backups"
        upstream_dns.STAGING_DIR = self.tmp / "staging"
        upstream_dns.STAGING_DIR.mkdir(parents=True)
        upstream_dns.NAMED_OPTIONS_CONF.write_text('options {\n\tforward only;\n\tforwarders { 9.9.9.9; };\n};\n')
        upstream_dns.DNSDIST_CONF.write_text(
            'newServer({\n  address="127.0.0.1:5354",\n  name="bind-proxy"\n})\n'
            'pc = newPacketCache(100)\n'
            'getPool(""):setCache(pc)\n'
            'addAction(OrRule({\n  QTypeRule(DNSQType.AXFR)\n}), RCodeAction(DNSRCode.REFUSED))\n'
        )
        upstream_dns.DNSDIST_PACKAGING_CONF.write_text(upstream_dns.DNSDIST_CONF.read_text())
        upstream_dns.init_db()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(upstream_dns, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rows(self) -> dict[str, dict]:
        return {row["name"]: row for row in upstream_dns.resolvers()}

    def test_disabling_the_only_enabled_resolver_is_rejected_before_commit(self) -> None:
        rows = upstream_dns.resolvers()
        self.assertEqual(len(rows), 1, "seeded fixture should be a single resolver")
        only_id = rows[0]["id"]
        with self.assertRaises(upstream_dns.UpstreamDNSError) as ctx:
            upstream_dns.set_enabled(only_id, False)
        self.assertEqual(str(ctx.exception), "At least one upstream resolver must be enabled.")
        # DB must still show it enabled -- the mutation must never have committed.
        self.assertTrue(upstream_dns.resolvers()[0]["enabled"])

    def test_disabling_the_last_of_several_is_rejected_others_stay_untouched(self) -> None:
        upstream_dns.add_resolver({"name": "Quad9", "protocol": "plain", "address": "9.9.9.9", "enabled": "1"})
        first_id = upstream_dns.resolvers()[0]["id"]
        second_id = upstream_dns.resolvers()[1]["id"]

        # Disabling the first one is fine -- one resolver remains enabled.
        upstream_dns.set_enabled(first_id, False)
        rows_by_id = {row["id"]: row for row in upstream_dns.resolvers()}
        self.assertFalse(rows_by_id[first_id]["enabled"])

        # Disabling the last remaining enabled resolver must be rejected.
        with self.assertRaises(upstream_dns.UpstreamDNSError):
            upstream_dns.set_enabled(second_id, False)
        rows = self._rows()
        self.assertTrue(rows["Quad9"]["enabled"], "the last enabled resolver must remain enabled after a rejected disable")

    def test_deleting_the_last_enabled_resolver_is_rejected_before_commit(self) -> None:
        only_id = upstream_dns.resolvers()[0]["id"]
        with self.assertRaises(upstream_dns.UpstreamDNSError):
            upstream_dns.delete_resolver(only_id)
        self.assertEqual(len(upstream_dns.resolvers()), 1, "the resolver must not have been deleted")
        self.assertTrue(upstream_dns.resolvers()[0]["enabled"])

    def test_deleting_a_disabled_resolver_is_never_blocked_by_the_guard(self) -> None:
        upstream_dns.add_resolver({"name": "Spare", "protocol": "plain", "address": "9.9.9.9", "enabled": "0"})
        spare_id = self._rows()["Spare"]["id"]
        upstream_dns.delete_resolver(spare_id)  # must not raise
        self.assertNotIn("Spare", self._rows())

    def test_editing_the_last_enabled_resolver_to_disabled_is_rejected_before_commit(self) -> None:
        only = upstream_dns.resolvers()[0]
        with self.assertRaises(upstream_dns.UpstreamDNSError):
            upstream_dns.update_resolver(only["id"], {
                "name": only["name"], "protocol": "plain", "address": only["address"],
                "port": str(only["port"]), "enabled": "0",
            })
        row = upstream_dns.resolvers()[0]
        self.assertTrue(row["enabled"])
        self.assertEqual(row["name"], only["name"], "the rejected edit must not have partially applied either")

    def test_editing_a_non_last_resolver_to_disabled_still_works(self) -> None:
        upstream_dns.add_resolver({"name": "Quad9", "protocol": "plain", "address": "9.9.9.9", "enabled": "1"})
        rows = upstream_dns.resolvers()
        target = next(r for r in rows if r["name"] != "Quad9")
        upstream_dns.update_resolver(target["id"], {
            "name": target["name"], "protocol": "plain", "address": target["address"],
            "port": str(target["port"]), "enabled": "0",
        })
        self.assertFalse(self._rows()[target["name"]]["enabled"])
        self.assertTrue(self._rows()["Quad9"]["enabled"])

    def test_rejected_disable_never_touches_runtime_files_or_deployment_history(self) -> None:
        # A prior successful deploy establishes a runtime baseline.
        with mock.patch.object(upstream_dns, "run", self._fake_run):
            upstream_dns.deploy_upstreams()
        good_dnsdist = upstream_dns.DNSDIST_UPSTREAM_CONF.read_text()
        good_bind = upstream_dns.BIND_FORWARDERS_CONF.read_text()
        history_count_before = len(self._deployment_ids())

        only_id = upstream_dns.resolvers()[0]["id"]
        with mock.patch.object(upstream_dns, "run", self._fake_run):
            with self.assertRaises(upstream_dns.UpstreamDNSError):
                upstream_dns.set_enabled(only_id, False)

        self.assertEqual(upstream_dns.DNSDIST_UPSTREAM_CONF.read_text(), good_dnsdist, "runtime dnsdist config must be untouched by a rejected disable")
        self.assertEqual(upstream_dns.BIND_FORWARDERS_CONF.read_text(), good_bind, "runtime BIND config must be untouched by a rejected disable")
        # The guard fires inside set_enabled(), before deploy_upstreams() is
        # even invoked -- so no new upstream_deployments row is created at all.
        self.assertEqual(len(self._deployment_ids()), history_count_before)

    def _deployment_ids(self) -> list[int]:
        with upstream_dns.connect() as conn:
            return [row["id"] for row in conn.execute("SELECT id FROM upstream_deployments")]

    @staticmethod
    def _fake_run(command, check=True):
        import subprocess
        if command[:2] == ["dig", "@127.0.0.1"]:
            return subprocess.CompletedProcess(command, 0, ";; ->>HEADER<<- status: NOERROR\ncloudflare.com.\t300\tIN\tA\t1.1.1.1\n")
        return subprocess.CompletedProcess(command, 0, "ok\n")


class LastEnabledGuardWebTest(unittest.TestCase):
    """End-to-end through the actual /dns-settings/upstreams/... routes:
    proves the UI-visible behavior an admin actually sees, not just the
    underlying function contract."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-last-enabled-web-test-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "upstream_db": upstream_dns.DB_PATH,
            "upstream_compiled": upstream_dns.COMPILED_DIR,
            "upstream_bind_forwarders": upstream_dns.BIND_FORWARDERS_CONF,
            "upstream_dnsdist_conf_gen": upstream_dns.DNSDIST_UPSTREAM_CONF,
            "upstream_named_options": upstream_dns.NAMED_OPTIONS_CONF,
            "upstream_dnsdist_conf": upstream_dns.DNSDIST_CONF,
            "upstream_dnsdist_packaging_conf": upstream_dns.DNSDIST_PACKAGING_CONF,
            "upstream_backup_dir": upstream_dns.BACKUP_DIR,
            "upstream_staging_dir": upstream_dns.STAGING_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        webapp.DB_PATH = db_path
        alderpointdns_compiler.DB_PATH = db_path
        upstream_dns.DB_PATH = db_path
        upstream_dns.COMPILED_DIR = self.tmp / "compiled"
        upstream_dns.BIND_FORWARDERS_CONF = self.tmp / "compiled" / "bind" / "upstream-forwarders.conf"
        upstream_dns.DNSDIST_UPSTREAM_CONF = self.tmp / "compiled" / "dnsdist" / "upstream-forwarder.conf"
        upstream_dns.NAMED_OPTIONS_CONF = self.tmp / "named.conf.options"
        upstream_dns.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        upstream_dns.DNSDIST_PACKAGING_CONF = self.tmp / "packaging-dnsdist.conf"
        upstream_dns.BACKUP_DIR = self.tmp / "backups"
        upstream_dns.STAGING_DIR = self.tmp / "staging"
        upstream_dns.NAMED_OPTIONS_CONF.write_text('options {\n\tforward only;\n\tdirectory "/var/cache/bind";\n};\n')
        upstream_dns.DNSDIST_CONF.write_text(
            'newServer({\n  address="127.0.0.1:5354",\n  name="bind-proxy"\n})\n'
            'pc = newPacketCache(100)\n'
            'getPool(""):setCache(pc)\n'
            'addAction(OrRule({\n  QTypeRule(DNSQType.AXFR)\n}), RCodeAction(DNSRCode.REFUSED))\n'
        )
        upstream_dns.DNSDIST_PACKAGING_CONF.write_text(upstream_dns.DNSDIST_CONF.read_text())

        # No real `sudo .../alderpointdns_compiler.py ...` invocation should
        # ever happen once the guard rejects the mutation -- assert that
        # explicitly by failing the test outright if one is attempted, while
        # still letting the dashboard's own unrelated `systemctl is-active`
        # health-status calls (needed just to render pages/login) through to
        # the real `run()`.
        real_run = webapp.run

        def guarded_run(command):
            if "alderpointdns_compiler.py" in command:
                raise AssertionError(f"webapp.run() must not invoke the compiler once the last-enabled guard rejects the mutation: {command}")
            return real_run(command)

        self.patches = [
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(webapp, "run", guarded_run),
        ]
        for patcher in self.patches:
            patcher.start()

        alderpointdns_compiler.init_db()
        upstream_dns.init_db()
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO admins(username, password_hash, created_at) VALUES (?, ?, ?)",
            ("admin", auth.hash_password(INITIAL_PASSWORD), "now"),
        )
        conn.execute("DELETE FROM upstream_resolvers")
        conn.execute(
            "INSERT INTO upstream_resolvers(name, protocol, address, port, enabled, position, created_at, updated_at) "
            "VALUES ('Cloudflare', 'plain', '1.1.1.1', 53, 1, 1, '2026-08-10T00:00:00+00:00', '2026-08-10T00:00:00+00:00')"
        )
        conn.commit()
        conn.close()

        self.client = TestClient(webapp.app)
        self.client.post("/login", data={"username": "admin", "password": INITIAL_PASSWORD})
        self.csrf = self._current_csrf()

    def _current_csrf(self) -> str:
        html = self.client.get("/").text
        match = CSRF_RE.search(html)
        self.assertIsNotNone(match, "no csrf token found on dashboard")
        return match.group(1)

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        webapp.DB_PATH = self.old_paths["webapp_db"]
        alderpointdns_compiler.DB_PATH = self.old_paths["compiler_db"]
        upstream_dns.DB_PATH = self.old_paths["upstream_db"]
        upstream_dns.COMPILED_DIR = self.old_paths["upstream_compiled"]
        upstream_dns.BIND_FORWARDERS_CONF = self.old_paths["upstream_bind_forwarders"]
        upstream_dns.DNSDIST_UPSTREAM_CONF = self.old_paths["upstream_dnsdist_conf_gen"]
        upstream_dns.NAMED_OPTIONS_CONF = self.old_paths["upstream_named_options"]
        upstream_dns.DNSDIST_CONF = self.old_paths["upstream_dnsdist_conf"]
        upstream_dns.DNSDIST_PACKAGING_CONF = self.old_paths["upstream_dnsdist_packaging_conf"]
        upstream_dns.BACKUP_DIR = self.old_paths["upstream_backup_dir"]
        upstream_dns.STAGING_DIR = self.old_paths["upstream_staging_dir"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _resolver_id(self) -> int:
        return upstream_dns.resolvers()[0]["id"]

    def test_toggling_off_the_last_enabled_resolver_is_rejected_and_never_reaches_sudo(self) -> None:
        resolver_id = self._resolver_id()
        resp = self.client.post(
            f"/dns-settings/upstreams/{resolver_id}/toggle",
            data={"csrf": self.csrf, "enabled": "0"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("At least one upstream resolver must be enabled.", resp.text)
        # Truthful UI/DB state: the resolver is still enabled.
        self.assertTrue(upstream_dns.resolvers()[0]["enabled"])

    def test_deleting_the_last_enabled_resolver_is_rejected_and_never_reaches_sudo(self) -> None:
        resolver_id = self._resolver_id()
        resp = self.client.post(
            f"/dns-settings/upstreams/{resolver_id}/delete",
            data={"csrf": self.csrf},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("At least one upstream resolver must be enabled.", resp.text)
        self.assertEqual(len(upstream_dns.resolvers()), 1)

    def test_editing_the_last_enabled_resolver_to_disabled_is_rejected_and_never_reaches_sudo(self) -> None:
        resolver_id = self._resolver_id()
        resp = self.client.post(
            f"/dns-settings/upstreams/{resolver_id}/edit",
            data={
                "csrf": self.csrf, "name": "Cloudflare", "protocol": "plain",
                "address": "1.1.1.1", "port": "53", "enabled": "0",
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("At least one upstream resolver must be enabled.", resp.text)
        self.assertTrue(upstream_dns.resolvers()[0]["enabled"])


if __name__ == "__main__":
    unittest.main()
