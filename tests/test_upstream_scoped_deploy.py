#!/usr/bin/env python3
"""Regression coverage for two things the v1.0.1 RC concurrency incident
investigation found about the upstream DNS resolver routes:

1. Upstream add/edit/toggle/move/delete used to invoke the *entire*
   `alderpointdns_compiler.py deploy --no-download` pipeline (RPZ
   compile/validate, BIND reload, upstream deploy, cache options deploy,
   custom-rules dnsdist layer, multiple post-deploy health checks) for a
   change that only ever touches the managed-upstream-resolver stage.
   upstream_dns.deploy_upstreams() already owns its own render/stage/
   promote, validation, restart/reload, post-deploy health check, and
   last-good rollback/history end to end -- nothing else in the pipeline
   depends on upstream resolver state (only the reverse dependency exists,
   which is exactly what the deploy-ordering fix in
   tests/test_upstream_deploy_ordering.py is about). Routing through the
   full pipeline was needless cost, not a real dependency, and made a
   single checkbox click take as long as a full blocklist recompile while
   needlessly overlapping with unrelated blocklist/local-DNS/cache changes.

2. Real UI use -- several upstream toggles submitted before the previous
   one's request had returned -- must never surface a raw SQLite
   "database is locked" error, must never pile up one full deploy per
   click, and must leave the database and live runtime state truthful and
   recoverable once the burst settles.
"""

from __future__ import annotations

import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from fastapi.testclient import TestClient  # noqa: E402

from app import alderpointdns_compiler, auth, local_dns, upstream_dns, webapp  # noqa: E402

CSRF_RE = re.compile(r'name="csrf" value="([^"]+)"')
INITIAL_PASSWORD = "initial-password-123"


class UpstreamScopedDeployTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-upstream-scoped-test-"))
        self.old_paths = {
            "webapp_db": webapp.DB_PATH,
            "compiler_db": alderpointdns_compiler.DB_PATH,
            "compiler_migration_lock": alderpointdns_compiler.MIGRATION_LOCK,
            "compiler_deploy_lock": alderpointdns_compiler.DEPLOY_LOCK,
            "local_dns_db": local_dns.DB_PATH,
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
        alderpointdns_compiler.MIGRATION_LOCK = self.tmp / "staging" / "schema-migration.lock"
        alderpointdns_compiler.DEPLOY_LOCK = self.tmp / "staging" / "deploy.lock"
        local_dns.DB_PATH = db_path
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

        self.patches = [
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(webapp, "dnsdist_version_info", lambda: {"ok": True, "version": "dnsdist test", "features": "", "feature_set": set()}),
            mock.patch.object(webapp, "proxy_backend_enabled", lambda: True),
            mock.patch.object(webapp, "client_address_preservation_status", lambda: {"state": "Configured", "detail": "test"}),
            mock.patch.object(webapp, "protocol_statuses", lambda: []),
            mock.patch.object(webapp, "cert_status", lambda: {"state": "present", "detail": "test"}),
            mock.patch.object(webapp.encryption, "dnsdist_capabilities", lambda: {"doh": True, "dot": True, "doq": False, "doh3": False, "dnscrypt": False}),
            mock.patch.object(webapp, "dns_allow_all_enabled", lambda: False),
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
        conn.execute(
            "INSERT INTO upstream_resolvers(name, protocol, address, port, enabled, position, created_at, updated_at) "
            "VALUES ('Quad9', 'plain', '9.9.9.9', 53, 0, 2, '2026-08-10T00:00:00+00:00', '2026-08-10T00:00:00+00:00')"
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
        alderpointdns_compiler.MIGRATION_LOCK = self.old_paths["compiler_migration_lock"]
        alderpointdns_compiler.DEPLOY_LOCK = self.old_paths["compiler_deploy_lock"]
        local_dns.DB_PATH = self.old_paths["local_dns_db"]
        upstream_dns.DB_PATH = self.old_paths["upstream_db"]
        upstream_dns.COMPILED_DIR = self.old_paths["upstream_compiled"]
        upstream_dns.BIND_FORWARDERS_CONF = self.old_paths["upstream_bind_forwarders"]
        upstream_dns.DNSDIST_UPSTREAM_CONF = self.old_paths["upstream_dnsdist_conf_gen"]
        upstream_dns.NAMED_OPTIONS_CONF = self.old_paths["upstream_named_options"]
        upstream_dns.DNSDIST_CONF = self.old_paths["upstream_dnsdist_conf"]
        upstream_dns.DNSDIST_PACKAGING_CONF = self.old_paths["upstream_dnsdist_packaging_conf"]
        upstream_dns.BACKUP_DIR = self.old_paths["upstream_backup_dir"]
        upstream_dns.STAGING_DIR = self.old_paths["upstream_staging_dir"]
        # Coordinators are process-wide singletons; a leftover in-flight/
        # coalesced state from one test must never bleed into the next.
        # Reset in place (not by constructing replacements) so each
        # coordinator's real production configuration -- e.g.
        # _upstream_deploy_coordinator's min_interval_seconds restart-rate
        # limit -- survives every test file that runs after this one in the
        # same process instead of silently reverting to the constructor
        # defaults.
        for coordinator in (webapp._deploy_coordinator, webapp._upstream_deploy_coordinator, webapp._cache_flush_coordinator, webapp._cache_options_coordinator):
            coordinator._in_flight = False
            coordinator._coalesced = False
            coordinator._round = 0
            coordinator._result = None
            coordinator._error = None
            coordinator._last_finished = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _resolver_id(self, name: str) -> int:
        with sqlite3.connect(webapp.DB_PATH) as conn:
            row = conn.execute("SELECT id FROM upstream_resolvers WHERE name=?", (name,)).fetchone()
        return row[0]

    def test_dns_settings_exposes_upstream_telemetry_hooks_by_provider_id(self) -> None:
        cloudflare_id = self._resolver_id("Cloudflare")
        response = self.client.get("/dns-settings")

        self.assertEqual(response.status_code, 200)
        self.assertIn('data-upstream-telemetry-url="/dns-settings/upstreams/telemetry"', response.text)
        self.assertIn('data-upstream-telemetry-interval-ms="5000"', response.text)
        self.assertIn(f'data-upstream-resolver-id="{cloudflare_id}"', response.text)
        self.assertIn("data-upstream-health", response.text)

    def test_upstream_telemetry_endpoint_returns_stored_rows_without_external_probe(self) -> None:
        cloudflare_id = self._resolver_id("Cloudflare")
        quad9_id = self._resolver_id("Quad9")
        upstream_dns.record_probe_result(cloudflare_id, ok=True, latency_ms=23.4)

        with mock.patch.object(upstream_dns, "probe_resolver") as probe, \
             mock.patch.object(upstream_dns, "probe_and_record") as probe_record:
            response = self.client.get("/dns-settings/upstreams/telemetry")

        self.assertEqual(response.status_code, 200)
        probe.assert_not_called()
        probe_record.assert_not_called()
        rows = {row["id"]: row for row in response.json()["resolvers"]}
        self.assertEqual(rows[cloudflare_id]["status"], "healthy")
        self.assertEqual(rows[cloudflare_id]["latency_ms"], 23.4)
        self.assertEqual(rows[quad9_id]["status"], "disabled")
        self.assertIsNone(rows[quad9_id]["latency_ms"])

    # -- 7. scoped path: unrelated subsystems are never touched --------

    def test_toggle_invokes_only_the_scoped_upstream_deploy_subcommand(self) -> None:
        resolver_id = self._resolver_id("Quad9")
        commands: list[list[str]] = []
        real_run = webapp.run

        def observing_run(command: list[str]) -> tuple[int, str]:
            commands.append(command)
            return real_run(command) if command[:2] != ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py"] else (0, "deployed 2 enabled upstream resolver(s)")

        with mock.patch.object(webapp, "run", observing_run):
            response = self.client.post(
                f"/dns-settings/upstreams/{resolver_id}/toggle",
                data={"csrf": self.csrf, "enabled": "1"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 303)
        compiler_subcommands = [c[2] for c in commands if len(c) > 2 and c[:2] == ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py"]]
        self.assertEqual(
            compiler_subcommands, ["upstream-deploy"],
            f"upstream toggle must invoke only the scoped upstream-deploy subcommand, got {compiler_subcommands}",
        )
        self.assertNotIn("deploy", compiler_subcommands)
        self.assertNotIn("cache-deploy", compiler_subcommands)
        self.assertNotIn("local-dns-deploy", compiler_subcommands)

    def test_add_edit_move_delete_also_use_the_scoped_path(self) -> None:
        cloudflare_id = self._resolver_id("Cloudflare")
        quad9_id = self._resolver_id("Quad9")
        actions = [
            ("post", "/dns-settings/upstreams/add", {"csrf": self.csrf, "name": "OpenDNS", "protocol": "plain", "address": "208.67.222.222", "port": "53", "enabled": "1"}),
            ("post", f"/dns-settings/upstreams/{cloudflare_id}/edit", {"csrf": self.csrf, "name": "Cloudflare", "protocol": "plain", "address": "1.1.1.1", "port": "53", "enabled": "1"}),
            ("post", f"/dns-settings/upstreams/{quad9_id}/move", {"csrf": self.csrf, "direction": "up"}),
            ("post", f"/dns-settings/upstreams/{quad9_id}/delete", {"csrf": self.csrf}),
        ]
        with mock.patch.object(webapp, "run", return_value=(0, "1 deployed 1 enabled upstream resolver(s) (applied live, no dnsdist restart)")) as run_mock:
            for _, path, data in actions:
                response = self.client.post(path, data=data, follow_redirects=False)
                self.assertEqual(response.status_code, 303, response.text)

        for call in run_mock.call_args_list:
            command = call.args[0]
            self.assertEqual(command[:2], ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py"])
            self.assertEqual(command[2], "upstream-deploy", f"unexpected subcommand invoked: {command}")

    # -- overlapping toggles: no pile-up, no raw sqlite errors, ---------
    # -- truthful/recoverable final state --------------------------------

    def test_overlapping_toggles_never_surface_database_locked_and_coalesce(self) -> None:
        resolver_id = self._resolver_id("Quad9")
        run_count = 0
        run_guard = threading.Lock()

        def slow_run(command: list[str]) -> tuple[int, str]:
            nonlocal run_count
            with run_guard:
                run_count += 1
            time.sleep(0.1)
            # Matches the real subprocess output for the common case (see
            # app.upstream_dns.deploy_upstreams()'s _console_reconcile()):
            # applied live, no restart -- so this test isn't slowed down by
            # _upstream_deploy_coordinator's restart-only pacing, which
            # only fires when a run's own output says otherwise.
            return (0, "1 deployed 2 enabled upstream resolver(s) (applied live, no dnsdist restart)")

        responses: list = []
        response_guard = threading.Lock()
        errors: list[BaseException] = []

        def toggle(enabled: str) -> None:
            try:
                resp = self.client.post(
                    f"/dns-settings/upstreams/{resolver_id}/toggle",
                    data={"csrf": self.csrf, "enabled": enabled},
                    follow_redirects=False,
                )
                with response_guard:
                    responses.append(resp)
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        with mock.patch.object(webapp, "run", slow_run):
            threads = [threading.Thread(target=toggle, args=(str(i % 2),)) for i in range(6)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)

        self.assertEqual(errors, [])
        self.assertEqual(len(responses), 6)
        for resp in responses:
            body = resp.text.lower()
            self.assertNotIn("database is locked", body)
            # Every request must either succeed (redirect) or fail with a
            # clear, handled message -- never an unhandled 500.
            self.assertIn(resp.status_code, (303, 400))
            if resp.status_code == 400:
                self.assertIn("progress", body)

        # Coalescing: 6 overlapping clicks must not cost 6 full subprocess
        # spawns.
        self.assertLess(run_count, 6, f"overlapping toggles were not coalesced: {run_count} deploys for 6 clicks")

        # Recoverable: an ordinary toggle after the storm settles must still
        # work normally.
        final = self.client.post(
            f"/dns-settings/upstreams/{resolver_id}/toggle",
            data={"csrf": self.csrf, "enabled": "1"},
            follow_redirects=False,
        )
        self.assertEqual(final.status_code, 303)
        with sqlite3.connect(webapp.DB_PATH) as conn:
            row = conn.execute("SELECT enabled FROM upstream_resolvers WHERE id=?", (resolver_id,)).fetchone()
        self.assertEqual(row[0], 1, "final DB state must truthfully reflect the last applied change")

    def test_sequential_ordinary_use_still_works(self) -> None:
        """Also guards the exact UX regression an earlier version of the
        restart-rate fix introduced: pacing every deploy unconditionally at
        _upstream_deploy_coordinator's min_interval_seconds (16s in
        production) turned 3 ordinary sequential toggles into a many-second
        wait even though none of them ever restarted dnsdist. Pacing must
        apply only when a deploy's own output says it actually restarted --
        this mock's "no dnsdist restart" response must never be throttled."""
        resolver_id = self._resolver_id("Quad9")
        start = time.monotonic()
        with mock.patch.object(webapp, "run", return_value=(0, "1 deployed 2 enabled upstream resolver(s) (applied live, no dnsdist restart)")):
            for enabled in ("1", "0", "1"):
                resp = self.client.post(
                    f"/dns-settings/upstreams/{resolver_id}/toggle",
                    data={"csrf": self.csrf, "enabled": enabled},
                    follow_redirects=False,
                )
                self.assertEqual(resp.status_code, 303)
        elapsed = time.monotonic() - start
        self.assertLess(
            elapsed, 5.0,
            f"3 sequential ordinary toggles that never restarted dnsdist took {elapsed:.1f}s -- "
            "restart-rate pacing must not apply to non-restart deploys",
        )
        with sqlite3.connect(webapp.DB_PATH) as conn:
            row = conn.execute("SELECT enabled FROM upstream_resolvers WHERE id=?", (resolver_id,)).fetchone()
        self.assertEqual(row[0], 1)


if __name__ == "__main__":
    unittest.main()
