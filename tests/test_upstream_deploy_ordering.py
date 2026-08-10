#!/usr/bin/env python3
"""Regression coverage for the live dns1 incident: a fresh install restored
from another appliance's backup, then edited through the ordinary upstream
DNS UI, ended up with SQLite's upstream_resolvers.enabled describing four
plain resolvers while the live dnsdist upstream-forwarder.conf still only
had two dead DoH resolvers -- with no upstream_deployments row ever
recording an attempt to apply the new state.

Root cause: app.alderpointdns_compiler.deploy() ran
dns_cache.deploy_cache_options() *before* upstream_dns.deploy_upstreams().
dns_cache.deploy_cache_options()'s own post-deploy health check resolves a
live domain through BIND :5353, which forwards through dnsdist's managed
upstream listener (:5355) -- i.e. it transitively depends on the upstream
forwarder chain already being current. When that chain was stale (e.g. the
live upstream config still pointed at resolvers that have since gone down,
while the database had already been edited to describe a different,
healthy set), the cache stage's own health check failed and aborted the
*entire* deploy() pipeline before upstream_dns.deploy_upstreams() -- which
would have fixed exactly this -- ever got a chance to run. The operator saw
"post-deploy ordinary resolution failed after cache options reload" (dns_cache's
message, not upstream's) and no upstream_deployments row was ever written
for the attempted change, even though the database had already committed
it.

This is also, deliberately, the exact deploy_upstreams()/deploy_cache_options()
boundary that tests/test_compiler_transaction_scope.py and
tests/test_deploy_allow_validation.py mock away (both stub
compiler.upstream_dns.deploy_upstreams with `lambda conn=None: 1` so they
can isolate what they're each actually testing) -- which is exactly why
this ordering bug escaped v1 acceptance: nothing exercised the real
interaction between the two. This file exercises both real, unmocked.
"""

from __future__ import annotations

import shutil
import subprocess
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

from app import alderpointdns_compiler as compiler  # noqa: E402
from app import custom_rules, dns_cache, local_dns, replication, upstream_dns  # noqa: E402


class UpstreamCacheReconciliationOrderTests(unittest.TestCase):
    """Exercises the real app.upstream_dns.deploy_upstreams() and the real
    app.dns_cache.deploy_cache_options() together through the real
    app.alderpointdns_compiler.deploy() pipeline -- only local_dns.deploy_zones()
    and custom_rules.deploy_dnsdist_layer() are stubbed, since they are not
    part of the interaction under test."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-upstream-order-test-"))
        self.old = {
            "c_DB_PATH": compiler.DB_PATH,
            "c_DOWNLOAD_DIR": compiler.DOWNLOAD_DIR,
            "c_COMPILED_RPZ": compiler.COMPILED_RPZ,
            "c_STAGING_DIR": compiler.STAGING_DIR,
            "c_BACKUP_DIR": compiler.BACKUP_DIR,
            "c_DEPLOY_LOCK": compiler.DEPLOY_LOCK,
            "l_DB_PATH": local_dns.DB_PATH,
            "dc_DB_PATH": dns_cache.DB_PATH,
            "dc_COMPILED_DIR": dns_cache.COMPILED_DIR,
            "dc_CACHE_OPTIONS_CONF": dns_cache.CACHE_OPTIONS_CONF,
            "dc_NAMED_OPTIONS_CONF": dns_cache.NAMED_OPTIONS_CONF,
            "dc_BACKUP_DIR": dns_cache.BACKUP_DIR,
            "dc_STAGING_DIR": dns_cache.STAGING_DIR,
            "cr_DB_PATH": custom_rules.DB_PATH,
            "cr_COMPILED_DNSDIST_DIR": custom_rules.COMPILED_DNSDIST_DIR,
            "cr_DNSDIST_CONF": custom_rules.DNSDIST_CONF,
            "cr_DNSDIST_PACKAGING_CONF": custom_rules.DNSDIST_PACKAGING_CONF,
            "cr_BACKUP_DIR": custom_rules.BACKUP_DIR,
            "cr_STAGING_DIR": custom_rules.STAGING_DIR,
            "u_DB_PATH": upstream_dns.DB_PATH,
            "u_COMPILED_DIR": upstream_dns.COMPILED_DIR,
            "u_BIND_FORWARDERS_CONF": upstream_dns.BIND_FORWARDERS_CONF,
            "u_DNSDIST_UPSTREAM_CONF": upstream_dns.DNSDIST_UPSTREAM_CONF,
            "u_NAMED_OPTIONS_CONF": upstream_dns.NAMED_OPTIONS_CONF,
            "u_DNSDIST_CONF": upstream_dns.DNSDIST_CONF,
            "u_DNSDIST_PACKAGING_CONF": upstream_dns.DNSDIST_PACKAGING_CONF,
            "u_BACKUP_DIR": upstream_dns.BACKUP_DIR,
            "u_STAGING_DIR": upstream_dns.STAGING_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        compiler.DB_PATH = db_path
        compiler.DOWNLOAD_DIR = self.tmp / "downloads"
        compiler.COMPILED_RPZ = self.tmp / "compiled" / "bind" / "alderpointdns.rpz"
        compiler.STAGING_DIR = self.tmp / "staging"
        compiler.BACKUP_DIR = self.tmp / "backups"
        compiler.DEPLOY_LOCK = self.tmp / "staging" / "deploy.lock"
        local_dns.DB_PATH = db_path
        dns_cache.DB_PATH = db_path
        dns_cache.COMPILED_DIR = self.tmp / "compiled" / "bind"
        dns_cache.CACHE_OPTIONS_CONF = dns_cache.COMPILED_DIR / "cache-options.conf"
        named_options_conf = self.tmp / "named.conf.options"
        dns_cache.NAMED_OPTIONS_CONF = named_options_conf
        dns_cache.BACKUP_DIR = self.tmp / "backups"
        dns_cache.STAGING_DIR = self.tmp / "staging"
        custom_rules.DB_PATH = db_path
        custom_rules.COMPILED_DNSDIST_DIR = self.tmp / "compiled" / "dnsdist"
        dnsdist_conf = self.tmp / "dnsdist.conf"
        custom_rules.DNSDIST_CONF = dnsdist_conf
        custom_rules.DNSDIST_PACKAGING_CONF = self.tmp / "packaging-dnsdist.conf"
        custom_rules.BACKUP_DIR = self.tmp / "backups"
        custom_rules.STAGING_DIR = self.tmp / "staging"
        upstream_dns.DB_PATH = db_path
        upstream_dns.COMPILED_DIR = self.tmp / "compiled"
        upstream_dns.BIND_FORWARDERS_CONF = self.tmp / "compiled" / "bind" / "upstream-forwarders.conf"
        upstream_dns.DNSDIST_UPSTREAM_CONF = self.tmp / "compiled" / "dnsdist" / "upstream-forwarder.conf"
        # Same physical files dns_cache's/custom_rules' own constants above
        # point at -- in production all of these modules share one
        # /etc/bind/named.conf.options and one /etc/dnsdist/dnsdist.conf.
        upstream_dns.NAMED_OPTIONS_CONF = named_options_conf
        upstream_dns.DNSDIST_CONF = dnsdist_conf
        upstream_dns.DNSDIST_PACKAGING_CONF = dnsdist_conf
        upstream_dns.BACKUP_DIR = self.tmp / "backups"
        upstream_dns.STAGING_DIR = self.tmp / "staging"

        compiler.STAGING_DIR.mkdir(parents=True)
        named_options_conf.write_text('options {\n\tforward only;\n\tdirectory "/var/cache/bind";\n};\n')
        dnsdist_conf.write_text(
            'newServer({\n  address="127.0.0.1:5354",\n  name="bind-proxy"\n})\n'
            'pc = newPacketCache(100)\n'
            'getPool(""):setCache(pc)\n'
            'addAction(OrRule({\n  QTypeRule(DNSQType.AXFR)\n}), RCodeAction(DNSRCode.REFUSED))\n'
        )
        compiler.init_db()
        # Simulate upstream DNS having already been configured and deployed
        # successfully once in the past (exactly dns1's situation after the
        # DoH resolvers were first enabled and deployed -- upstream_deployments
        # ids 5/6/7 in the incident): wire the includes into named.conf.options
        # and dnsdist.conf once via the real functions, then hand-write a
        # "live" upstream-forwarder.conf that still names the since-gone-dead
        # resolvers, standing in for whatever the last *successful*
        # deploy_upstreams() run actually wrote.
        upstream_dns.ensure_named_forwarders_include()
        upstream_dns.ensure_dnsdist_include()
        upstream_dns.DNSDIST_UPSTREAM_CONF.parent.mkdir(parents=True, exist_ok=True)
        upstream_dns.DNSDIST_UPSTREAM_CONF.write_text(
            '-- Managed by Alderpoint DNS. Generated upstream forwarder; do not edit by hand.\n'
            'alderpointdnsUpstreamsEnabled = true\n'
            'addLocal("127.0.0.1:5355", {reusePort=true})\n'
            'setPoolServerPolicy(firstAvailable, "alderpointdns_upstreams")\n'
            'newServer({address="198.51.100.53:443", name="upstream-5-dead-doh", pool="alderpointdns_upstreams", '
            'tls="openssl", validateCertificates=true, subjectName="dns.dead-doh.example"})\n'
        )
        upstream_dns.BIND_FORWARDERS_CONF.parent.mkdir(parents=True, exist_ok=True)
        upstream_dns.BIND_FORWARDERS_CONF.write_text(upstream_dns.render_bind_forwarders())
        upstream_dns.init_db()
        with self.connect() as conn:
            # A UI edit that has already committed a new, healthy desired
            # state to SQLite (upstream_toggle()/upstream_edit() always
            # commit before attempting a redeploy) -- but the live
            # dnsdist upstream-forwarder.conf above still reflects the
            # last successfully *applied* state, not this one.
            conn.execute("DELETE FROM upstream_resolvers")
            conn.execute(
                "INSERT INTO upstream_resolvers(name, protocol, address, port, enabled, position, created_at, updated_at) "
                "VALUES ('Quad9', 'plain', '9.9.9.9', 53, 1, 1, '2026-08-10T00:00:00+00:00', '2026-08-10T00:00:00+00:00')"
            )
            conn.commit()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            prefix, name = key.split("_", 1)
            module = {"c": compiler, "l": local_dns, "dc": dns_cache, "cr": custom_rules, "u": upstream_dns}[prefix]
            setattr(module, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(compiler.DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def fake_run(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        """Models the real dependency chain: a `dig` against BIND (:5353) or
        dnsdist's managed upstream listener (:5355) only actually succeeds
        once the live upstream-forwarder.conf names the resolver the
        database currently has enabled (9.9.9.9) -- exactly like a real
        BIND-forwards-to-dnsdist-forwards-to-the-real-Internet chain would,
        and exactly why the incident's dead DoH servers produced real
        timeouts, not a mocked-away non-issue."""
        if command[:2] == ["dig", "@127.0.0.1"]:
            content = upstream_dns.DNSDIST_UPSTREAM_CONF.read_text() if upstream_dns.DNSDIST_UPSTREAM_CONF.exists() else ""
            if "9.9.9.9:53" in content:
                return subprocess.CompletedProcess(command, 0, ";; ->>HEADER<<- status: NOERROR\ncloudflare.com.\t300\tIN\tA\t1.1.1.1\n")
            return subprocess.CompletedProcess(command, 9, ";; connection timed out; no servers could be reached\n")
        return subprocess.CompletedProcess(command, 0, "ok\n")

    def run_deploy(self):
        with mock.patch.object(compiler, "run", self.fake_run), \
                mock.patch.object(dns_cache, "run", self.fake_run), \
                mock.patch.object(upstream_dns, "run", self.fake_run), \
                mock.patch.object(custom_rules, "run", self.fake_run), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: 1), \
                mock.patch.object(compiler.custom_rules, "deploy_dnsdist_layer", lambda conn, active=None: {"changed": False, "backups": [], "counts": {}}), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: None):
            return compiler.deploy(download=False)

    def test_stale_upstream_runtime_no_longer_silently_blocks_reconciliation(self) -> None:
        """The exact incident: a stale/dead live upstream config must not
        prevent deploy_upstreams() from ever running and fixing itself just
        because an earlier pipeline stage's own health check depends on the
        very thing that's stale."""
        deployment_id = self.run_deploy()

        with self.connect() as conn:
            deployment = conn.execute("SELECT status, message FROM deployments WHERE id=?", (deployment_id,)).fetchone()
            upstream_deployment = conn.execute("SELECT status, message FROM upstream_deployments ORDER BY id DESC LIMIT 1").fetchone()

        self.assertEqual(deployment["status"], "deployed", deployment["message"])
        # The critical assertion from the incident report: an
        # upstream_deployments row recording the attempt (success or
        # failure) must exist -- not silence.
        self.assertIsNotNone(upstream_deployment, "upstream_dns.deploy_upstreams() was never even attempted")
        self.assertEqual(upstream_deployment["status"], "deployed")
        self.assertIn("deployed 1 enabled upstream resolver", upstream_deployment["message"])

        live_upstream_conf = upstream_dns.DNSDIST_UPSTREAM_CONF.read_text()
        self.assertIn("9.9.9.9:53", live_upstream_conf)
        self.assertNotIn("dead-doh", live_upstream_conf)

    def test_deploy_regenerates_upstream_before_cache_options_health_check(self) -> None:
        """Directly pins the fix's ordering: by the time
        dns_cache.deploy_cache_options()'s own health check runs, the live
        upstream config must already be the freshly regenerated one, not
        whatever was there when deploy() started."""
        seen_upstream_conf_during_cache_deploy: list[str] = []
        real_deploy_cache_options = dns_cache.deploy_cache_options

        def observing_cache_deploy(conn=None):
            seen_upstream_conf_during_cache_deploy.append(upstream_dns.DNSDIST_UPSTREAM_CONF.read_text())
            return real_deploy_cache_options(conn)

        with mock.patch.object(compiler, "run", self.fake_run), \
                mock.patch.object(dns_cache, "run", self.fake_run), \
                mock.patch.object(upstream_dns, "run", self.fake_run), \
                mock.patch.object(custom_rules, "run", self.fake_run), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: 1), \
                mock.patch.object(compiler.dns_cache, "deploy_cache_options", observing_cache_deploy), \
                mock.patch.object(compiler.custom_rules, "deploy_dnsdist_layer", lambda conn, active=None: {"changed": False, "backups": [], "counts": {}}), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: None):
            compiler.deploy(download=False)

        self.assertEqual(len(seen_upstream_conf_during_cache_deploy), 1)
        self.assertIn("9.9.9.9:53", seen_upstream_conf_during_cache_deploy[0])

    def test_deployment_history_never_silent_when_upstream_reconciliation_itself_fails(self) -> None:
        """If the *new* desired resolver is also unreachable, the failure
        must be truthfully recorded against upstream_deployments (never
        silently absorbed by an unrelated stage failing first), and the
        last-good live config must be restored -- last-good rollback safety
        is preserved."""
        stale_conf = upstream_dns.DNSDIST_UPSTREAM_CONF.read_text()

        def always_fail_dig(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["dig", "@127.0.0.1"]:
                return subprocess.CompletedProcess(command, 9, ";; connection timed out; no servers could be reached\n")
            return subprocess.CompletedProcess(command, 0, "ok\n")

        with mock.patch.object(compiler, "run", always_fail_dig), \
                mock.patch.object(dns_cache, "run", always_fail_dig), \
                mock.patch.object(upstream_dns, "run", always_fail_dig), \
                mock.patch.object(custom_rules, "run", always_fail_dig), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: 1), \
                mock.patch.object(compiler.custom_rules, "deploy_dnsdist_layer", lambda conn, active=None: {"changed": False, "backups": [], "counts": {}}), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: None):
            with self.assertRaises(Exception):
                compiler.deploy(download=False)

        with self.connect() as conn:
            upstream_deployment = conn.execute("SELECT status FROM upstream_deployments ORDER BY id DESC LIMIT 1").fetchone()
            row = conn.execute("SELECT enabled, last_status FROM upstream_resolvers WHERE name='Quad9'").fetchone()

        self.assertIsNotNone(upstream_deployment)
        self.assertEqual(upstream_deployment["status"], "rolled_back")
        # Runtime file rolled back to last-good -- the safety behavior this
        # fix must preserve.
        self.assertEqual(upstream_dns.DNSDIST_UPSTREAM_CONF.read_text(), stale_conf)
        # Truthful per-row state: the database still says Quad9 is enabled
        # (an ordinary UI edit is never silently undone by this fix), but
        # its last_status must say it failed to actually apply -- never a
        # bare "enabled" checkbox with no indication the live config
        # disagrees.
        self.assertEqual(row["enabled"], 1)
        self.assertEqual(row["last_status"], "failed")

    def test_successful_upstream_deploy_is_not_undone_by_a_later_cache_failure(self) -> None:
        """Pins the exact question the reorder raises: upstream deploys
        successfully and changes live runtime, then a *later*, independent
        stage (cache options) fails. deploy() has never rolled back an
        already-successful *earlier* subsystem just because a later one
        failed (RPZ/local zones aren't undone by a custom-rules failure
        either) -- each subsystem owns its own last-good rollback, and the
        aggregate `deployments` row is the only thing that reports the
        overall run as failed. Moving upstream earlier must not change that:
        upstream's own success (SQLite, live runtime, upstream_deployments)
        must stand untouched, truthfully recorded as 'deployed', while the
        cache stage's own failure is independently and truthfully recorded
        against dns_cache_deployments/deployments -- never misattributed to
        upstream, and never silently reverting upstream's real, live
        success."""
        # Decoupled from self.fake_run on purpose: dns_cache.run's `dig`
        # always fails here while upstream_dns.run's `dig` always succeeds,
        # so the two subsystems' outcomes can't be accidentally coupled by
        # a single shared fake the way self.fake_run ties them to the same
        # file's content.
        def always_ok_dig(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["dig", "@127.0.0.1"]:
                return subprocess.CompletedProcess(command, 0, ";; ->>HEADER<<- status: NOERROR\ncloudflare.com.\t300\tIN\tA\t1.1.1.1\n")
            if command[:2] == ["dnsdist", "-e"]:
                # A synthetic `showServers()` reply reporting Quad9's own
                # backend as up -- deploy_upstreams() now records each
                # row's real per-backend state instead of blanket-marking
                # every enabled row 'healthy' off the pool-level check alone.
                return subprocess.CompletedProcess(command, 0, "0   Quad9                9.9.9.9:53                                      up     0.0       0          1          1          1       0   0.0   0.5     -           0 alderpointdns_upstreams\n")
            return subprocess.CompletedProcess(command, 0, "ok\n")

        def always_fail_dig(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["dig", "@127.0.0.1"]:
                return subprocess.CompletedProcess(command, 9, ";; connection timed out; no servers could be reached\n")
            return subprocess.CompletedProcess(command, 0, "ok\n")

        with mock.patch.object(compiler, "run", always_ok_dig), \
                mock.patch.object(dns_cache, "run", always_fail_dig), \
                mock.patch.object(upstream_dns, "run", always_ok_dig), \
                mock.patch.object(custom_rules, "run", always_ok_dig), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: 1), \
                mock.patch.object(compiler.custom_rules, "deploy_dnsdist_layer", lambda conn, active=None: {"changed": False, "backups": [], "counts": {}}), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: None):
            with self.assertRaises(Exception) as ctx:
                compiler.deploy(download=False)

        with self.connect() as conn:
            deployment = conn.execute("SELECT status, message FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
            upstream_deployment = conn.execute("SELECT status, message FROM upstream_deployments ORDER BY id DESC LIMIT 1").fetchone()
            cache_deployment = conn.execute("SELECT status FROM dns_cache_deployments ORDER BY id DESC LIMIT 1").fetchone()
            resolver_row = conn.execute("SELECT enabled, last_status FROM upstream_resolvers WHERE name='Quad9'").fetchone()

        # The overall run is truthfully reported as failed/rolled back, and
        # for the right (cache) reason -- never silent, never misattributed.
        self.assertEqual(deployment["status"], "rolled_back")
        self.assertIn("post-deploy ordinary resolution failed after cache options reload", str(ctx.exception))
        self.assertIn("post-deploy ordinary resolution failed after cache options reload", deployment["message"])

        # Upstream's own success is untouched: still recorded as 'deployed'
        # (never silently flipped to rolled_back just because a later,
        # unrelated stage failed), and both SQLite and the live runtime
        # file agree with it.
        self.assertEqual(upstream_deployment["status"], "deployed")
        self.assertIn("9.9.9.9:53", upstream_dns.DNSDIST_UPSTREAM_CONF.read_text())
        self.assertEqual(resolver_row["enabled"], 1)
        self.assertEqual(resolver_row["last_status"], "healthy")

        # Cache's own failure is independently, truthfully recorded and
        # rolled back to its own last-good (no prior cache-options.conf
        # existed, so last-good is "not installed") -- never left half
        # applied.
        self.assertEqual(cache_deployment["status"], "rolled_back")
        self.assertFalse(dns_cache.CACHE_OPTIONS_CONF.exists())


if __name__ == "__main__":
    unittest.main()
