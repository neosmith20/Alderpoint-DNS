#!/usr/bin/env python3
from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import upstream_dns  # noqa: E402


class UpstreamDNSTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-upstream-test-"))
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
        upstream_dns.NAMED_OPTIONS_CONF.write_text('options {\n\tforward only;\n\tforwarders { 9.9.9.9; 149.112.112.112; };\n};\n')
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

    def fake_run(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        if command[:1] == ["dig"] and len(command) > 3 and command[1].startswith("@") and command[1] != "@127.0.0.1":
            if command[2] == "cloudflare-dns.com" and command[3] == "A":
                return subprocess.CompletedProcess(command, 0, "104.16.248.249\n104.16.249.249\n")
            if command[3] == "AAAA":
                return subprocess.CompletedProcess(command, 0, "")
        if command[:2] == ["dig", "@127.0.0.1"]:
            return subprocess.CompletedProcess(command, 0, ";; ->>HEADER<<- status: NOERROR\ncloudflare.com.\t300\tIN\tA\t1.1.1.1\n")
        return subprocess.CompletedProcess(command, 0, "ok\n")

    def test_seed_preserves_existing_plain_forwarders(self) -> None:
        rows = upstream_dns.resolvers()
        self.assertEqual([row["address"] for row in rows], ["9.9.9.9", "149.112.112.112"])
        self.assertTrue(all(row["protocol"] == "plain" and row["enabled"] for row in rows))

    def test_changing_standard_dns_upstream_persists(self) -> None:
        resolver_id = upstream_dns.resolvers()[0]["id"]
        upstream_dns.update_resolver(resolver_id, {"name": "Quad9 primary", "protocol": "plain", "address": "9.9.9.10", "port": "53", "enabled": "1"})
        row = upstream_dns.resolvers()[0]
        self.assertEqual(row["name"], "Quad9 primary")
        self.assertEqual(row["address"], "9.9.9.10")

    def test_doh_upstream_requires_https_and_bootstrap_for_hostname(self) -> None:
        with self.assertRaises(upstream_dns.UpstreamDNSError):
            upstream_dns.validate_resolver({"name": "bad", "protocol": "doh", "address": "http://dns.example/dns-query"})
        with self.assertRaises(upstream_dns.UpstreamDNSError):
            upstream_dns.validate_resolver({"name": "bad", "protocol": "doh", "address": "https://dns.example/dns-query?token=secret"})
        with self.assertRaises(upstream_dns.UpstreamDNSError):
            upstream_dns.validate_resolver({"name": "bad", "protocol": "doh", "address": "https://dns.example/dns-query"})
        ok = upstream_dns.validate_resolver({"name": "ok", "protocol": "doh", "address": "https://dns.example/dns-query", "bootstrap_ips": "1.1.1.1"})
        self.assertEqual(ok["doh_path"], "/dns-query")
        self.assertEqual(ok["tls_hostname"], "dns.example")

    def test_prepare_doh_upstream_resolves_hostname_through_bootstrap(self) -> None:
        rows = [{
            "id": 10,
            "name": "Cloudflare DoH",
            "protocol": "doh",
            "address": "cloudflare-dns.com",
            "port": 443,
            "doh_path": "/dns-query",
            "tls_hostname": "cloudflare-dns.com",
            "bootstrap_ips": "1.1.1.1",
            "position": 1,
        }]
        calls: list[list[str]] = []

        def bootstrap_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if command == ["dig", "@1.1.1.1", "cloudflare-dns.com", "A", "+short", "+time=3", "+tries=1"]:
                return subprocess.CompletedProcess(command, 0, "104.16.248.249\n104.16.249.249\n")
            return subprocess.CompletedProcess(command, 0, "")

        with mock.patch.object(upstream_dns, "run", bootstrap_run):
            prepared = upstream_dns.prepare_dnsdist_rows(rows)

        text = upstream_dns.render_dnsdist_upstreams(prepared)
        self.assertIn('addLocal("127.0.0.1:5355"', text)
        self.assertIn('pool="alderpointdns_upstreams"', text)
        self.assertIn('address="104.16.248.249:443"', text)
        self.assertNotIn('address="1.1.1.1:443"', text)
        self.assertIn('tls="openssl"', text)
        self.assertIn('subjectName="cloudflare-dns.com"', text)
        self.assertIn('dohPath="/dns-query"', text)
        self.assertEqual(calls[0], ["dig", "@1.1.1.1", "cloudflare-dns.com", "A", "+short", "+time=3", "+tries=1"])

    def test_prepare_doh_upstream_tries_later_bootstrap_resolvers(self) -> None:
        rows = [{
            "id": 11,
            "name": "Slash8 DoH",
            "protocol": "doh",
            "address": "dns.slash8network.com",
            "port": 443,
            "doh_path": "/dns-query/redacted",
            "tls_hostname": "dns.slash8network.com",
            "bootstrap_ips": "1.1.1.2, 1.0.0.2",
            "position": 1,
        }]

        def bootstrap_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:3] == ["dig", "@1.1.1.2", "dns.slash8network.com"]:
                return subprocess.CompletedProcess(command, 9, "")
            if command == ["dig", "@1.0.0.2", "dns.slash8network.com", "A", "+short", "+time=3", "+tries=1"]:
                return subprocess.CompletedProcess(command, 0, "104.21.25.172\n172.67.134.106\n")
            return subprocess.CompletedProcess(command, 0, "")

        with mock.patch.object(upstream_dns, "run", bootstrap_run):
            prepared = upstream_dns.prepare_dnsdist_rows(rows)

        text = upstream_dns.render_dnsdist_upstreams(prepared)
        self.assertIn('address="104.21.25.172:443"', text)
        self.assertNotIn('address="1.1.1.2:443"', text)
        self.assertIn('subjectName="dns.slash8network.com"', text)

    def test_deploy_multiple_enabled_resolvers(self) -> None:
        upstream_dns.add_resolver({"name": "Cloudflare DoH", "protocol": "doh", "address": "https://cloudflare-dns.com/dns-query", "bootstrap_ips": "1.1.1.1", "enabled": "1"})
        with mock.patch.object(upstream_dns, "run", self.fake_run):
            upstream_dns.deploy_upstreams()
        self.assertIn("forwarders port 5355", upstream_dns.BIND_FORWARDERS_CONF.read_text())
        dnsdist = upstream_dns.DNSDIST_UPSTREAM_CONF.read_text()
        self.assertIn("9.9.9.9:53", dnsdist)
        self.assertIn("104.16.248.249:443", dnsdist)
        self.assertNotIn("1.1.1.1:443", dnsdist)
        self.assertEqual(upstream_dns.last_deployment()["status"], "deployed")

    def test_mixed_plain_and_unresolvable_doh_deploys_plain_and_marks_doh_failed(self) -> None:
        upstream_dns.add_resolver({"name": "Broken DoH", "protocol": "doh", "address": "https://broken.example/dns-query", "bootstrap_ips": "1.1.1.1", "enabled": "1"})

        def mixed_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:3] == ["dig", "@1.1.1.1", "broken.example"]:
                return subprocess.CompletedProcess(command, 0, "")
            return self.fake_run(command, check)

        with mock.patch.object(upstream_dns, "run", mixed_run):
            upstream_dns.deploy_upstreams()

        dnsdist = upstream_dns.DNSDIST_UPSTREAM_CONF.read_text()
        self.assertIn("9.9.9.9:53", dnsdist)
        self.assertNotIn("broken.example", dnsdist)
        rows = {row["name"]: row for row in upstream_dns.resolvers()}
        self.assertEqual(rows["Broken DoH"]["last_status"], "failed")
        self.assertIn("bootstrap resolution failed", rows["Broken DoH"]["last_message"])
        self.assertEqual(upstream_dns.last_deployment()["status"], "deployed")
        self.assertIn("deployed 2 of 3 enabled", upstream_dns.last_deployment()["message"])

    def test_doh_only_unresolvable_bootstrap_fails_safely(self) -> None:
        with sqlite3.connect(upstream_dns.DB_PATH) as conn:
            conn.execute("DELETE FROM upstream_resolvers")
            conn.execute(
                "INSERT INTO upstream_resolvers(name, protocol, address, port, doh_path, tls_hostname, bootstrap_ips, enabled, position, created_at, updated_at) "
                "VALUES ('Broken DoH', 'doh', 'broken.example', 443, '/dns-query', 'broken.example', '1.1.1.1', 1, 1, 'now', 'now')"
            )
            conn.commit()

        def fail_bootstrap(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:3] == ["dig", "@1.1.1.1", "broken.example"]:
                return subprocess.CompletedProcess(command, 0, "")
            return self.fake_run(command, check)

        with self.assertRaises(upstream_dns.UpstreamDNSError):
            with mock.patch.object(upstream_dns, "run", fail_bootstrap):
                upstream_dns.deploy_upstreams()

        self.assertEqual(upstream_dns.last_deployment()["status"], "rolled_back")
        rows = {row["name"]: row for row in upstream_dns.resolvers()}
        self.assertTrue(rows["Broken DoH"]["enabled"])
        self.assertEqual(rows["Broken DoH"]["last_status"], "failed")

    def test_failed_connectivity_rolls_back(self) -> None:
        with mock.patch.object(upstream_dns, "run", self.fake_run):
            upstream_dns.deploy_upstreams()
        good = upstream_dns.DNSDIST_UPSTREAM_CONF.read_text()

        def fail_dig(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["dig", "@127.0.0.1"]:
                return subprocess.CompletedProcess(command, 9, "SERVFAIL\n")
            return subprocess.CompletedProcess(command, 0, "ok\n")

        upstream_dns.add_resolver({"name": "bad", "protocol": "plain", "address": "192.0.2.53", "port": "53", "enabled": "1"})
        with self.assertRaises(RuntimeError):
            with mock.patch.object(upstream_dns, "run", fail_dig), \
                 mock.patch.object(upstream_dns, "POST_DEPLOY_CHECK_TIMEOUT_SECONDS", 0.2), \
                 mock.patch.object(upstream_dns, "POST_DEPLOY_CHECK_RETRY_INTERVAL_SECONDS", 0.05):
                upstream_dns.deploy_upstreams()
        self.assertEqual(upstream_dns.DNSDIST_UPSTREAM_CONF.read_text(), good)
        self.assertEqual(upstream_dns.last_deployment()["status"], "rolled_back")
        # The database still says every previously/still-enabled resolver
        # (including "bad") is enabled -- an ordinary failed activation must
        # never silently flip that -- but each row's own last_status/
        # last_message must truthfully say it failed to actually apply, so
        # the UI never shows a bare "enabled" checkbox with no indication
        # the live config disagrees.
        rows = {row["name"]: row for row in upstream_dns.resolvers()}
        self.assertTrue(rows["bad"]["enabled"])
        self.assertEqual(rows["bad"]["last_status"], "failed")
        self.assertIn("post-deploy upstream resolution failed", rows["bad"]["last_message"])

    def test_post_deploy_check_forces_fresh_resolution_not_stale_cache(self) -> None:
        """Regression test for the exact defect found live on dns1: a
        deployment could be recorded 'deployed' even though the newly
        staged upstream set was entirely unreachable, because the
        post-deploy check's `dig` query was answered from BIND's own
        resolver cache -- a leftover answer from a prior, genuinely good
        deploy -- rather than by an actual round trip through the freshly
        staged upstream chain.

        This fake `run()` models that cache explicitly: a `dig` reply only
        counts as fresh if a `rndc flushname` for TEST_DOMAIN happened
        immediately before it; otherwise it just replays whatever the last
        real answer was (exactly what a real cache would do). If
        deploy_upstreams() ever stopped flushing before checking, the
        second deploy below -- upstream now genuinely unreachable -- would
        incorrectly inherit the first deploy's cached success instead of
        failing and rolling back.
        """
        state = {"cached_answer": None, "reachable": True}

        def cache_aware_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["rndc", "flushname"]:
                state["cached_answer"] = None
                return subprocess.CompletedProcess(command, 0, "flushed\n")
            if command[:2] == ["dig", "@127.0.0.1"]:
                if state["cached_answer"] is not None:
                    return state["cached_answer"]
                if state["reachable"]:
                    answer = subprocess.CompletedProcess(command, 0, ";; ->>HEADER<<- status: NOERROR\ncloudflare.com.\t300\tIN\tA\t1.1.1.1\n")
                else:
                    answer = subprocess.CompletedProcess(command, 9, "SERVFAIL\n")
                state["cached_answer"] = answer
                return answer
            return subprocess.CompletedProcess(command, 0, "ok\n")

        with mock.patch.object(upstream_dns, "run", cache_aware_run):
            upstream_dns.deploy_upstreams()
        self.assertEqual(upstream_dns.last_deployment()["status"], "deployed")

        state["reachable"] = False
        with self.assertRaises(RuntimeError):
            with mock.patch.object(upstream_dns, "run", cache_aware_run), \
                 mock.patch.object(upstream_dns, "POST_DEPLOY_CHECK_TIMEOUT_SECONDS", 0.2), \
                 mock.patch.object(upstream_dns, "POST_DEPLOY_CHECK_RETRY_INTERVAL_SECONDS", 0.05):
                upstream_dns.deploy_upstreams()
        self.assertEqual(
            upstream_dns.last_deployment()["status"], "rolled_back",
            "an all-unreachable upstream set must never be recorded as a successful "
            "deployment merely because a stale cached answer was still lying around",
        )

    def test_resolvers_persist_after_new_connection(self) -> None:
        upstream_dns.add_resolver({"name": "Persisted", "protocol": "plain", "address": "8.8.8.8", "enabled": "1"})
        conn = sqlite3.connect(upstream_dns.DB_PATH)
        try:
            count = conn.execute("SELECT count(*) FROM upstream_resolvers WHERE name='Persisted'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
