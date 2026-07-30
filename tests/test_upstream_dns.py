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

    def test_render_doh_upstream_uses_dnsdist_tls_doh_backend(self) -> None:
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
        text = upstream_dns.render_dnsdist_upstreams(rows)
        self.assertIn('addLocal("127.0.0.1:5355"', text)
        self.assertIn('pool="alderpointdns_upstreams"', text)
        self.assertIn('address="1.1.1.1:443"', text)
        self.assertIn('tls="openssl"', text)
        self.assertIn('subjectName="cloudflare-dns.com"', text)
        self.assertIn('dohPath="/dns-query"', text)

    def test_deploy_multiple_enabled_resolvers(self) -> None:
        upstream_dns.add_resolver({"name": "Cloudflare DoH", "protocol": "doh", "address": "https://cloudflare-dns.com/dns-query", "bootstrap_ips": "1.1.1.1", "enabled": "1"})
        with mock.patch.object(upstream_dns, "run", self.fake_run):
            upstream_dns.deploy_upstreams()
        self.assertIn("forwarders port 5355", upstream_dns.BIND_FORWARDERS_CONF.read_text())
        dnsdist = upstream_dns.DNSDIST_UPSTREAM_CONF.read_text()
        self.assertIn("9.9.9.9:53", dnsdist)
        self.assertIn("1.1.1.1:443", dnsdist)
        self.assertEqual(upstream_dns.last_deployment()["status"], "deployed")

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
            with mock.patch.object(upstream_dns, "run", fail_dig):
                upstream_dns.deploy_upstreams()
        self.assertEqual(upstream_dns.DNSDIST_UPSTREAM_CONF.read_text(), good)
        self.assertEqual(upstream_dns.last_deployment()["status"], "rolled_back")

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
