#!/usr/bin/env python3
from __future__ import annotations

import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
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

    def test_post_deploy_check_failure_raises_when_outbound_network_reachable(self) -> None:
        # A genuinely broken newly-staged upstream chain (the post-deploy
        # dig against 127.0.0.1 never returns a real answer) must still be
        # treated as a real deploy failure when this host can actually
        # reach the outside world -- this is the "real bug" branch that
        # the no-outbound-route degrade below must not accidentally
        # swallow.
        upstream_dns.add_resolver({"name": "Cloudflare DoH", "protocol": "doh", "address": "https://cloudflare-dns.com/dns-query", "bootstrap_ips": "1.1.1.1", "enabled": "1"})

        def broken_backend_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["dig", "@127.0.0.1"]:
                return subprocess.CompletedProcess(command, 1, "")
            return self.fake_run(command, check)

        with mock.patch.object(upstream_dns, "run", broken_backend_run), mock.patch.object(upstream_dns, "outbound_dns_reachable", lambda timeout=2.0: True):
            with self.assertRaises(RuntimeError):
                upstream_dns.deploy_upstreams()
        self.assertEqual(upstream_dns.last_deployment()["status"], "rolled_back")

    def test_post_deploy_check_failure_degrades_when_no_outbound_route(self) -> None:
        # The same broken-looking postcheck must NOT be reported as a
        # deploy failure when this environment genuinely has no outbound
        # network route at all (an offline CI sandbox, most notably) --
        # the public-domain postcheck could never have succeeded either
        # way, so it must not be able to fail (or roll back) an otherwise
        # correct deploy.
        upstream_dns.add_resolver({"name": "Cloudflare DoH", "protocol": "doh", "address": "https://cloudflare-dns.com/dns-query", "bootstrap_ips": "1.1.1.1", "enabled": "1"})

        def broken_backend_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["dig", "@127.0.0.1"]:
                return subprocess.CompletedProcess(command, 1, "")
            return self.fake_run(command, check)

        with mock.patch.object(upstream_dns, "run", broken_backend_run), mock.patch.object(upstream_dns, "outbound_dns_reachable", lambda timeout=2.0: False):
            upstream_dns.deploy_upstreams()
        deployment = upstream_dns.last_deployment()
        self.assertEqual(deployment["status"], "deployed")
        self.assertIn("postcheck skipped: no outbound network route", deployment["message"])

    def test_deploy_records_real_backend_latency_not_pool_check_duration(self) -> None:
        upstream_dns.add_resolver({"name": "Cloudflare DoH", "protocol": "doh", "address": "https://cloudflare-dns.com/dns-query", "bootstrap_ips": "1.1.1.1", "enabled": "1"})

        def latency_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["dnsdist", "-e"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "\n".join(
                        [
                            "0   Quad9                9.9.9.9:53                                      up     0.0       0          1          1          9       0   0.0   4.2     -           0 alderpointdns_upstreams",
                            "1   Quad9-secondary      149.112.112.112:53                              up     0.0       0          2          1          3       0   0.0   8.4     -           0 alderpointdns_upstreams",
                            "2   Cloudflare-DoH       104.16.248.249:443                              up     0.0       0          3          1          5       0   0.0     -  19.3           0 alderpointdns_upstreams",
                        ]
                    )
                    + "\n",
                )
            return self.fake_run(command, check)

        with mock.patch.object(upstream_dns, "run", latency_run):
            upstream_dns.deploy_upstreams()

        rows = {row["name"]: row for row in upstream_dns.resolvers()}
        self.assertEqual(rows["Imported upstream 1"]["last_latency_ms"], 4.2)
        self.assertEqual(rows["Imported upstream 2"]["last_latency_ms"], 8.4)
        self.assertEqual(rows["Cloudflare DoH"]["last_latency_ms"], 19.3)
        self.assertNotEqual(rows["Imported upstream 1"]["last_latency_ms"], rows["Imported upstream 2"]["last_latency_ms"])
        self.assertNotEqual(rows["Cloudflare DoH"]["last_latency_ms"], rows["Imported upstream 1"]["last_latency_ms"])

    def test_doh_backend_with_no_tcp_latency_sample_keeps_latency_empty(self) -> None:
        with sqlite3.connect(upstream_dns.DB_PATH) as conn:
            conn.execute("DELETE FROM upstream_resolvers")
            conn.execute(
                "INSERT INTO upstream_resolvers(name, protocol, address, port, doh_path, tls_hostname, bootstrap_ips, enabled, position, created_at, updated_at) "
                "VALUES ('Idle DoH', 'doh', 'cloudflare-dns.com', 443, '/dns-query', 'cloudflare-dns.com', '1.1.1.1', 1, 1, 'now', 'now')"
            )
            conn.commit()

        def no_sample_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            if command[:2] == ["dnsdist", "-e"]:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "0   Idle-DoH             104.16.248.249:443                              up     0.0       0          1          1          0       0   0.0     -     -           0 alderpointdns_upstreams\n",
                )
            return self.fake_run(command, check)

        with mock.patch.object(upstream_dns, "run", no_sample_run):
            upstream_dns.deploy_upstreams()

        row = upstream_dns.resolvers()[0]
        self.assertEqual(row["last_status"], "healthy")
        self.assertIsNone(row["last_latency_ms"])

    def test_disabled_resolver_display_state_does_not_show_stale_health_or_latency(self) -> None:
        resolver_id = upstream_dns.resolvers()[0]["id"]
        with sqlite3.connect(upstream_dns.DB_PATH) as conn:
            conn.execute(
                "UPDATE upstream_resolvers SET enabled=0, last_status='healthy', last_message='resolved through active upstream set', last_latency_ms=1286.7 WHERE id=?",
                (resolver_id,),
            )
            conn.commit()

        row = upstream_dns.display_resolvers()[0]
        self.assertEqual(row["display_status"], "disabled")
        self.assertEqual(row["display_message"], "Disabled")
        self.assertIsNone(row["display_latency_ms"])
        self.assertEqual(row["last_status"], "healthy")
        self.assertEqual(row["last_latency_ms"], 1286.7)

    def test_enabled_display_uses_probe_state_not_stale_deploy_or_dnsdist_traffic_latency(self) -> None:
        resolver_id = upstream_dns.resolvers()[0]["id"]
        with sqlite3.connect(upstream_dns.DB_PATH) as conn:
            conn.execute(
                """
                UPDATE upstream_resolvers
                SET enabled=1,
                    last_status='healthy',
                    last_message='dnsdist marked this upstream reachable',
                    last_latency_ms=1286.7,
                    probe_status='checking',
                    probe_message='',
                    probe_latency_ms=NULL
                WHERE id=?
                """,
                (resolver_id,),
            )
            conn.commit()

        row = upstream_dns.display_resolvers()[0]
        self.assertEqual(row["display_status"], "checking")
        self.assertEqual(row["display_message"], "No completed direct probe yet")
        self.assertIsNone(row["display_latency_ms"])

    def test_probe_results_are_isolated_per_provider(self) -> None:
        rows = upstream_dns.resolvers()
        upstream_dns.record_probe_result(rows[0]["id"], ok=True, latency_ms=11.1)
        upstream_dns.record_probe_result(rows[1]["id"], ok=True, latency_ms=22.2)

        displayed = {row["id"]: row for row in upstream_dns.display_resolvers()}
        self.assertEqual(displayed[rows[0]["id"]]["display_latency_ms"], 11.1)
        self.assertEqual(displayed[rows[1]["id"]]["display_latency_ms"], 22.2)
        self.assertNotEqual(displayed[rows[0]["id"]]["display_latency_ms"], displayed[rows[1]["id"]]["display_latency_ms"])

    def test_probe_telemetry_reports_rows_by_provider_id_without_probing(self) -> None:
        rows = upstream_dns.resolvers()
        upstream_dns.record_probe_result(rows[0]["id"], ok=True, latency_ms=11.1)
        upstream_dns.set_enabled(rows[1]["id"], False)

        with mock.patch.object(upstream_dns, "probe_resolver") as probe:
            telemetry = {row["id"]: row for row in upstream_dns.probe_telemetry()}

        probe.assert_not_called()
        self.assertEqual(telemetry[rows[0]["id"]]["status"], "healthy")
        self.assertEqual(telemetry[rows[0]["id"]]["label"], "Healthy")
        self.assertEqual(telemetry[rows[0]["id"]]["latency_ms"], 11.1)
        self.assertEqual(telemetry[rows[1]["id"]]["status"], "disabled")
        self.assertEqual(telemetry[rows[1]["id"]]["label"], "Disabled")
        self.assertIsNone(telemetry[rows[1]["id"]]["latency_ms"])

    def test_probe_failure_threshold_and_recovery(self) -> None:
        resolver_id = upstream_dns.resolvers()[0]["id"]
        upstream_dns.record_probe_result(resolver_id, ok=False, message="timeout")
        row = upstream_dns.display_resolvers()[0]
        self.assertEqual(row["display_status"], "checking")
        self.assertIsNone(row["display_latency_ms"])

        upstream_dns.record_probe_result(resolver_id, ok=False, message="timeout")
        upstream_dns.record_probe_result(resolver_id, ok=False, message="timeout")
        row = upstream_dns.display_resolvers()[0]
        self.assertEqual(row["display_status"], "failed")
        self.assertIn("timeout", row["display_message"])
        self.assertIsNone(row["display_latency_ms"])

        upstream_dns.record_probe_result(resolver_id, ok=True, latency_ms=7.5)
        row = upstream_dns.display_resolvers()[0]
        self.assertEqual(row["display_status"], "healthy")
        self.assertEqual(row["display_latency_ms"], 7.5)

    def test_lifecycle_resets_probe_state_for_enable_disable_add_edit(self) -> None:
        resolver_id = upstream_dns.resolvers()[0]["id"]
        upstream_dns.record_probe_result(resolver_id, ok=True, latency_ms=9.1)
        upstream_dns.set_enabled(resolver_id, False)
        row = upstream_dns.display_resolvers()[0]
        self.assertEqual(row["display_status"], "disabled")
        self.assertIsNone(row["display_latency_ms"])

        upstream_dns.set_enabled(resolver_id, True)
        row = upstream_dns.display_resolvers()[0]
        self.assertEqual(row["display_status"], "checking")
        self.assertIsNone(row["display_latency_ms"])

        upstream_dns.record_probe_result(resolver_id, ok=True, latency_ms=9.1)
        upstream_dns.update_resolver(resolver_id, {"name": "Edited arbitrary", "protocol": "plain", "address": "8.8.4.4", "port": "53", "enabled": "1"})
        row = upstream_dns.display_resolvers()[0]
        self.assertEqual(row["display_status"], "checking")
        self.assertIsNone(row["display_latency_ms"])

        added = upstream_dns.add_resolver({"name": "Arbitrary custom", "protocol": "plain", "address": "203.0.113.53", "port": "53", "enabled": "1"})
        rows = {row["id"]: row for row in upstream_dns.display_resolvers()}
        self.assertEqual(rows[added]["display_status"], "checking")
        upstream_dns.delete_resolver(added)
        self.assertNotIn(added, {row["id"] for row in upstream_dns.resolvers()})

    def test_probe_scheduler_dynamically_enumerates_and_staggers_enabled_rows(self) -> None:
        sequence = [
            [
                {"id": 1, "name": "alpha", "protocol": "plain", "address": "203.0.113.10", "port": 53, "position": 1, "enabled": 1},
                {"id": 2, "name": "beta", "protocol": "plain", "address": "203.0.113.11", "port": 53, "position": 2, "enabled": 1},
                {"id": 3, "name": "gamma", "protocol": "plain", "address": "203.0.113.12", "port": 53, "position": 3, "enabled": 1},
            ],
            [
                {"id": 2, "name": "beta", "protocol": "plain", "address": "203.0.113.11", "port": 53, "position": 2, "enabled": 1},
                {"id": 4, "name": "new arbitrary", "protocol": "plain", "address": "198.51.100.44", "port": 53, "position": 4, "enabled": 1},
            ],
        ]
        waits: list[float] = []
        probed: list[int] = []

        class StopAfterThree(threading.Event):
            def wait(self, timeout: float | None = None) -> bool:  # type: ignore[override]
                waits.append(float(timeout or 0))
                if len(waits) >= 3:
                    self.set()
                return self.is_set()

        def dynamic_rows() -> list[dict[str, object]]:
            return sequence[0] if len(probed) < 1 else sequence[1]

        with mock.patch.object(upstream_dns, "enabled_resolvers", dynamic_rows), \
             mock.patch.object(upstream_dns, "probe_and_record", lambda row, timeout=4.0: probed.append(int(row["id"]))):
            upstream_dns.upstream_probe_loop(StopAfterThree(), interval=30.0)

        self.assertEqual(probed, [1, 4, 2])
        self.assertEqual(waits[:3], [10.0, 15.0, 15.0])

    def test_probe_spacing_targets_thirty_seconds_per_provider_for_normal_counts(self) -> None:
        self.assertEqual(upstream_dns.probe_spacing_seconds(1), 30.0)
        self.assertEqual(upstream_dns.probe_spacing_seconds(3), 10.0)
        self.assertEqual(upstream_dns.probe_spacing_seconds(6), 5.0)

    def test_probe_spacing_enforces_minimum_global_spacing_for_large_counts(self) -> None:
        self.assertEqual(upstream_dns.probe_spacing_seconds(10), 5.0)
        self.assertEqual(upstream_dns.probe_spacing_seconds(12), 5.0)
        self.assertEqual(upstream_dns.probe_spacing_seconds(20), 5.0)
        self.assertEqual(upstream_dns.probe_spacing_seconds(60), 5.0)
        self.assertEqual(upstream_dns.probe_spacing_seconds(300), 5.0)

        self.assertEqual(upstream_dns.probe_spacing_seconds(10) * 10, 50.0)
        self.assertEqual(upstream_dns.probe_spacing_seconds(12) * 12, 60.0)
        self.assertEqual(upstream_dns.probe_spacing_seconds(20) * 20, 100.0)

    def test_scheduler_never_catches_up_with_multi_probe_burst_after_restart_or_delay(self) -> None:
        rows = [
            {"id": idx, "name": f"resolver-{idx}", "protocol": "plain", "address": f"203.0.113.{idx}", "port": 53, "position": idx, "enabled": 1}
            for idx in range(1, 61)
        ]
        waits: list[float] = []
        probed: list[int] = []

        class StopAfterFourWaits(threading.Event):
            def wait(self, timeout: float | None = None) -> bool:  # type: ignore[override]
                waits.append(float(timeout or 0))
                if len(waits) >= 4:
                    self.set()
                return self.is_set()

        with mock.patch.object(upstream_dns, "enabled_resolvers", return_value=rows), \
             mock.patch.object(upstream_dns, "probe_and_record", lambda row, timeout=4.0: probed.append(int(row["id"]))):
            upstream_dns.upstream_probe_loop(StopAfterFourWaits(), interval=30.0)

        self.assertEqual(probed, [1, 2, 3, 4])
        self.assertEqual(waits, [5.0, 5.0, 5.0, 5.0])
        self.assertEqual(len(probed), len(waits))

    def test_dynamic_provider_changes_keep_one_probe_per_spacing_without_burst(self) -> None:
        large_set = [
            {"id": idx, "name": f"resolver-{idx}", "protocol": "plain", "address": f"198.51.100.{idx}", "port": 53, "position": idx, "enabled": 1}
            for idx in range(1, 21)
        ]
        small_set = large_set[:3]
        waits: list[float] = []
        probed: list[int] = []

        class StopAfterFourWaits(threading.Event):
            def wait(self, timeout: float | None = None) -> bool:  # type: ignore[override]
                waits.append(float(timeout or 0))
                if len(waits) >= 4:
                    self.set()
                return self.is_set()

        def dynamic_rows() -> list[dict[str, object]]:
            return large_set if len(probed) < 2 else small_set

        with mock.patch.object(upstream_dns, "enabled_resolvers", dynamic_rows), \
             mock.patch.object(upstream_dns, "probe_and_record", lambda row, timeout=4.0: probed.append(int(row["id"]))):
            upstream_dns.upstream_probe_loop(StopAfterFourWaits(), interval=30.0)

        self.assertEqual(probed, [1, 2, 3, 1])
        self.assertEqual(waits, [5.0, 5.0, 10.0, 10.0])
        self.assertEqual(len(probed), len(waits))

    def test_probe_protocol_dispatch_uses_direct_protocol_implementation(self) -> None:
        rows = {
            "plain": {"id": 1, "protocol": "plain", "address": "203.0.113.1", "port": 53},
            "dot": {"id": 2, "protocol": "dot", "address": "dns.example", "port": 853, "tls_hostname": "dns.example"},
            "doh": {"id": 3, "protocol": "doh", "address": "dns.example", "port": 443, "tls_hostname": "dns.example", "doh_path": "/dns-query/secret", "bootstrap_ips": "198.51.100.1"},
        }
        with mock.patch.object(upstream_dns, "_probe_plain_dns", return_value=(1.0, b"", 1)) as plain, \
             mock.patch.object(upstream_dns, "_probe_dot", return_value=2.0) as dot, \
             mock.patch.object(upstream_dns, "_probe_doh", return_value=3.0) as doh:
            self.assertEqual(upstream_dns.probe_resolver(rows["plain"]), 1.0)
            self.assertEqual(upstream_dns.probe_resolver(rows["dot"]), 2.0)
            self.assertEqual(upstream_dns.probe_resolver(rows["doh"]), 3.0)
        plain.assert_called_once()
        dot.assert_called_once_with(rows["dot"], timeout=upstream_dns.UPSTREAM_PROBE_TIMEOUT_SECONDS)
        doh.assert_called_once_with(rows["doh"], timeout=upstream_dns.UPSTREAM_PROBE_TIMEOUT_SECONDS)

    def test_doh_bootstrap_ips_are_only_used_for_hostname_resolution(self) -> None:
        row = {"protocol": "doh", "address": "dns.example", "bootstrap_ips": "198.51.100.1, 198.51.100.2"}
        qid, query = upstream_dns._build_dns_query(upstream_dns.TEST_DOMAIN, 1, query_id=0x1234)
        response = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
        response += query[12:]
        response += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 99])
        calls: list[tuple[str, int]] = []

        def fake_plain(address: str, port: int, *, timeout: float = 4.0, qtype: int = 1, qname: str = upstream_dns.TEST_DOMAIN):
            calls.append((address, qtype, qname))
            return 1.0, response, qid

        with mock.patch.object(upstream_dns, "_probe_plain_dns", fake_plain):
            self.assertEqual(upstream_dns._bootstrap_resolve_for_probe(row), "203.0.113.99")

        self.assertEqual(calls, [("198.51.100.1", 1, "dns.example")])

    def test_doh_direct_probe_request_uses_resolved_ip_authority_path_and_dns_message_headers(self) -> None:
        row = {
            "protocol": "doh",
            "address": "arbitrary.example",
            "port": 443,
            "tls_hostname": "arbitrary.example",
            "doh_path": "/private-doh-token",
            "bootstrap_ips": "198.51.100.1",
        }
        sent: list[bytes] = []
        connected: list[tuple[str, int]] = []
        wrapped: list[str] = []
        qid, packet = upstream_dns._build_dns_query("cloudflare.com", 1, query_id=0xBEEF)

        class FakeTLSSocket:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback) -> None:
                return None

            def sendall(self, data: bytes) -> None:
                sent.append(data)

        class FakeRawSocket:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback) -> None:
                return None

            def settimeout(self, timeout: float) -> None:
                pass

            def connect(self, address: tuple[str, int]) -> None:
                connected.append(address)

        class FakeSSLContext:
            def wrap_socket(self, raw, server_hostname: str):
                wrapped.append(server_hostname)
                return FakeTLSSocket()

        with mock.patch.object(upstream_dns, "_bootstrap_resolve_for_probe", return_value="203.0.113.44"), \
             mock.patch.object(upstream_dns, "_build_dns_query", return_value=(qid, packet)), \
             mock.patch.object(upstream_dns.socket, "socket", FakeRawSocket), \
             mock.patch.object(upstream_dns.ssl, "create_default_context", return_value=FakeSSLContext()), \
             mock.patch.object(upstream_dns, "_read_http_response", return_value=(200, packet)), \
             mock.patch.object(upstream_dns, "_validate_dns_response") as validate:
            upstream_dns._probe_doh(row)

        self.assertEqual(connected, [("203.0.113.44", 443)])
        self.assertEqual(wrapped, ["arbitrary.example"])
        request = sent[0]
        headers, body = request.split(b"\r\n\r\n", 1)
        self.assertIn(b"POST /private-doh-token HTTP/1.1", headers)
        self.assertIn(b"Host: arbitrary.example", headers)
        self.assertIn(b"Accept: application/dns-message", headers)
        self.assertIn(b"Content-Type: application/dns-message", headers)
        self.assertEqual(body, packet)
        validate.assert_called_once_with(packet, qid)

    def test_doh_probe_trace_redacts_path_and_reports_generic_authority(self) -> None:
        trace = upstream_dns.doh_probe_request_trace(
            {
                "protocol": "doh",
                "address": "resolver.example",
                "port": 8443,
                "tls_hostname": "resolver.example",
                "doh_path": "/dns-query/super-secret-token",
            },
            endpoint_ip="203.0.113.44",
        )
        self.assertEqual(trace["tcp_destination"], "203.0.113.44:8443")
        self.assertEqual(trace["tls_sni"], "resolver.example")
        self.assertEqual(trace["http_authority"], "resolver.example:8443")
        self.assertEqual(trace["http_path"], "<redacted>")
        self.assertNotIn("super-secret-token", str(trace))
        self.assertEqual(trace["accept"], "application/dns-message")
        self.assertEqual(trace["content_type"], "application/dns-message")


    def test_private_doh_path_is_redacted_from_probe_failure_messages(self) -> None:
        resolver_id = upstream_dns.add_resolver(
            {
                "name": "Private DoH",
                "protocol": "doh",
                "address": "dns.example",
                "port": "443",
                "doh_path": "/dns-query/super-secret-token",
                "tls_hostname": "dns.example",
                "bootstrap_ips": "198.51.100.1",
                "enabled": "1",
            }
        )
        for _ in range(upstream_dns.UPSTREAM_PROBE_FAILURE_THRESHOLD):
            upstream_dns.record_probe_result(resolver_id, ok=False, message="POST /dns-query/super-secret-token failed")
        row = {row["id"]: row for row in upstream_dns.display_resolvers()}[resolver_id]
        self.assertNotIn("super-secret-token", row["display_message"])
        self.assertIn("/dns-query/...", row["display_message"])

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
