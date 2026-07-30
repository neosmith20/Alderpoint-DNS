#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import analytics, alderpointdns_compiler, local_dns  # noqa: E402


class LocalDNSTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-localdns-test-"))
        self.old = {
            "DB_PATH": local_dns.DB_PATH,
            "COMPILED_DIR": local_dns.COMPILED_DIR,
            "LOCAL_ZONE_DIR": local_dns.LOCAL_ZONE_DIR,
            "LOCAL_ZONES_CONF": local_dns.LOCAL_ZONES_CONF,
            "NAMED_LOCAL_CONF": local_dns.NAMED_LOCAL_CONF,
            "BACKUP_DIR": local_dns.BACKUP_DIR,
            "STAGING_DIR": local_dns.STAGING_DIR,
            "ANALYTICS_DB_PATH": analytics.DB_PATH,
            "COMPILER_DB_PATH": alderpointdns_compiler.DB_PATH,
        }
        local_dns.DB_PATH = self.tmp / "alderpointdns.db"
        local_dns.COMPILED_DIR = self.tmp / "compiled" / "bind"
        local_dns.LOCAL_ZONE_DIR = local_dns.COMPILED_DIR / "local"
        local_dns.LOCAL_ZONES_CONF = local_dns.COMPILED_DIR / "local-zones.conf"
        local_dns.NAMED_LOCAL_CONF = self.tmp / "named.conf.local"
        local_dns.BACKUP_DIR = self.tmp / "backups"
        local_dns.STAGING_DIR = self.tmp / "staging"
        analytics.DB_PATH = local_dns.DB_PATH
        alderpointdns_compiler.DB_PATH = local_dns.DB_PATH
        local_dns.STAGING_DIR.mkdir(parents=True)
        local_dns.NAMED_LOCAL_CONF.write_text(
            'acl "alderpointdns_clients" { localhost; };\nzone "alderpointdns.rpz" { type primary; file "alderpointdns.rpz"; };\n'
        )
        local_dns.init_db()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            if key == "ANALYTICS_DB_PATH":
                analytics.DB_PATH = value
            elif key == "COMPILER_DB_PATH":
                alderpointdns_compiler.DB_PATH = value
            else:
                setattr(local_dns, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def fake_run(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        text = "ok\n"
        if command[0] == "named-checkzone" and "invalid zone record" in Path(command[2]).read_text():
            if check:
                raise subprocess.CalledProcessError(1, command, "zone invalid")
            return subprocess.CompletedProcess(command, 1, "zone invalid")
        if command[0] == "dig" and "+short" in command:
            if "-x" in command:
                text = "alex-pc.home.arpa.\n"
            elif "adguard.internal.example" in command:
                text = "192.168.1.10\n"
            elif "AAAA" in command:
                text = "fd00::50\n"
            else:
                text = "192.168.1.50\n"
        return subprocess.CompletedProcess(command, 0, text)

    def test_a_record_creation_and_automatic_ptr(self) -> None:
        local_dns.add_host("alex-pc", "home.arpa", "192.168.1.50", 300, "desktop", True)
        with local_dns.connect() as conn:
            rows = conn.execute("SELECT record_type, fqdn, value, ptr_record_id FROM local_dns_records ORDER BY record_type").fetchall()
        self.assertEqual(rows[0]["record_type"], "A")
        self.assertEqual(rows[0]["fqdn"], "alex-pc.home.arpa")
        self.assertEqual(rows[1]["record_type"], "PTR")
        self.assertEqual(rows[1]["fqdn"], "50.1.168.192.in-addr.arpa")
        self.assertEqual(rows[1]["value"], "alex-pc.home.arpa")
        self.assertTrue(rows[0]["ptr_record_id"])

    def test_aaaa_record_creation(self) -> None:
        local_dns.add_host("v6-host", "home.arpa", "fd00::50", 300, "", True)
        with local_dns.connect() as conn:
            row = conn.execute("SELECT record_type, value FROM local_dns_records WHERE record_type='AAAA'").fetchone()
        self.assertEqual(dict(row), {"record_type": "AAAA", "value": "fd00::50"})

    def test_invalid_hostname_and_ip_rejected(self) -> None:
        with self.assertRaises(local_dns.LocalDNSError):
            local_dns.add_host("bad_name", "home.arpa", "192.168.1.50")
        with self.assertRaises(ValueError):
            local_dns.add_host("ok", "home.arpa", "not-an-ip")

    def test_duplicate_hostname_warning_can_be_overridden(self) -> None:
        local_dns.add_host("alex-pc", "home.arpa", "192.168.1.50", auto_ptr=False)
        with self.assertRaises(local_dns.LocalDNSError):
            local_dns.add_host("alex-pc", "home.arpa", "192.168.1.51", auto_ptr=False)
        local_dns.add_host("alex-pc", "home.arpa", "192.168.1.51", auto_ptr=False, override=True)

    def test_duplicate_ptr_warning(self) -> None:
        local_dns.add_host("one", "home.arpa", "192.168.1.50", auto_ptr=True)
        with self.assertRaises(local_dns.LocalDNSError):
            local_dns.add_host("two", "home.arpa", "192.168.1.50", auto_ptr=True)

    def test_cname_conflict_detection(self) -> None:
        local_dns.add_host("target", "home.arpa", "192.168.1.50", auto_ptr=False)
        with self.assertRaises(local_dns.LocalDNSError):
            local_dns.add_record("CNAME", "target.home.arpa", "other.home.arpa")

    def test_record_edit_delete_and_disable(self) -> None:
        local_dns.add_record("A", "edit.home.arpa", "192.168.1.60")
        row_id = local_dns.list_records()["records"][0]["id"]
        local_dns.update_record(row_id, "A", "edit.home.arpa", "192.168.1.61", 600, "changed", True, True)
        local_dns.toggle_record(row_id)
        self.assertFalse(local_dns.list_records()["records"][0]["enabled"])
        local_dns.delete_record(row_id)
        self.assertEqual(local_dns.list_records()["records"], [])

    def test_multiple_local_subnets_and_zone_rendering(self) -> None:
        local_dns.add_host("one", "home.arpa", "192.168.1.50", auto_ptr=True)
        local_dns.add_host("two", "home.arpa", "10.10.9.8", auto_ptr=True)
        with local_dns.connect() as conn:
            zones = local_dns.build_zone_files(conn, self.tmp / "stage", 2026072901)
        names = {zone.zone for zone in zones}
        self.assertIn("home.arpa", names)
        self.assertIn("1.168.192.in-addr.arpa", names)
        self.assertIn("9.10.10.in-addr.arpa", names)

    def test_external_fqdn_records_create_managed_forward_zone(self) -> None:
        local_dns.add_record("A", "adguard.internal.example", "192.168.1.10")
        with local_dns.connect() as conn:
            zones = local_dns.build_zone_files(conn, self.tmp / "stage", 2026072901)
        by_name = {zone.zone: zone.text for zone in zones}
        self.assertIn("home.arpa", by_name)
        self.assertIn("internal.example", by_name)
        self.assertIn("$ORIGIN internal.example.", by_name["internal.example"])
        self.assertIn("adguard 300 IN A 192.168.1.10", by_name["internal.example"])

    def test_zone_serial_increment(self) -> None:
        with local_dns.connect() as conn:
            first = local_dns.next_serial(conn)
            conn.execute(
                "INSERT INTO local_dns_deployments(started_at, finished_at, status, serial) VALUES (?, ?, 'deployed', ?)",
                (local_dns.now(), local_dns.now(), first),
            )
            second = local_dns.next_serial(conn)
        self.assertGreater(second, first)

    def test_invalid_generated_zone_rolls_back(self) -> None:
        local_dns.add_host("alex-pc", "home.arpa", "192.168.1.50", auto_ptr=True)
        with mock.patch.object(local_dns, "run", self.fake_run):
            local_dns.deploy_zones()
        before = local_dns.LOCAL_ZONES_CONF.read_text()
        os.environ["ALDERPOINTDNS_TEST_INVALID_LOCAL_ZONE"] = "1"
        try:
            with self.assertRaises(subprocess.CalledProcessError):
                with mock.patch.object(local_dns, "run", self.fake_run):
                    local_dns.deploy_zones()
        finally:
            os.environ.pop("ALDERPOINTDNS_TEST_INVALID_LOCAL_ZONE", None)
        self.assertEqual(local_dns.LOCAL_ZONES_CONF.read_text(), before)

    def test_deploy_flushes_dnsdist_packet_cache_for_local_zones(self) -> None:
        local_dns.add_record("A", "adguard.internal.example", "192.168.1.10")
        commands = []

        def recording_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            return self.fake_run(command, check)

        with mock.patch.object(local_dns, "run", recording_run):
            local_dns.deploy_zones()
        executed = [" ".join(command) for command in commands]
        self.assertTrue(any('pc:expungeByName("internal.example.", DNSQType.ANY, true)' in command for command in executed))
        self.assertTrue(any('pc:expungeByName("home.arpa.", DNSQType.ANY, true)' in command for command in executed))

    def test_dns_validation_retries_transient_forward_failure(self) -> None:
        local_dns.add_record("A", "adguard.internal.example", "192.168.1.10")
        calls = []

        def flaky_run(command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
            calls.append(command)
            if len(calls) == 1:
                return subprocess.CompletedProcess(command, 0, "")
            return subprocess.CompletedProcess(command, 0, "192.168.1.10\n")

        with local_dns.connect() as conn:
            with mock.patch.object(local_dns, "run", flaky_run), mock.patch.object(local_dns.time, "sleep"):
                local_dns.validate_dns_results(conn)
        self.assertGreaterEqual(len(calls), 2)

    def test_client_alias_and_ptr_fallback_display(self) -> None:
        local_dns.add_host("alex-pc", "home.arpa", "192.168.1.50", auto_ptr=True)
        self.assertEqual(local_dns.alias_for_client("192.168.1.50"), "alex-pc.home.arpa (192.168.1.50)")
        local_dns.upsert_alias("192.168.1.50", "Alex-PC", "desktop")
        self.assertEqual(local_dns.alias_for_client("192.168.1.50"), "Alex-PC")

    def test_csv_preview_import_export(self) -> None:
        text = "fqdn,record_type,value,ttl,enabled,comment\ncsv.home.arpa,A,192.168.1.70,300,1,imported\n"
        preview = local_dns.csv_preview(text)
        self.assertTrue(preview[0]["valid"])
        self.assertEqual(local_dns.csv_import(text), 1)
        self.assertIn("csv.home.arpa,A,192.168.1.70", local_dns.csv_export())

    def test_hosts_preview(self) -> None:
        preview = local_dns.hosts_preview("192.168.1.80 printer printer.home.arpa", "home.arpa")
        self.assertTrue(preview[0]["valid"])
        self.assertEqual(len(preview[0]["records"]), 2)

    def test_analytics_client_aliases(self) -> None:
        analytics.init_analytics_db()
        local_dns.upsert_alias("192.168.1.101", "Alderpoint DNS", "")
        with analytics.connect() as conn:
            analytics.insert_events(conn, [analytics.QueryEvent(analytics.utc_now(), "192.168.1.101", "x.home.arpa", "A", "UDP", "NOERROR", None, False)], True)
        data = analytics.dashboard_data("24h")
        self.assertEqual(data["top_clients"][0]["label"], "Alderpoint DNS")
        log = analytics.query_log({}, 1, 10)
        self.assertEqual(log["rows"][0]["client_display"], "Alderpoint DNS")


if __name__ == "__main__":
    unittest.main()
