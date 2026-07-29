#!/usr/bin/env python3
from __future__ import annotations

import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import importer, local_dns  # noqa: E402


class ImporterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="bindguard-importer-test-"))
        self.old_importer_db_path = importer.DB_PATH
        self.old_local_dns_db_path = local_dns.DB_PATH
        self.old_backup_script = importer.BACKUP_SCRIPT
        importer.DB_PATH = self.tmp / "bindguard.db"
        local_dns.DB_PATH = importer.DB_PATH
        importer.BACKUP_SCRIPT = self.tmp / "no-such-backup-script.sh"
        local_dns.STAGING_DIR = self.tmp / "staging"
        local_dns.BACKUP_DIR = self.tmp / "backups"
        local_dns.COMPILED_DIR = self.tmp / "compiled" / "bind"
        local_dns.LOCAL_ZONE_DIR = local_dns.COMPILED_DIR / "local"
        local_dns.LOCAL_ZONES_CONF = local_dns.COMPILED_DIR / "local-zones.conf"
        local_dns.NAMED_LOCAL_CONF = self.tmp / "named.conf.local"
        local_dns.STAGING_DIR.mkdir(parents=True)
        local_dns.NAMED_LOCAL_CONF.write_text(
            'acl "bindguard_clients" { localhost; };\nzone "bindguard.rpz" { type primary; file "bindguard.rpz"; };\n'
        )
        local_dns.init_db()
        importer.init_db()

    def tearDown(self) -> None:
        importer.DB_PATH = self.old_importer_db_path
        local_dns.DB_PATH = self.old_local_dns_db_path
        importer.BACKUP_SCRIPT = self.old_backup_script
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- parsing ---------------------------------------------------------

    def test_parse_csv_text(self) -> None:
        headers, rows = importer.parse_csv_text("hostname,ip\nalpha,172.16.43.10\n")
        self.assertEqual(headers, ["hostname", "ip"])
        self.assertEqual(rows, [{"hostname": "alpha", "ip": "172.16.43.10"}])

    def test_parse_hosts_text(self) -> None:
        rows = importer.parse_hosts_text("172.16.43.20 printer\n# comment\n172.16.43.21 nas nas-alias\n", "home.arpa")
        fqdns = {row["fqdn"] for row in rows}
        self.assertIn("printer.home.arpa", fqdns)
        self.assertIn("nas.home.arpa", fqdns)
        self.assertIn("nas-alias.home.arpa", fqdns)

    def test_parse_zone_text_basic_records(self) -> None:
        zone = "$ORIGIN example.home.\nwww 300 IN A 172.16.43.30\nmail AAAA fd00::30\nalias CNAME www.example.home.\n"
        rows = importer.parse_zone_text(zone, "home.arpa")
        by_name = {row["fqdn"]: row for row in rows}
        self.assertEqual(by_name["www.example.home"]["record_type"], "A")
        self.assertEqual(by_name["www.example.home"]["target"], "172.16.43.30")
        self.assertEqual(by_name["mail.example.home"]["record_type"], "AAAA")
        self.assertEqual(by_name["alias.example.home"]["record_type"], "CNAME")

    def test_parse_bindguard_csv(self) -> None:
        text = "fqdn,record_type,value,ttl,enabled,comment\nx.home.arpa,A,172.16.43.40,300,1,note\n"
        rows = importer.parse_bindguard_csv(text)
        self.assertEqual(rows[0]["fqdn"], "x.home.arpa")
        self.assertEqual(rows[0]["target"], "172.16.43.40")

    # -- column mapping ----------------------------------------------------

    def test_auto_map_columns_matches_common_aliases(self) -> None:
        mapping = importer.auto_map_columns(["Hostname", "IP Address", "Notes"])
        self.assertEqual(mapping["hostname"], "Hostname")
        self.assertEqual(mapping["ipv4"], "IP Address")
        self.assertEqual(mapping["comment"], "Notes")

    def test_apply_column_map_passthrough_for_canonical_rows(self) -> None:
        rows = [{"fqdn": "a.home.arpa", "record_type": "A", "target": "172.16.43.1", "ttl": "300", "comment": "", "enabled": "1", "hostname": "", "domain": "", "ipv4": "", "ipv6": "", "create_ptr": "", "client_alias": "", "client_id_or_cidr": ""}]
        out = importer.apply_column_map(rows, {})
        self.assertEqual(out[0]["fqdn"], "a.home.arpa")

    # -- job lifecycle: create, preview, apply, rollback --------------------

    def test_preview_classifies_valid_invalid_duplicate_conflict(self) -> None:
        local_dns.add_record("A", "existing.home.arpa", "172.16.43.99", 300, "", True)
        headers, rows = importer.parse_csv_text(
            "hostname,ip\n"
            "newhost,172.16.43.50\n"
            "newhost,172.16.43.50\n"
            "bad-host,not-an-ip\n"
            "existing,172.16.43.100\n"
        )
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        colmap = importer.auto_map_columns(headers)
        preview = importer.preview_job(job_id, colmap, "home.arpa")
        self.assertEqual(len(preview["valid"]), 1)
        self.assertEqual(len(preview["duplicates"]), 1)
        self.assertEqual(len(preview["invalid"]), 1)
        self.assertEqual(len(preview["conflicts"]), 1)

    def test_apply_job_skip_policy_leaves_conflicts_out(self) -> None:
        local_dns.add_record("A", "dup.home.arpa", "172.16.43.5", 300, "", True)
        headers, rows = importer.parse_csv_text("hostname,ip\ndup,172.16.43.6\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        result = importer.apply_job(job_id, default_policy="skip")
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["skipped"], 1)

    def test_apply_job_merge_policy_adds_alongside_existing(self) -> None:
        local_dns.add_record("A", "dup.home.arpa", "172.16.43.5", 300, "", True)
        headers, rows = importer.parse_csv_text("hostname,ip\ndup,172.16.43.6\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        result = importer.apply_job(job_id, default_policy="merge")
        self.assertEqual(result["applied"], 1)
        with local_dns.connect() as conn:
            count = conn.execute("SELECT count(*) FROM local_dns_records WHERE fqdn='dup.home.arpa' AND record_type='A'").fetchone()[0]
        self.assertEqual(count, 2)

    def test_apply_job_replace_policy_removes_prior_record(self) -> None:
        local_dns.add_record("A", "dup.home.arpa", "172.16.43.5", 300, "", True)
        headers, rows = importer.parse_csv_text("hostname,ip\ndup,172.16.43.6\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        result = importer.apply_job(job_id, default_policy="replace")
        self.assertEqual(result["applied"], 1)
        with local_dns.connect() as conn:
            rows_after = conn.execute("SELECT value FROM local_dns_records WHERE fqdn='dup.home.arpa' AND record_type='A'").fetchall()
        self.assertEqual(len(rows_after), 1)
        self.assertEqual(rows_after[0]["value"], "172.16.43.6")

    def test_apply_and_rollback_round_trip(self) -> None:
        headers, rows = importer.parse_csv_text("hostname,ip\nrollme,172.16.43.70\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        result = importer.apply_job(job_id, default_policy="skip")
        self.assertEqual(result["applied"], 1)
        with local_dns.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records WHERE fqdn='rollme.home.arpa'").fetchone()[0], 1)
        removed = importer.rollback_job(job_id)
        self.assertEqual(removed, 1)
        with local_dns.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records WHERE fqdn='rollme.home.arpa'").fetchone()[0], 0)
        job = importer.get_job(job_id)
        self.assertEqual(job["status"], "rolled_back")

    def test_apply_job_rejects_unknown_policy(self) -> None:
        headers, rows = importer.parse_csv_text("hostname,ip\nx,172.16.43.1\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        with self.assertRaises(importer.ImportError_):
            importer.apply_job(job_id, default_policy="bogus")

    def test_apply_job_never_overwrites_existing_record_silently(self) -> None:
        # An import that hits an existing hostname/record must not silently
        # replace it unless the operator explicitly chose merge or replace.
        local_dns.add_record("A", "silent.home.arpa", "172.16.43.9", 300, "original", True)
        headers, rows = importer.parse_csv_text("hostname,ip\nsilent,172.16.43.99\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        importer.apply_job(job_id, default_policy="skip")
        with local_dns.connect() as conn:
            row = conn.execute("SELECT value FROM local_dns_records WHERE fqdn='silent.home.arpa' AND record_type='A'").fetchone()
        self.assertEqual(row["value"], "172.16.43.9")

    # -- AdGuard translation -----------------------------------------------

    def test_translate_adguard_yaml_top_level_schema(self) -> None:
        text = (
            "filters:\n"
            "  - {name: EasyList, url: https://a.example/list.txt, enabled: true}\n"
            "whitelist_filters:\n"
            "  - {name: Allow, url: https://b.example/allow.txt}\n"
            "user_rules:\n"
            "  - '||ads.example^'\n"
            "  - '@@||safe.example^'\n"
            "filtering:\n"
            "  rewrites:\n"
            "    - {domain: nas.home, answer: 172.16.43.50}\n"
            "clients:\n"
            "  persistent:\n"
            "    - {name: Phone, ids: ['172.16.43.77'], filtering_enabled: true}\n"
        )
        result = importer.parse_adguard_yaml(text)
        self.assertEqual(result["blocklist_sources"][0]["url"], "https://a.example/list.txt")
        self.assertEqual(result["allowlist_unsupported"][0]["url"], "https://b.example/allow.txt")
        self.assertIn("ads.example", result["custom_block"])
        self.assertIn("safe.example", result["custom_allow"])
        self.assertEqual(result["rewrites_as_local_dns"][0]["fqdn"], "nas.home")
        self.assertEqual(result["clients_as_aliases"][0]["cidr_or_ip"], "172.16.43.77")
        self.assertTrue(any("filtering_enabled" in note for note in result["untranslatable"]))

    def test_translate_adguard_ignores_comments_and_cosmetic_rules(self) -> None:
        text = "user_rules:\n  - '! this is a comment'\n  - 'example.com##.ad-banner'\n"
        result = importer.parse_adguard_yaml(text)
        self.assertEqual(result["custom_block"], [])
        self.assertIn("example.com##.ad-banner", result["unsupported_rules"])

    def test_apply_adguard_translation_writes_expected_tables(self) -> None:
        translation = {
            "blocklist_sources": [{"name": "TestSrc", "url": "https://example.invalid/list.txt", "enabled": True}],
            "custom_allow": ["allow.example"],
            "custom_block": ["block.example"],
            "rewrites_as_local_dns": [{"fqdn": "rewrite.home.arpa", "record_type": "A", "value": "172.16.43.60"}],
            "clients_as_aliases": [{"display_name": "TestClient", "cidr_or_ip": "172.16.43.61", "all_ids": []}],
        }
        counts = importer.apply_adguard_translation(translation, {"blocklist_sources", "custom_rules", "rewrites", "clients"})
        self.assertEqual(counts, {"sources": 1, "custom_allow": 1, "custom_block": 1, "local_dns": 1, "aliases": 1})
        self.assertEqual(local_dns.alias_for_client("172.16.43.61"), "TestClient")

    def test_apply_adguard_translation_respects_group_selection(self) -> None:
        translation = {
            "blocklist_sources": [{"name": "TestSrc2", "url": "https://example.invalid/list2.txt", "enabled": True}],
            "custom_allow": [], "custom_block": [], "rewrites_as_local_dns": [], "clients_as_aliases": [],
        }
        counts = importer.apply_adguard_translation(translation, set())
        self.assertEqual(counts["sources"], 0)


if __name__ == "__main__":
    unittest.main()
