#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import alderpointdns_compiler, custom_rules, importer, local_dns, upstream_dns  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ADGUARD_FIXTURE = (FIXTURES / "adguard_home.yaml").read_text()
PIHOLE_FIXTURE = (FIXTURES / "pihole_export.txt").read_text()


class ImporterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-importer-test-"))
        self.old_importer_db_path = importer.DB_PATH
        self.old_local_dns_db_path = local_dns.DB_PATH
        self.old_upstream_dns_db_path = upstream_dns.DB_PATH
        self.old_compiler_db_path = alderpointdns_compiler.DB_PATH
        self.old_custom_rules_db_path = custom_rules.DB_PATH
        self.old_upload_dir = importer.IMPORT_UPLOAD_DIR
        importer.DB_PATH = self.tmp / "alderpointdns.db"
        local_dns.DB_PATH = importer.DB_PATH
        upstream_dns.DB_PATH = importer.DB_PATH
        alderpointdns_compiler.DB_PATH = importer.DB_PATH
        custom_rules.DB_PATH = importer.DB_PATH
        # create_pre_import_backup() runs the privileged
        # `sudo alderpointdns_compiler.py backup-create` command; stub the
        # single subprocess.run call site so tests never invoke real sudo.
        self._backup_patcher = mock.patch.object(
            importer.subprocess, "run",
            return_value=subprocess.CompletedProcess(importer.PRE_IMPORT_BACKUP_COMMAND, 0, "backup_path=/tmp/pre-import-backup.tar\n", ""),
        )
        self._backup_patcher.start()
        importer.IMPORT_UPLOAD_DIR = self.tmp / "imports"
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
        local_dns.init_db()
        upstream_dns.init_db()
        alderpointdns_compiler.init_db()
        importer.init_db()
        custom_rules.init_db()

    def tearDown(self) -> None:
        importer.DB_PATH = self.old_importer_db_path
        local_dns.DB_PATH = self.old_local_dns_db_path
        upstream_dns.DB_PATH = self.old_upstream_dns_db_path
        alderpointdns_compiler.DB_PATH = self.old_compiler_db_path
        custom_rules.DB_PATH = self.old_custom_rules_db_path
        self._backup_patcher.stop()
        importer.IMPORT_UPLOAD_DIR = self.old_upload_dir
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(importer.DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def destination_counts(self) -> dict[str, int]:
        with self.connect() as conn:
            return {
                table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in ("sources", "custom_filter_rules", "custom_rules", "local_dns_records", "upstream_resolvers", "client_aliases")
            }

    @staticmethod
    def summary_items(summary: dict, category: str) -> list[dict]:
        for section in summary["categories"]:
            if section["name"] == category:
                return section["items"]
        return []

    # -- parsing ---------------------------------------------------------

    def test_parse_csv_text(self) -> None:
        headers, rows = importer.parse_csv_text("hostname,ip\nalpha,192.168.1.10\n")
        self.assertEqual(headers, ["hostname", "ip"])
        self.assertEqual(rows, [{"hostname": "alpha", "ip": "192.168.1.10"}])

    def test_parse_hosts_text(self) -> None:
        rows = importer.parse_hosts_text("192.168.1.20 printer\n# comment\n192.168.1.21 nas nas-alias\n", "home.arpa")
        fqdns = {row["fqdn"] for row in rows}
        self.assertIn("printer.home.arpa", fqdns)
        self.assertIn("nas.home.arpa", fqdns)
        self.assertIn("nas-alias.home.arpa", fqdns)

    def test_parse_zone_text_basic_records(self) -> None:
        zone = "$ORIGIN example.home.\nwww 300 IN A 192.168.1.30\nmail AAAA fd00::30\nalias CNAME www.example.home.\n"
        rows = importer.parse_zone_text(zone, "home.arpa")
        by_name = {row["fqdn"]: row for row in rows}
        self.assertEqual(by_name["www.example.home"]["record_type"], "A")
        self.assertEqual(by_name["www.example.home"]["target"], "192.168.1.30")
        self.assertEqual(by_name["mail.example.home"]["record_type"], "AAAA")
        self.assertEqual(by_name["alias.example.home"]["record_type"], "CNAME")

    def test_parse_alderpointdns_csv(self) -> None:
        text = "fqdn,record_type,value,ttl,enabled,comment\nx.home.arpa,A,192.168.1.40,300,1,note\n"
        rows = importer.parse_alderpointdns_csv(text)
        self.assertEqual(rows[0]["fqdn"], "x.home.arpa")
        self.assertEqual(rows[0]["target"], "192.168.1.40")

    def test_parse_pihole_text_practical_exports(self) -> None:
        result = importer.parse_pihole_text(
            "https://example.invalid/adlist.txt\n"
            "whitelist safe.example\n"
            "blacklist bad.example\n"
            "192.168.1.90 printer\n"
            "plainblock.example\n"
            "%% not pihole syntax %%\n",
            "home.arpa",
        )
        self.assertEqual(result["blocklist_sources"][0]["url"], "https://example.invalid/adlist.txt")
        rules = {entry["text"]: entry for entry in result["custom_rules"]}
        self.assertEqual(rules["whitelist safe.example"]["rule"], "@@safe.example")
        self.assertFalse(rules["whitelist safe.example"]["plain_domain_subdomains"])
        self.assertEqual(rules["blacklist bad.example"]["rule"], "bad.example")
        self.assertEqual(rules["plainblock.example"]["rule"], "plainblock.example")
        self.assertFalse(rules["plainblock.example"]["plain_domain_subdomains"])
        self.assertEqual(result["rewrites_as_local_dns"][0]["fqdn"], "printer.home.arpa")
        self.assertEqual(len(result["unsupported_rules"]), 1)
        self.assertIn("%% not pihole syntax %%", result["unsupported_rules"][0])

    def test_stage_uploaded_source_sanitizes_name_and_limits_size(self) -> None:
        path = importer.stage_uploaded_source("../../bad name.txt", b"content")
        self.assertEqual(path.parent, importer.IMPORT_UPLOAD_DIR)
        self.assertTrue(path.name.endswith("bad-name.txt"))
        with self.assertRaises(importer.ImportError_):
            importer.stage_uploaded_source("too-big.txt", b"x" * (importer.MAX_UPLOAD_BYTES + 1))

    # -- column mapping ----------------------------------------------------

    def test_auto_map_columns_matches_common_aliases(self) -> None:
        mapping = importer.auto_map_columns(["Hostname", "IP Address", "Notes"])
        self.assertEqual(mapping["hostname"], "Hostname")
        self.assertEqual(mapping["ipv4"], "IP Address")
        self.assertEqual(mapping["comment"], "Notes")

    def test_apply_column_map_passthrough_for_canonical_rows(self) -> None:
        rows = [{"fqdn": "a.home.arpa", "record_type": "A", "target": "192.168.1.1", "ttl": "300", "comment": "", "enabled": "1", "hostname": "", "domain": "", "ipv4": "", "ipv6": "", "create_ptr": "", "client_alias": "", "client_id_or_cidr": ""}]
        out = importer.apply_column_map(rows, {})
        self.assertEqual(out[0]["fqdn"], "a.home.arpa")

    # -- job lifecycle: create, preview, apply, rollback --------------------

    def test_preview_classifies_valid_invalid_duplicate_conflict(self) -> None:
        local_dns.add_record("A", "existing.home.arpa", "192.168.1.99", 300, "", True)
        headers, rows = importer.parse_csv_text(
            "hostname,ip\n"
            "newhost,192.168.1.50\n"
            "newhost,192.168.1.50\n"
            "bad-host,not-an-ip\n"
            "existing,192.168.1.100\n"
        )
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        colmap = importer.auto_map_columns(headers)
        preview = importer.preview_job(job_id, colmap, "home.arpa")
        self.assertEqual(len(preview["valid"]), 1)
        self.assertEqual(len(preview["duplicates"]), 1)
        self.assertEqual(len(preview["invalid"]), 1)
        self.assertEqual(len(preview["conflicts"]), 1)

    def test_apply_job_skip_policy_leaves_conflicts_out(self) -> None:
        local_dns.add_record("A", "dup.home.arpa", "192.168.1.5", 300, "", True)
        headers, rows = importer.parse_csv_text("hostname,ip\ndup,192.168.1.6\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        result = importer.apply_job(job_id, default_policy="skip")
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["skipped"], 1)

    def test_apply_job_merge_policy_adds_alongside_existing(self) -> None:
        local_dns.add_record("A", "dup.home.arpa", "192.168.1.5", 300, "", True)
        headers, rows = importer.parse_csv_text("hostname,ip\ndup,192.168.1.6\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        result = importer.apply_job(job_id, default_policy="merge")
        self.assertEqual(result["applied"], 1)
        with local_dns.connect() as conn:
            count = conn.execute("SELECT count(*) FROM local_dns_records WHERE fqdn='dup.home.arpa' AND record_type='A'").fetchone()[0]
        self.assertEqual(count, 2)

    def test_apply_job_replace_policy_removes_prior_record(self) -> None:
        local_dns.add_record("A", "dup.home.arpa", "192.168.1.5", 300, "", True)
        headers, rows = importer.parse_csv_text("hostname,ip\ndup,192.168.1.6\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        result = importer.apply_job(job_id, default_policy="replace")
        self.assertEqual(result["applied"], 1)
        with local_dns.connect() as conn:
            rows_after = conn.execute("SELECT value FROM local_dns_records WHERE fqdn='dup.home.arpa' AND record_type='A'").fetchall()
        self.assertEqual(len(rows_after), 1)
        self.assertEqual(rows_after[0]["value"], "192.168.1.6")

    def test_apply_and_rollback_round_trip(self) -> None:
        headers, rows = importer.parse_csv_text("hostname,ip\nrollme,192.168.1.70\n")
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
        headers, rows = importer.parse_csv_text("hostname,ip\nx,192.168.1.1\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        with self.assertRaises(importer.ImportError_):
            importer.apply_job(job_id, default_policy="bogus")

    def test_apply_job_never_overwrites_existing_record_silently(self) -> None:
        # An import that hits an existing hostname/record must not silently
        # replace it unless the operator explicitly chose merge or replace.
        local_dns.add_record("A", "silent.home.arpa", "192.168.1.9", 300, "original", True)
        headers, rows = importer.parse_csv_text("hostname,ip\nsilent,192.168.1.99\n")
        job_id = importer.create_job("csv", "t.csv", headers, rows)
        importer.preview_job(job_id, importer.auto_map_columns(headers), "home.arpa")
        importer.apply_job(job_id, default_policy="skip")
        with local_dns.connect() as conn:
            row = conn.execute("SELECT value FROM local_dns_records WHERE fqdn='silent.home.arpa' AND record_type='A'").fetchone()
        self.assertEqual(row["value"], "192.168.1.9")

    # -- AdGuard translation -----------------------------------------------

    def test_translate_adguard_fixture_classifies_every_rule_form(self) -> None:
        translation = importer.parse_adguard_yaml(ADGUARD_FIXTURE, "home.arpa")
        summary = importer.summarize_migration(translation, "home.arpa")
        by_cat = {
            section["name"]: {item["source"]: item for item in section["items"]}
            for section in summary["categories"]
        }
        blocks = by_cat["custom_blocks"]
        self.assertIn("domain + subdomains", blocks["||ads.example^"]["detected"])
        self.assertIn("exact host", blocks["|exact.example^"]["detected"])
        self.assertIn("domain + subdomains", blocks["plainblock.example"]["detected"])
        self.assertIn("exact host", blocks["0.0.0.0 hosts-blocked.example"]["detected"])
        self.assertIn("exact host", blocks[":: hosts-blocked-v6.example"]["detected"])
        self.assertIn("$important", blocks["||important.example^$important"]["detected"])
        allows = by_cat["custom_allows"]
        self.assertIn("domain + subdomains", allows["@@||safe.example^"]["detected"])
        self.assertIn("exact host", allows["@@|exactallow.example^"]["detected"])
        rewrites = by_cat["rewrites"]
        self.assertIn("127.0.0.1", rewrites["127.0.0.1 loopback.example"]["detected"])
        multi = rewrites["fd00::9 hosts-v6.example nas-alias.example # media box"]
        self.assertIn("2 hostnames", multi["detected"])
        self.assertIn("fd00::9 hosts-v6.example", multi["normalized"])
        self.assertIn("fd00::9 nas-alias.example", multi["normalized"])
        self.assertIn("192.168.1.10", rewrites["||rewritten.example^$dnsrewrite=192.168.1.10"]["detected"])
        regexes = by_cat["regex_rules"]
        self.assertIn("regex block", regexes["/^ads[0-9]+\\./"]["detected"])
        self.assertIn("regex allow", regexes["@@/^goodcdn[0-9]+\\./"]["detected"])
        comments = by_cat["comments"]
        self.assertIn("! adguard style comment", comments)
        self.assertIn("# hosts style comment", comments)
        self.assertIn("! ||disabled-rule.example^", comments)
        for item in comments.values():
            self.assertNotEqual(item["outcome"], "informational")
        client_scoped = by_cat["client_scoped"]
        self.assertIn("$client", client_scoped["||clientscoped.example^$client=192.168.1.44"]["warning"])
        self.assertEqual(client_scoped["||clientscoped.example^$client=192.168.1.44"]["outcome"], "inactive")
        unsupported = by_cat["unsupported"]
        self.assertIn("$dnstype", unsupported["||typerestricted.example^$dnstype=AAAA"]["warning"])
        self.assertIn("$ctag", unsupported["||ctagged.example^$ctag=device_phone"]["warning"])
        self.assertIn("/bad(?!lookahead)/", unsupported)
        invalid = by_cat["invalid"]
        self.assertTrue(any("not_a_valid_domain" in source for source in invalid))
        for item in list(unsupported.values()) + list(invalid.values()):
            if item["selectable"]:
                self.assertEqual(item["outcome"], "inactive")

    def test_translate_adguard_rewrites_split_local_vs_custom(self) -> None:
        translation = importer.parse_adguard_yaml(ADGUARD_FIXTURE, "home.arpa")
        local = {(r["fqdn"], r["record_type"], r["value"]) for r in translation["rewrites_as_local_dns"]}
        self.assertIn(("nas.home.arpa", "A", "192.168.1.50"), local)
        self.assertIn(("printer.home.arpa", "AAAA", "fd00::50"), local)
        self.assertIn(("alias.home.arpa", "CNAME", "target.home.arpa"), local)
        rules = {entry["text"]: entry["rule"] for entry in translation["custom_rules"]}
        self.assertEqual(rules["external.example.com -> 192.168.1.51"], "|external.example.com^$dnsrewrite=192.168.1.51")
        self.assertEqual(rules["*.wildcard.example -> 192.168.1.52"], "||wildcard.example^$dnsrewrite=192.168.1.52")
        self.assertTrue(any("badalias.home.arpa" in note for note in translation["unsupported_rules"]))

    def test_translate_adguard_sources_carry_enabled_state_and_category(self) -> None:
        translation = importer.parse_adguard_yaml(ADGUARD_FIXTURE, "home.arpa")
        sources = {s["name"]: s for s in translation["blocklist_sources"]}
        self.assertTrue(sources["Ads Filter"]["enabled"])
        self.assertFalse(sources["Malware Protection List"]["enabled"])
        self.assertEqual(sources["Malware Protection List"]["category"], "malware")
        self.assertEqual(sources["Mystery List"]["category"], "ads_trackers")
        allowlists = translation["allowlist_unsupported"]
        self.assertEqual(allowlists[0]["url"], "https://filters.example/allow.txt")

    def test_translate_adguard_upstream_resolvers(self) -> None:
        translation = importer.parse_adguard_yaml(ADGUARD_FIXTURE, "home.arpa")
        protocols = {row["protocol"] for row in translation["upstream_resolvers"]}
        self.assertEqual(protocols, {"doh", "plain"})
        self.assertTrue(any("domain-specific upstream routing" in note for note in translation["untranslatable"]))

    def test_translate_adguard_clients(self) -> None:
        translation = importer.parse_adguard_yaml(ADGUARD_FIXTURE, "home.arpa")
        aliases = {c["display_name"]: c["cidr_or_ip"] for c in translation["clients_as_aliases"]}
        self.assertEqual(aliases, {"Phone": "192.168.1.77", "Laptop": "192.168.1.0/28"})
        self.assertTrue(any("filtering_enabled" in note for note in translation["client_scoped"]))

    def test_adguard_yaml_line_count_cap(self) -> None:
        text = "user_rules:\n" + "".join(f"  - '||r{i}.example^'\n" for i in range(5))
        with mock.patch.object(importer, "MAX_IMPORT_LINES", 3):
            with self.assertRaises(importer.ImportError_) as ctx:
                importer.parse_adguard_yaml(text, "home.arpa")
        self.assertIn("line limit", str(ctx.exception).replace("-", " "))

    def test_adguard_overlong_rule_line_is_reported_not_imported(self) -> None:
        long_rule = "||" + "a" * (importer.MAX_LINE_CHARS + 10) + ".example^"
        translation = importer.parse_adguard_yaml(f"user_rules:\n  - '{long_rule}'\n", "home.arpa")
        self.assertEqual(translation["custom_rules"], [])
        self.assertTrue(any("exceeds" in note for note in translation["unsupported_rules"]))

    def test_sanitize_adguard_base_url_strips_userinfo_and_query(self) -> None:
        cleaned = importer.sanitize_adguard_base_url("http://admin:hunter2@adguard.lan:3000/?next=1")
        self.assertEqual(cleaned, "http://adguard.lan:3000")
        with self.assertRaises(importer.ImportError_):
            importer.sanitize_adguard_base_url("ftp://adguard.lan")
        with self.assertRaises(importer.ImportError_):
            importer.sanitize_adguard_base_url("file:///etc/passwd")

    def test_fetch_adguard_api_refuses_non_http_redirects(self) -> None:
        handler = importer._HttpOnlyRedirectHandler()
        with self.assertRaises(importer.ImportError_):
            handler.redirect_request(None, None, 302, "Found", {}, "file:///etc/passwd")

    # -- Pi-hole fixture classification -------------------------------------

    def test_pihole_fixture_classification(self) -> None:
        translation = importer.parse_pihole_text(PIHOLE_FIXTURE, "home.arpa")
        summary = importer.summarize_migration(translation, "home.arpa")
        by_cat = {
            section["name"]: {item["source"]: item for item in section["items"]}
            for section in summary["categories"]
        }
        self.assertEqual(len(by_cat["blocklists"]), 2)
        blocks = by_cat["custom_blocks"]
        self.assertIn("exact host", blocks["blocked-bare.example"]["detected"])
        self.assertIn("exact host", blocks["blacklist blocked-keyword.example"]["detected"])
        self.assertIn("domain + subdomains", blocks["(\\.|^)wildcardblock\\.example$"]["detected"])
        self.assertIn("domain + subdomains", blocks["regex (\\.|^)keywordwild\\.example$"]["detected"])
        allows = by_cat["custom_allows"]
        self.assertIn("exact host", allows["allowed-bare.example"]["detected"])
        self.assertIn("exact host", allows["whitelist allowed-keyword.example"]["detected"])
        regexes = by_cat["regex_rules"]
        self.assertIn("regex block", regexes["regex ^tracker[0-9]+\\.example$"]["detected"])
        self.assertIn("regex allow", regexes["^goodregex\\.example$"]["detected"])
        self.assertIn("regex allow", regexes["regex whitelist ^alsogood\\.example$"]["detected"])
        self.assertTrue(any("lookahead" in source for source in by_cat["unsupported"]))
        local = by_cat["local_dns"]
        self.assertIn("printer.home.arpa A 192.168.1.90", {i["normalized"].rsplit(" (", 1)[0] for i in local.values()})
        normalized = {item["normalized"] for item in local.values()}
        self.assertTrue(any("nas.home.arpa AAAA fd00::91" in n for n in normalized))
        self.assertTrue(any("nas-alias.home.arpa AAAA fd00::91" in n for n in normalized))
        self.assertTrue(any("media.home.arpa CNAME printer.home.arpa" in n for n in normalized))
        self.assertTrue(any("slow.home.arpa CNAME printer.home.arpa (TTL 600)" in n for n in normalized))
        group_findings = [i for i in by_cat["client_scoped"].values() if not i["selectable"]]
        self.assertEqual(len(group_findings), 3)
        self.assertTrue(any("broken-target" in note for note in translation["unsupported_rules"]))

    def test_pihole_exact_vs_adguard_subdomain_conformance(self) -> None:
        pihole = importer.parse_pihole_text("blacklist tracker.example\n", "home.arpa")
        entry = pihole["custom_rules"][0]
        rule = custom_rules.parse_rule(entry["rule"], plain_domain_subdomains=entry["plain_domain_subdomains"])[0]
        self.assertFalse(rule.match_subdomains, "Pi-hole exact lists must not cover subdomains")
        adguard = importer.parse_adguard_yaml("user_rules:\n  - 'tracker.example'\n", "home.arpa")
        entry = adguard["custom_rules"][0]
        rule = custom_rules.parse_rule(entry["rule"], plain_domain_subdomains=entry["plain_domain_subdomains"])[0]
        self.assertTrue(rule.match_subdomains, "AdGuard plain domains cover subdomains")

    def test_pihole_wildcard_idiom_preserves_original_text(self) -> None:
        translation = importer.parse_pihole_text("regex (\\.|^)ads\\.example$\n", "home.arpa")
        entry = translation["custom_rules"][0]
        self.assertEqual(entry["rule"], "||ads.example^")
        self.assertIn("(\\.|^)ads\\.example$", entry["comment"])

    def test_pihole_line_count_cap(self) -> None:
        with mock.patch.object(importer, "MAX_IMPORT_LINES", 10):
            with self.assertRaises(importer.ImportError_):
                importer.parse_pihole_text("\n".join(f"block{i}.example" for i in range(20)), "home.arpa")

    def test_pihole_overlong_line_reported(self) -> None:
        translation = importer.parse_pihole_text("x" * (importer.MAX_LINE_CHARS + 1) + "\n", "home.arpa")
        self.assertEqual(translation["custom_rules"], [])
        self.assertTrue(any("exceeds" in note for note in translation["unsupported_rules"]))

    # -- preview -------------------------------------------------------------

    def test_migration_preview_is_pure_and_repeatable(self) -> None:
        translation = importer.parse_pihole_text(PIHOLE_FIXTURE, "home.arpa")
        job_id = importer.create_migration_job("pihole", "pihole_export.txt", translation)
        before = self.destination_counts()
        importer.migration_preview_job(job_id, "home.arpa")
        importer.migration_preview_job(job_id, "home.arpa")
        self.assertEqual(self.destination_counts(), before, "preview must never create destination objects")
        job = importer.get_job(job_id)
        self.assertEqual(job["status"], "previewed")

    def test_preview_items_have_stable_keys_and_required_fields(self) -> None:
        translation = importer.parse_adguard_yaml(ADGUARD_FIXTURE, "home.arpa")
        first = importer.summarize_migration(translation, "home.arpa")
        second = importer.summarize_migration(translation, "home.arpa")
        keys_first = [item["key"] for section in first["categories"] for item in section["items"]]
        keys_second = [item["key"] for section in second["categories"] for item in section["items"]]
        self.assertEqual(keys_first, keys_second)
        self.assertEqual(len(keys_first), len(set(keys_first)))
        for section in first["categories"]:
            for item in section["items"]:
                for field in ("key", "source", "detected", "destination", "normalized", "outcome", "warning", "conflict", "selectable", "selected"):
                    self.assertIn(field, item)
                self.assertRegex(item["key"], r"^[a-z_]+:\d+$")

    def test_preview_reports_duplicates_and_allow_block_conflicts(self) -> None:
        translation = importer.parse_pihole_text(
            "blacklist dup.example\nblacklist dup.example\nblacklist both.example\nwhitelist both.example\n",
            "home.arpa",
        )
        summary = importer.summarize_migration(translation, "home.arpa")
        duplicates = self.summary_items(summary, "duplicates")
        self.assertEqual(len(duplicates), 1)
        self.assertFalse(duplicates[0]["selected"], "in-import duplicates default to deselected")
        self.assertTrue(any("both.example" in c["label"] for c in summary["conflicts"]))

    def test_preview_marks_already_existing_rule(self) -> None:
        custom_rules.add_rule("||exists.example^")
        translation = importer.parse_adguard_yaml("user_rules:\n  - '||exists.example^'\n", "home.arpa")
        summary = importer.summarize_migration(translation, "home.arpa")
        item = self.summary_items(summary, "custom_blocks")[0]
        self.assertIn("already exists", item["conflict"])
        self.assertTrue(any("exists.example" in e["label"] for e in summary["existing"]))

    def test_preview_marks_local_dns_conflicts(self) -> None:
        local_dns.add_record("A", "conflict.home.arpa", "192.168.1.10", 300, "", True)
        translation = {"rewrites_as_local_dns": [{"fqdn": "conflict.home.arpa", "record_type": "A", "value": "192.168.1.11"}]}
        summary = importer.summarize_migration(translation, "home.arpa")
        self.assertTrue(any("conflict.home.arpa" in c["label"] for c in summary["conflicts"]))

    def test_preview_marks_existing_blocklist_source(self) -> None:
        with alderpointdns_compiler.connect() as conn:
            conn.execute("INSERT INTO sources(name, url) VALUES ('Existing', 'https://old.invalid/list.txt')")
            conn.commit()
        translation = {"blocklist_sources": [{"name": "Existing", "url": "https://new.invalid/list.txt", "enabled": True}]}
        summary = importer.summarize_migration(translation, "home.arpa")
        self.assertTrue(any("Existing" in e["label"] for e in summary["existing"]))

    def test_large_rule_set_preview_is_bounded_and_counts_correct(self) -> None:
        lines = [f"||bulk{i}.example^" for i in range(20000)]
        text = "user_rules:\n" + "".join(f"  - '{line}'\n" for line in lines)
        started = time.monotonic()
        translation = importer.parse_adguard_yaml(text, "home.arpa")
        summary = importer.summarize_migration(translation, "home.arpa")
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 60, f"translating+previewing 20k rules took {elapsed:.1f}s")
        blocks = self.summary_items(summary, "custom_blocks")
        self.assertEqual(len(blocks), 20000)
        self.assertEqual(summary["counts"]["active"], 20000)
        self.assertEqual(summary["counts"]["duplicates"], 0)

    # -- transactional apply -------------------------------------------------

    def _pihole_job(self) -> tuple[int, dict]:
        translation = importer.parse_pihole_text(PIHOLE_FIXTURE, "home.arpa")
        job_id = importer.create_migration_job("pihole", "pihole_export.txt", translation)
        preview = importer.migration_preview_job(job_id, "home.arpa")
        return job_id, preview["summary"]

    def test_apply_pihole_fixture_counts_and_destinations(self) -> None:
        job_id, _summary = self._pihole_job()
        result = importer.apply_migration_job(job_id, default_domain="home.arpa")
        counts = result["counts"]
        self.assertEqual(counts["blocklists_added"], 2)
        self.assertEqual(counts["block_rules"], 4)
        self.assertEqual(counts["allow_rules"], 2)
        self.assertEqual(counts["regex_rules"], 3)
        self.assertEqual(counts["unsupported_kept_inactive"], 1)
        self.assertEqual(counts["local_dns_records"], 5)
        self.assertEqual(counts["comments"], 1)
        self.assertEqual(counts["failed"], 0)
        with self.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_rules").fetchone()[0], 0, "the legacy table must stay frozen")
            rows = conn.execute("SELECT * FROM custom_filter_rules").fetchall()
            self.assertTrue(all(row["source_system"] == "pihole" for row in rows))
            self.assertTrue(all(row["import_job_id"] == job_id for row in rows))
            exact_block = conn.execute("SELECT match_subdomains FROM custom_filter_rules WHERE domain='blocked-bare.example'").fetchone()
            self.assertEqual(exact_block["match_subdomains"], 0)
            wildcard = conn.execute("SELECT match_subdomains, comment FROM custom_filter_rules WHERE domain='wildcardblock.example'").fetchone()
            self.assertEqual(wildcard["match_subdomains"], 1)
            self.assertIn("(\\.|^)wildcardblock\\.example$", wildcard["comment"])
            unsupported = conn.execute("SELECT enabled, unsupported_reason FROM custom_filter_rules WHERE validation_state='unsupported'").fetchall()
            self.assertTrue(unsupported and all(row["enabled"] == 0 for row in unsupported))
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0], 5)
            ttl600 = conn.execute("SELECT ttl FROM local_dns_records WHERE fqdn='slow.home.arpa'").fetchone()
            self.assertEqual(ttl600["ttl"], 600)
        job = importer.get_job(job_id)
        self.assertEqual(job["status"], "applied")

    def test_apply_honors_item_and_category_deselection(self) -> None:
        job_id, summary = self._pihole_job()
        selected = {
            item["key"]
            for section in summary["categories"]
            for item in section["items"]
            if item["selected"]
        }
        # Deselect one single block rule and the whole local_dns category.
        blocks = self.summary_items(summary, "custom_blocks")
        dropped_rule = blocks[0]
        selected.discard(dropped_rule["key"])
        for item in self.summary_items(summary, "local_dns"):
            selected.discard(item["key"])
        result = importer.apply_migration_job(job_id, selected=selected, default_domain="home.arpa")
        self.assertEqual(result["counts"]["local_dns_records"], 0)
        self.assertEqual(result["counts"]["block_rules"], 3)
        self.assertEqual(result["counts"]["user_deselected"], 6)
        with self.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0], 0)
            self.assertIsNone(conn.execute("SELECT 1 FROM custom_filter_rules WHERE domain='blocked-bare.example'").fetchone())
            self.assertIsNotNone(conn.execute("SELECT 1 FROM custom_filter_rules WHERE domain='blocked-keyword.example'").fetchone())

    def test_apply_is_transactional_on_mid_apply_failure(self) -> None:
        job_id, _summary = self._pihole_job()
        before = self.destination_counts()
        with mock.patch.object(importer, "_apply_local_dns_record", side_effect=RuntimeError("disk exploded")):
            with self.assertRaises(importer.ImportError_) as ctx:
                importer.apply_migration_job(job_id, default_domain="home.arpa")
        self.assertIn("stage", str(ctx.exception))
        self.assertIn("local DNS record", str(ctx.exception))
        self.assertEqual(self.destination_counts(), before, "no destination table may keep partial rows")
        job = importer.get_job(job_id)
        self.assertEqual(job["status"], "failed")
        self.assertIn("local DNS record", job["message"])

    def test_apply_requires_verified_backup(self) -> None:
        job_id, _summary = self._pihole_job()
        before = self.destination_counts()
        with mock.patch.object(importer.subprocess, "run", side_effect=subprocess.CalledProcessError(1, importer.PRE_IMPORT_BACKUP_COMMAND, "backup failed")):
            with self.assertRaises(importer.ImportError_) as ctx:
                importer.apply_migration_job(job_id, default_domain="home.arpa")
        self.assertIn("backup", str(ctx.exception))
        self.assertEqual(self.destination_counts(), before)

    def test_apply_refuses_when_privileged_backup_helper_is_unavailable(self) -> None:
        job_id, _summary = self._pihole_job()
        before = self.destination_counts()
        with mock.patch.object(importer.subprocess, "run", side_effect=FileNotFoundError("sudo")):
            with self.assertRaises(importer.ImportError_) as ctx:
                importer.apply_migration_job(job_id, default_domain="home.arpa")
        self.assertIn("backup", str(ctx.exception))
        self.assertEqual(self.destination_counts(), before)

    def test_rollback_removes_exactly_the_imported_objects(self) -> None:
        local_dns.add_record("A", "keepme.home.arpa", "192.168.1.200", 300, "pre-existing", True)
        custom_rules.add_rule("||keepme.example^", comment="pre-existing")
        with alderpointdns_compiler.connect() as conn:
            conn.execute("INSERT INTO sources(name, url) VALUES ('KeepSource', 'https://keep.invalid/list.txt')")
            conn.commit()
        job_id, _summary = self._pihole_job()
        importer.apply_migration_job(job_id, default_domain="home.arpa")
        removed = importer.rollback_job(job_id)
        self.assertGreater(removed, 0)
        with self.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_filter_rules WHERE import_job_id=?", (job_id,)).fetchone()[0], 0)
            self.assertIsNotNone(conn.execute("SELECT 1 FROM custom_filter_rules WHERE domain='keepme.example'").fetchone())
            self.assertEqual(conn.execute("SELECT count(*) FROM local_dns_records").fetchone()[0], 1)
            self.assertIsNotNone(conn.execute("SELECT 1 FROM local_dns_records WHERE fqdn='keepme.home.arpa'").fetchone())
            self.assertEqual(conn.execute("SELECT count(*) FROM sources").fetchone()[0], 1)
            self.assertIsNotNone(conn.execute("SELECT 1 FROM sources WHERE name='KeepSource'").fetchone())
        self.assertEqual(importer.get_job(job_id)["status"], "rolled_back")

    def test_rollback_restores_updated_source(self) -> None:
        with alderpointdns_compiler.connect() as conn:
            conn.execute("INSERT INTO sources(name, url, enabled, category) VALUES ('Shared', 'https://old.invalid/list.txt', 0, 'malware')")
            conn.commit()
        translation = {"blocklist_sources": [{"name": "Shared", "url": "https://new.invalid/list.txt", "enabled": True, "category": "ads_trackers"}]}
        job_id = importer.create_migration_job("pihole", "sources.txt", translation)
        importer.migration_preview_job(job_id, "home.arpa")
        importer.apply_migration_job(job_id, default_domain="home.arpa")
        with self.connect() as conn:
            row = conn.execute("SELECT url, enabled, category FROM sources WHERE name='Shared'").fetchone()
            self.assertEqual((row["url"], row["enabled"], row["category"]), ("https://new.invalid/list.txt", 1, "ads_trackers"))
        importer.rollback_job(job_id)
        with self.connect() as conn:
            row = conn.execute("SELECT url, enabled, category FROM sources WHERE name='Shared'").fetchone()
            self.assertEqual((row["url"], row["enabled"], row["category"]), ("https://old.invalid/list.txt", 0, "malware"))

    def test_apply_skips_identical_existing_rule_as_duplicate(self) -> None:
        custom_rules.add_rule("||exists.example^", comment="pre-existing")
        translation = importer.parse_adguard_yaml("user_rules:\n  - '||exists.example^'\n", "home.arpa")
        job_id = importer.create_migration_job("adguard_yaml", "dup.yaml", translation)
        importer.migration_preview_job(job_id, "home.arpa")
        result = importer.apply_migration_job(job_id, default_domain="home.arpa")
        self.assertEqual(result["counts"]["duplicates_skipped"], 1)
        self.assertEqual(result["counts"]["block_rules"], 0)
        with self.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_filter_rules").fetchone()[0], 1)

    def test_apply_adguard_fixture_end_to_end(self) -> None:
        translation = importer.parse_adguard_yaml(ADGUARD_FIXTURE, "home.arpa")
        job_id = importer.create_migration_job("adguard_yaml", "adguard_home.yaml", translation)
        importer.migration_preview_job(job_id, "home.arpa")
        result = importer.apply_migration_job(job_id, default_domain="home.arpa")
        counts = result["counts"]
        self.assertEqual(counts["blocklists_added"], 3)
        self.assertEqual(counts["block_rules"], 6)
        self.assertEqual(counts["allow_rules"], 2)
        self.assertEqual(counts["rewrite_rules"], 6)
        self.assertEqual(counts["regex_rules"], 2)
        self.assertEqual(counts["comments"], 3)
        self.assertEqual(counts["invalid_kept_inactive"], 1)
        self.assertEqual(counts["unsupported_kept_inactive"], 4)
        self.assertEqual(counts["local_dns_records"], 3)
        self.assertEqual(counts["upstream_resolvers"], 2)
        self.assertEqual(counts["client_aliases"], 2)
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM custom_filter_rules").fetchall()
            self.assertTrue(all(row["source_system"] == "adguard" for row in rows))
            important = conn.execute("SELECT priority FROM custom_filter_rules WHERE domain='important.example'").fetchone()
            self.assertEqual(important["priority"], custom_rules.IMPORTANT_PRIORITY)
            hosts_alias = conn.execute("SELECT comment FROM custom_filter_rules WHERE domain='nas-alias.example'").fetchone()
            self.assertEqual(hosts_alias["comment"], "media box")
            self.assertEqual(local_dns.alias_for_client("192.168.1.77"), "Phone")

    def test_mark_job_deploy_failed_and_rollback_after_deploy_failure(self) -> None:
        job_id, _summary = self._pihole_job()
        importer.apply_migration_job(job_id, default_domain="home.arpa")
        importer.mark_job_deploy_failed(job_id, "dnsdist refused the config")
        job = importer.get_job(job_id)
        self.assertEqual(job["status"], "deploy_failed")
        self.assertIn("deployment failed", job["message"])
        removed = importer.rollback_job(job_id)
        self.assertGreater(removed, 0)
        with self.connect() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM custom_filter_rules").fetchone()[0], 0)

    # -- reports and sanitization -------------------------------------------

    def test_report_redacts_url_credentials_and_tokens(self) -> None:
        translation = {
            "blocklist_sources": [
                {"name": "Secret List", "url": "https://user:hunter2@lists.example/private.txt?token=tok123secret", "enabled": True},
            ],
            "unsupported_rules": ["see https://user:hunter2@lists.example/other.txt?apikey=abcdef for details"],
        }
        job_id = importer.create_migration_job("adguard_yaml", "secret.yaml", translation)
        importer.migration_preview_job(job_id, "home.arpa")
        report_text = importer.job_report(importer.get_job(job_id))
        self.assertNotIn("hunter2", report_text)
        self.assertNotIn("tok123secret", report_text)
        self.assertNotIn("abcdef", report_text)
        self.assertIn("lists.example", report_text)
        importer.apply_migration_job(job_id, default_domain="home.arpa")
        report_text = importer.job_report(importer.get_job(job_id))
        self.assertNotIn("hunter2", report_text)
        self.assertNotIn("tok123secret", report_text)

    def test_report_contains_required_summary_counts(self) -> None:
        job_id, _summary = self._pihole_job()
        selected_none: set[str] = set()
        importer.apply_migration_job(job_id, selected=selected_none, default_domain="home.arpa")
        report = json.loads(importer.job_report(importer.get_job(job_id)))
        counts = report["report"]["counts"]
        for key in (
            "blocklists_added", "block_rules", "allow_rules", "rewrite_rules", "regex_rules", "comments",
            "duplicates_skipped", "invalid_kept_inactive", "unsupported_kept_inactive", "user_deselected", "failed",
        ):
            self.assertIn(key, counts)
        self.assertGreater(counts["user_deselected"], 0)
        self.assertEqual(report["report"]["counts"]["block_rules"], 0)

    def test_redact_sensitive_drops_credential_keys(self) -> None:
        payload = {"password": "x", "nested": {"api_key": "y", "note": "keep https://a.example/p?token=z"}}
        cleaned = importer.redact_sensitive(payload)
        self.assertNotIn("password", cleaned)
        self.assertNotIn("api_key", cleaned["nested"])
        self.assertEqual(cleaned["nested"]["note"], "keep https://a.example/p")

    def test_redact_sensitive_matches_compound_and_camelcase_keys(self) -> None:
        # Exact-match-only key checking misses compound field names; these
        # must be caught too.
        for key in ("admin_password", "AuthToken", "apiKey", "auth_secret"):
            cleaned = importer.redact_sensitive({key: "x", "keep": "y"})
            self.assertNotIn(key, cleaned, key)
            self.assertIn("keep", cleaned)

    def test_redact_sensitive_preserves_legitimate_key_fields(self) -> None:
        # Bare "key" and compounds like "deselected_keys" are real,
        # non-secret preview-selection fields and must survive redaction.
        payload = {"key": "blocklists:0", "deselected_keys": ["a:1"], "_dupkeys": [], "_upstream_key": ["plain", "1.1.1.1", 53, ""]}
        cleaned = importer.redact_sensitive(payload)
        self.assertEqual(set(cleaned.keys()), set(payload.keys()))

    # -- native round trip ---------------------------------------------------

    def test_native_export_parse_round_trip(self) -> None:
        local_dns.add_record("A", "native.home.arpa", "192.168.1.101", 300, "native", True)
        with alderpointdns_compiler.connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO custom_rules(domain, action, enabled, comment, created_at) VALUES (?, 'block', 1, 'native', ?)",
                ("native-block.example", importer.now()),
            )
            conn.commit()
        custom_rules.add_rule("||typed-rule.example^", comment="typed")
        exported = importer.export_alderpointdns_native()
        parsed = importer.parse_alderpointdns_native_json(exported)
        self.assertTrue(any(row["fqdn"] == "native.home.arpa" for row in parsed["rewrites_as_local_dns"]))
        self.assertIn("native-block.example", parsed["custom_block"])
        self.assertTrue(any(entry["rule"] == "||typed-rule.example^" for entry in parsed["custom_rules"]))


if __name__ == "__main__":
    unittest.main()
