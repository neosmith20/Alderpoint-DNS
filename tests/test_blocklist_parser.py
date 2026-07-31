#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import app.alderpointdns_compiler as compiler
from app.alderpointdns_compiler import normalize_domain, parse_rules, parse_source_line

FIXTURES = Path(__file__).parent / "fixtures"


class ParserTests(unittest.TestCase):
    def test_supported_formats_and_exceptions(self):
        content = """
        # comment
        example.com
        0.0.0.0 hosts.example
        127.0.0.1 local.example
        ||adblock.example^
        @@||example.com^
        example.com
        ||thirdparty.example^$third-party
        /regex/
        not a domain
        """
        blocks, allows, stats = parse_rules(content)
        self.assertIn("hosts.example", blocks)
        self.assertIn("local.example", blocks)
        self.assertIn("adblock.example", blocks)
        self.assertIn("example.com", allows)
        self.assertGreaterEqual(stats.duplicate_domains, 1)
        self.assertGreaterEqual(stats.unsupported_rules, 2)
        self.assertGreaterEqual(stats.invalid_rules, 1)

    def test_idn_normalization(self):
        self.assertEqual(normalize_domain("bücher.example"), "xn--bcher-kva.example")

    # -- Hosts-file format support -----------------------------------------

    def test_hosts_sinkhole_address_forms_all_block(self):
        content = "\n".join(
            [
                "0.0.0.0 a.example",
                "127.0.0.1 b.example",
                ":: c.example",
                "::0 d.example",
                "0:0:0:0:0:0:0:0 e.example",
            ]
        )
        blocks, allows, stats = parse_rules(content)
        self.assertEqual(blocks, {"a.example", "b.example", "c.example", "d.example", "e.example"})
        self.assertEqual(allows, set())
        self.assertEqual(stats.invalid_rules, 0)
        self.assertEqual(stats.unsupported_rules, 0)
        self.assertEqual(stats.accepted_domains, 5)

    def test_hosts_whitespace_and_inline_comments(self):
        content = "0.0.0.0\ttab.example\n0.0.0.0   multi.example  # blocked by policy\n"
        blocks, _, stats = parse_rules(content)
        self.assertEqual(blocks, {"tab.example", "multi.example"})
        self.assertEqual(stats.invalid_rules, 0)

    def test_malformed_hosts_entries_rejected_with_reason(self):
        content = "0.0.0.0\n0.0.0.0 not_a_valid_domain_@@@\n"
        _, _, stats = parse_rules(content)
        self.assertEqual(stats.invalid_rules, 2)
        reasons = [s["reason"] for s in stats.rejected_samples]
        self.assertTrue(any("no hostname" in r for r in reasons))
        self.assertTrue(any("not a valid hostname" in r for r in reasons))

    def test_localhost_aliases_ignored_not_invalid_or_blocked(self):
        content = (
            "0.0.0.0 localhost\n"
            "0.0.0.0 localhost.localdomain\n"
            ":: ip6-localhost\n"
            ":: ip6-loopback\n"
        )
        blocks, _, stats = parse_rules(content)
        self.assertEqual(blocks, set())
        self.assertEqual(stats.invalid_rules, 0)
        self.assertEqual(stats.unsupported_rules, 0)
        self.assertEqual(stats.accepted_domains, 0)

    # -- AdBlock / AdGuard syntax --------------------------------------------

    def test_plain_adblock_block_and_allow(self):
        blocks, allows, stats = parse_rules("||ads.example^\n@@||safe.example^\n")
        self.assertEqual(blocks, {"ads.example"})
        self.assertEqual(allows, {"safe.example"})
        self.assertEqual(stats.unsupported_rules, 0)

    def test_adguard_dnsrewrite_blockpage_normalized_to_block(self):
        kind_domain_reason = parse_source_line("||gamengirls.com^$dnsrewrite=ad-block.dns.adguard.com")
        self.assertEqual(kind_domain_reason, [("block", "gamengirls.com", "")])

    def test_adguard_dnsrewrite_mixed_supported_and_unsupported(self):
        content = "\n".join(
            [
                "||good.example^$dnsrewrite=ad-block.dns.adguard.com",
                "||other-target.example^$dnsrewrite=some.other.cname.example",
                "||ip-target.example^$dnsrewrite=1.2.3.4",
                "||combo.example^$important,dnsrewrite=ad-block.dns.adguard.com",
            ]
        )
        blocks, _, stats = parse_rules(content)
        self.assertEqual(blocks, {"good.example"})
        self.assertEqual(stats.unsupported_rules, 3)
        reasons = " ".join(s["reason"] for s in stats.rejected_samples)
        self.assertIn("dnsrewrite", reasons)

    def test_real_adguard_popup_fixture_all_supported(self):
        content = (FIXTURES / "adguard_popup_hosts.txt").read_text()
        blocks, _, stats = parse_rules(content)
        self.assertEqual(len(blocks), 10)
        self.assertEqual(stats.unsupported_rules, 0)
        self.assertEqual(stats.invalid_rules, 0)
        self.assertEqual(stats.parsed_rules, 10)

    def test_regex_rule_unsupported_for_blocklist_sources(self):
        _, _, stats = parse_rules("/ads?[0-9]+/\n")
        self.assertEqual(stats.unsupported_rules, 1)

    # -- IPv4/IPv6 companion + dedup semantics -------------------------------

    def test_ipv4_ipv6_companion_lists_share_domain_set(self):
        blocks4, _, _ = parse_rules((FIXTURES / "windows_spy_blocker_ipv4.txt").read_text())
        blocks6, _, _ = parse_rules((FIXTURES / "windows_spy_blocker_ipv6.txt").read_text())
        self.assertEqual(blocks4, blocks6)
        self.assertEqual(len(blocks4), 15)

    def test_fully_redundant_source_reports_healthy_redundant(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    ipv4_uri = (FIXTURES / "windows_spy_blocker_ipv4.txt").resolve().as_uri()
                    ipv6_uri = (FIXTURES / "windows_spy_blocker_ipv6.txt").resolve().as_uri()
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("Windows Spy Blocker", ipv4_uri),
                    )
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("Windows Spy Blocker - IPv6", ipv6_uri),
                    )
                    compiler.collect_rules(conn, download=True)
                    ipv4_row = conn.execute("SELECT * FROM sources WHERE name='Windows Spy Blocker'").fetchone()
                    ipv6_row = conn.execute("SELECT * FROM sources WHERE name='Windows Spy Blocker - IPv6'").fetchone()
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

        self.assertEqual(ipv4_row["unique_active_domains"], 15)
        self.assertEqual(compiler.source_health(ipv4_row)["state"], compiler.HEALTH_HEALTHY)

        self.assertEqual(ipv6_row["parsed_rules"], 15)
        self.assertEqual(ipv6_row["duplicate_domains"], 15)
        self.assertEqual(ipv6_row["unique_active_domains"], 0)
        health = compiler.source_health(ipv6_row)
        self.assertEqual(health["state"], compiler.HEALTH_HEALTHY_REDUNDANT)
        self.assertEqual(health["label"], "Healthy, redundant")

    def test_nonempty_unsupported_source_not_reported_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_file = tmp_path / "unsupported.txt"
            # Every line uses a modifier combination the shared parser
            # cannot preserve -- a nonempty, successfully-downloaded source
            # that contributes zero usable rules.
            source_file.write_text(
                "||a.example^$third-party\n||b.example^$denyallow=c.example\n||d.example^$dnstype=A\n"
            )
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("All Unsupported", source_file.as_uri()),
                    )
                    compiler.collect_rules(conn, download=True)
                    row = conn.execute("SELECT * FROM sources WHERE name='All Unsupported'").fetchone()
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

        self.assertEqual(row["parsed_rules"], 0)
        self.assertEqual(row["unsupported_rules"], 3)
        health = compiler.source_health(row)
        self.assertEqual(health["state"], compiler.HEALTH_UNSUPPORTED_FORMAT)
        self.assertNotEqual(health["label"], "Healthy")

    def test_globally_deduplicated_active_domain_total(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            a = tmp_path / "a.txt"
            b = tmp_path / "b.txt"
            a.write_text("0.0.0.0 shared.example\n0.0.0.0 only-a.example\n")
            b.write_text("0.0.0.0 shared.example\n0.0.0.0 only-b.example\n")
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("A", a.as_uri()),
                    )
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("B", b.as_uri()),
                    )
                    active_blocks, _, per_source, _ = compiler.collect_rules(conn, download=True)
                    a_row = conn.execute("SELECT * FROM sources WHERE name='A'").fetchone()
                    b_row = conn.execute("SELECT * FROM sources WHERE name='B'").fetchone()
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

        self.assertEqual(active_blocks, {"shared.example", "only-a.example", "only-b.example"})
        self.assertEqual(a_row["unique_active_domains"], 2)
        self.assertEqual(b_row["unique_active_domains"], 1)
        self.assertEqual(b_row["duplicate_domains"], 1)

    def test_cached_copy_behavior_after_failed_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_file = tmp_path / "source.txt"
            source_file.write_text("0.0.0.0 cached.example\n")
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("Flaky", source_file.as_uri()),
                    )
                    source = conn.execute("SELECT * FROM sources WHERE name='Flaky'").fetchone()
                    result, stats = compiler.update_one_source(conn, source)
                    self.assertTrue(result.success)
                    self.assertEqual(stats.unique_active_domains, 1)

                    # Point the same source at an unreachable URL and update
                    # again: the download fails, but the previously-cached
                    # copy on disk is still parsed and still contributes.
                    conn.execute("UPDATE sources SET url=? WHERE id=?", ("https://127.0.0.1:1/unreachable", source["id"]))
                    source = conn.execute("SELECT * FROM sources WHERE id=?", (source["id"],)).fetchone()
                    result, stats = compiler.update_one_source(conn, source)
                    row = conn.execute("SELECT * FROM sources WHERE id=?", (source["id"],)).fetchone()
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

        self.assertFalse(result.success)
        self.assertIsNotNone(row["last_error"])
        self.assertEqual(row["using_cached_copy"], 1)
        self.assertEqual(row["unique_active_domains"], 1)
        health = compiler.source_health(row)
        self.assertEqual(health["state"], compiler.HEALTH_USING_CACHED)
        self.assertEqual(health["label"], "Using cached copy")

    def test_public_source_catalog_seeds_large_list_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_db = compiler.DB_PATH
            compiler.DB_PATH = Path(tmp) / "alderpointdns.db"
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    compiler.seed_public(argparse.Namespace(enabled=True))
                    compiler.seed_public(argparse.Namespace(enabled=False))
                with compiler.connect() as conn:
                    rows = conn.execute("SELECT name, url, enabled, category FROM sources ORDER BY name").fetchall()
            finally:
                compiler.DB_PATH = original_db

        urls = [row["url"] for row in rows]
        categories = {row["category"] for row in rows}
        self.assertEqual(len(rows), 19)
        self.assertTrue(all(row["enabled"] == 0 for row in rows))
        self.assertIn("ads_trackers", categories)
        self.assertIn("malware", categories)
        self.assertTrue(any("adguardteam.github.io" in url for url in urls))
        self.assertTrue(any("raw.githubusercontent.com" in url for url in urls))

    def test_policy_schema_seed_supports_network_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_db = compiler.DB_PATH
            compiler.DB_PATH = Path(tmp) / "alderpointdns.db"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    categories = {row["key"] for row in conn.execute("SELECT key FROM categories")}
                    profiles = {row["key"] for row in conn.execute("SELECT key FROM policy_profiles")}
                    restricted = {
                        row["category_key"]
                        for row in conn.execute(
                            "SELECT category_key FROM profile_categories WHERE profile_key='restricted' AND enabled=1"
                        )
                    }
                    conn.execute(
                        "INSERT INTO network_policies(cidr, profile_key, description) VALUES (?, ?, ?)",
                        ("127.0.0.0/8", "trusted", "loopback lab policy"),
                    )
                    network = conn.execute("SELECT profile_key FROM network_policies WHERE cidr=?", ("127.0.0.0/8",)).fetchone()
            finally:
                compiler.DB_PATH = original_db

        self.assertEqual(
            {"malware", "ads_trackers", "adult_content", "iot_telemetry", "safesearch", "custom"},
            categories,
        )
        self.assertEqual({"trusted", "standard", "iot", "restricted"}, profiles)
        self.assertEqual({"malware", "ads_trackers", "adult_content", "iot_telemetry", "safesearch"}, restricted)
        self.assertEqual("trusted", network["profile_key"])

    def test_update_single_source_records_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_file = tmp_path / "source.txt"
            source_file.write_text("example.test\n||ads.example^\n@@||allowed.example^\n")
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, ?)",
                        ("local fixture", source_file.as_uri(), "ads_trackers"),
                    )
                    source = conn.execute("SELECT * FROM sources WHERE name='local fixture'").fetchone()
                    result, stats = compiler.update_one_source(conn, source)
                    row = conn.execute("SELECT accepted_domains, unique_active_domains, last_error FROM sources WHERE id=?", (source["id"],)).fetchone()
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

        self.assertTrue(result.success)
        self.assertEqual(3, stats.accepted_domains)
        self.assertEqual(3, row["accepted_domains"])
        self.assertEqual(2, row["unique_active_domains"])  # 2 blocks + 1 allow (allow not counted as "block contribution")
        self.assertIsNone(row["last_error"])

    # -- CLI exit-code contract -----------------------------------------------

    def test_update_sources_cli_exit_zero_when_all_healthy(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_file = tmp_path / "source.txt"
            source_file.write_text("0.0.0.0 healthy.example\n")
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("Healthy Source", source_file.as_uri()),
                    )
                with contextlib.redirect_stdout(io.StringIO()):
                    try:
                        compiler.update_sources(argparse.Namespace())
                    except SystemExit as exc:
                        self.fail(f"expected exit 0, got {exc.code}")
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

    def test_update_sources_cli_exit_two_on_partial_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            good_file = tmp_path / "good.txt"
            good_file.write_text("0.0.0.0 healthy.example\n")
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("Healthy Source", good_file.as_uri()),
                    )
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("Broken Source", "https://127.0.0.1:1/unreachable"),
                    )
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as ctx:
                        compiler.update_sources(argparse.Namespace())
                self.assertEqual(ctx.exception.code, 2)
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

    def test_update_sources_cli_exit_one_on_complete_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("Broken Source", "https://127.0.0.1:1/unreachable"),
                    )
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as ctx:
                        compiler.update_sources(argparse.Namespace())
                self.assertEqual(ctx.exception.code, 1)
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir


if __name__ == "__main__":
    unittest.main()
