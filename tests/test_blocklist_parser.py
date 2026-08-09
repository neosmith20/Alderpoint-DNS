#!/usr/bin/env python3
import argparse
import contextlib
import io
import json
import tempfile
import unittest
from unittest import mock
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

    def test_refresh_rpz_serial_updates_soa_without_changing_records(self):
        original = (
            "$TTL 2h\n"
            "@ IN SOA localhost. hostmaster.localhost. 1 1h 15m 30d 2h\n"
            "@ IN NS localhost.\n"
            "example.com CNAME .\n"
        )
        refreshed = compiler.refresh_rpz_serial(original)
        self.assertIn("example.com CNAME .", refreshed)
        self.assertNotIn("hostmaster.localhost. 1 1h", refreshed)

    def test_restore_rpz_backup_for_rollback_refreshes_serial(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            backup = tmp_path / "old-good.rpz"
            compiled = tmp_path / "alderpointdns.rpz"
            backup.write_text(
                "$TTL 2h\n"
                "@ IN SOA localhost. hostmaster.localhost. 1 1h 15m 30d 2h\n"
                "@ IN NS localhost.\n"
                "good.example CNAME .\n"
            )
            original_compiled = compiler.COMPILED_RPZ
            compiler.COMPILED_RPZ = compiled
            try:
                with mock.patch.object(compiler, "reload_bind") as reload_bind:
                    compiler.restore_rpz_backup_for_rollback(backup)
                restored = compiled.read_text()
            finally:
                compiler.COMPILED_RPZ = original_compiled

        self.assertIn("good.example CNAME .", restored)
        self.assertNotIn("hostmaster.localhost. 1 1h", restored)
        reload_bind.assert_called_once_with()

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

    def test_last_error_clears_once_a_later_update_actually_succeeds(self):
        # Regression: a live appliance restore left `sources.last_error` set
        # from a stale (pre-restore) DNS-resolution failure. After the host
        # regained connectivity, a real successful re-download of the same
        # source must clear that stale error -- it must not linger forever
        # just because it was once recorded.
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_file = tmp_path / "source.txt"
            source_file.write_text("0.0.0.0 recovers.example\n")
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, 'ads_trackers')",
                        ("Windows Spy Blocker", source_file.as_uri()),
                    )
                    source = conn.execute("SELECT * FROM sources WHERE name='Windows Spy Blocker'").fetchone()

                    # First attempt: DNS resolution failure, exactly the
                    # shape urllib raises for `[Errno -5] No address
                    # associated with hostname`.
                    conn.execute(
                        "UPDATE sources SET url=? WHERE id=?",
                        ("https://this-host-does-not-resolve.invalid/list.txt", source["id"]),
                    )
                    source = conn.execute("SELECT * FROM sources WHERE id=?", (source["id"],)).fetchone()
                    result, _stats = compiler.update_one_source(conn, source)
                    self.assertFalse(result.success)
                    failed_row = conn.execute("SELECT * FROM sources WHERE id=?", (source["id"],)).fetchone()
                    self.assertIsNotNone(failed_row["last_error"])
                    self.assertEqual(compiler.source_health(failed_row)["state"], compiler.HEALTH_ERROR)

                    # Connectivity restored, same source now resolves and
                    # downloads cleanly -- exactly what "Update All Now"
                    # (update_sources -> collect_rules(download=True) ->
                    # record_download_result) performs.
                    conn.execute("UPDATE sources SET url=? WHERE id=?", (source_file.as_uri(), source["id"]))
                    conn.commit()
                    compiler.collect_rules(conn, download=True)
                    healed_row = conn.execute("SELECT * FROM sources WHERE id=?", (source["id"],)).fetchone()
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

        self.assertIsNone(healed_row["last_error"])
        self.assertIsNotNone(healed_row["last_success"])
        self.assertEqual(healed_row["using_cached_copy"], 0)
        self.assertEqual(compiler.source_health(healed_row)["state"], compiler.HEALTH_HEALTHY)

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

    def test_unchanged_source_reuses_parse_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_file = tmp_path / "source.txt"
            source_file.write_text("0.0.0.0 cached.example\n||ads.example^\n@@||allowed.example^\n")
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            original_parse_rules = compiler.parse_rules
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, ?)",
                        ("local fixture", source_file.as_uri(), "ads_trackers"),
                    )
                    first_blocks, first_allows, _per_source, _errors = compiler.collect_rules(conn, download=True)

                    def fail_if_reparsed(_content):
                        raise AssertionError("unchanged source was reparsed instead of loaded from cache")

                    compiler.parse_rules = fail_if_reparsed
                    second_blocks, second_allows, _per_source, _errors = compiler.collect_rules(conn, download=False)
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir
                compiler.parse_rules = original_parse_rules

        self.assertEqual(first_blocks, second_blocks)
        self.assertEqual(first_allows, second_allows)

    def test_parse_cache_invalidates_when_source_content_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source_file = tmp_path / "source.txt"
            source_file.write_text("0.0.0.0 before.example\n")
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
                    before, _, _per_source, _errors = compiler.collect_rules(conn, download=True)
                    current, _ = compiler.source_paths(conn.execute("SELECT * FROM sources WHERE name='local fixture'").fetchone())
                    current.write_text("0.0.0.0 after.example\n")
                    after, _, _per_source, _errors = compiler.collect_rules(conn, download=False)
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

        self.assertEqual(before, {"before.example"})
        self.assertEqual(after, {"after.example"})

    def test_reusable_policy_manifest_invalidates_on_source_and_custom_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            original_rpz = compiler.COMPILED_RPZ
            original_staging = compiler.STAGING_DIR
            original_custom_db = compiler.custom_rules.DB_PATH
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            compiler.COMPILED_RPZ = tmp_path / "compiled" / "bind" / "alderpointdns.rpz"
            compiler.STAGING_DIR = tmp_path / "staging"
            compiler.custom_rules.DB_PATH = compiler.DB_PATH
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, ?)",
                        ("local fixture", (tmp_path / "unused.txt").as_uri(), "ads_trackers"),
                    )
                    conn.commit()
                    source = conn.execute("SELECT * FROM sources WHERE name='local fixture'").fetchone()
                    current, _ = compiler.source_paths(source)
                    current.parent.mkdir(parents=True, exist_ok=True)
                    current.write_text("0.0.0.0 cached.example\n")
                    rpz_text = compiler.render_rpz({"cached.example"})
                    compiler.record_reusable_protection_policy(conn, rpz_text, 1)
                    ok_initial, _ = compiler.reusable_protection_policy_available(conn)
                    current.write_text("0.0.0.0 changed.example\n")
                    ok_source_changed, _ = compiler.reusable_protection_policy_available(conn)
                    current.write_text("0.0.0.0 cached.example\n")
                    custom_rules = compiler.custom_rules
                    custom_rules.add_rule("||custom-block.example^")
                    ok_custom_changed, _ = compiler.reusable_protection_policy_available(conn)
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir
                compiler.COMPILED_RPZ = original_rpz
                compiler.STAGING_DIR = original_staging
                compiler.custom_rules.DB_PATH = original_custom_db

        self.assertTrue(ok_initial)
        self.assertFalse(ok_source_changed)
        self.assertFalse(ok_custom_changed)

    def test_reusable_policy_refuses_enabled_regex_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            original_db = compiler.DB_PATH
            original_download_dir = compiler.DOWNLOAD_DIR
            original_rpz = compiler.COMPILED_RPZ
            original_staging = compiler.STAGING_DIR
            original_custom_db = compiler.custom_rules.DB_PATH
            compiler.DB_PATH = tmp_path / "alderpointdns.db"
            compiler.DOWNLOAD_DIR = tmp_path / "downloads"
            compiler.COMPILED_RPZ = tmp_path / "compiled" / "bind" / "alderpointdns.rpz"
            compiler.STAGING_DIR = tmp_path / "staging"
            compiler.custom_rules.DB_PATH = compiler.DB_PATH
            try:
                compiler.init_db()
                with compiler.connect() as conn:
                    conn.execute(
                        "INSERT INTO sources(name, url, enabled, category) VALUES (?, ?, 1, ?)",
                        ("local fixture", (tmp_path / "unused.txt").as_uri(), "ads_trackers"),
                    )
                    conn.commit()
                    source = conn.execute("SELECT * FROM sources WHERE name='local fixture'").fetchone()
                    current, _ = compiler.source_paths(source)
                    current.parent.mkdir(parents=True, exist_ok=True)
                    current.write_text("0.0.0.0 cached.example\n")
                    compiler.record_reusable_protection_policy(conn, compiler.render_rpz({"cached.example"}), 1)
                    compiler.custom_rules.add_rule("/(^|\\.)regex-block\\.example$/")
                    ok, reason = compiler.reusable_protection_policy_available(conn)
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir
                compiler.COMPILED_RPZ = original_rpz
                compiler.STAGING_DIR = original_staging
                compiler.custom_rules.DB_PATH = original_custom_db

        self.assertFalse(ok)
        self.assertIn("regex", reason)

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
