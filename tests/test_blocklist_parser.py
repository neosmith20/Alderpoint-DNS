#!/usr/bin/env python3
import argparse
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import app.alderpointdns_compiler as compiler
from app.alderpointdns_compiler import normalize_domain, parse_rules


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
        ||bad^$third-party
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
                    row = conn.execute("SELECT accepted_domains, last_error FROM sources WHERE id=?", (source["id"],)).fetchone()
            finally:
                compiler.DB_PATH = original_db
                compiler.DOWNLOAD_DIR = original_download_dir

        self.assertTrue(result.success)
        self.assertEqual(3, stats.accepted_domains)
        self.assertEqual(3, row["accepted_domains"])
        self.assertIsNone(row["last_error"])


if __name__ == "__main__":
    unittest.main()
