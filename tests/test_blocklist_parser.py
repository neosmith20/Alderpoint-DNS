#!/usr/bin/env python3
import argparse
import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import app.bindguard_compiler as compiler
from app.bindguard_compiler import normalize_domain, parse_rules


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
            compiler.DB_PATH = Path(tmp) / "bindguard.db"
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


if __name__ == "__main__":
    unittest.main()
