#!/usr/bin/env python3
import unittest

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


if __name__ == "__main__":
    unittest.main()
