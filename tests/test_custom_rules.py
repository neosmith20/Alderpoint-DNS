#!/usr/bin/env python3
from __future__ import annotations

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

from app import alderpointdns_compiler as compiler  # noqa: E402
from app import custom_rules, local_dns  # noqa: E402


class CustomRulesTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-custom-rules-test-"))
        self.old = {
            "cr_DB_PATH": custom_rules.DB_PATH,
            "cr_COMPILED_DNSDIST_DIR": custom_rules.COMPILED_DNSDIST_DIR,
            "cr_DNSDIST_CONF": custom_rules.DNSDIST_CONF,
            "cr_DNSDIST_PACKAGING_CONF": custom_rules.DNSDIST_PACKAGING_CONF,
            "cr_BACKUP_DIR": custom_rules.BACKUP_DIR,
            "cr_STAGING_DIR": custom_rules.STAGING_DIR,
            "c_DB_PATH": compiler.DB_PATH,
            "c_DOWNLOAD_DIR": compiler.DOWNLOAD_DIR,
            "c_COMPILED_RPZ": compiler.COMPILED_RPZ,
            "c_STAGING_DIR": compiler.STAGING_DIR,
            "c_BACKUP_DIR": compiler.BACKUP_DIR,
            "c_DEPLOY_LOCK": compiler.DEPLOY_LOCK,
            "l_DB_PATH": local_dns.DB_PATH,
        }
        db_path = self.tmp / "alderpointdns.db"
        custom_rules.DB_PATH = db_path
        custom_rules.COMPILED_DNSDIST_DIR = self.tmp / "compiled" / "dnsdist"
        custom_rules.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        custom_rules.DNSDIST_PACKAGING_CONF = self.tmp / "packaging-dnsdist.conf"
        custom_rules.BACKUP_DIR = self.tmp / "backups"
        custom_rules.STAGING_DIR = self.tmp / "staging"
        compiler.DB_PATH = db_path
        compiler.DOWNLOAD_DIR = self.tmp / "downloads"
        compiler.COMPILED_RPZ = self.tmp / "compiled" / "bind" / "alderpointdns.rpz"
        compiler.STAGING_DIR = self.tmp / "staging"
        compiler.BACKUP_DIR = self.tmp / "backups"
        compiler.DEPLOY_LOCK = self.tmp / "staging" / "deploy.lock"
        local_dns.DB_PATH = db_path
        custom_rules.STAGING_DIR.mkdir(parents=True)

    def tearDown(self) -> None:
        for key, value in self.old.items():
            prefix, name = key.split("_", 1)
            module = {"cr": custom_rules, "c": compiler, "l": local_dns}[prefix]
            setattr(module, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(custom_rules.DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn


class ParserTests(CustomRulesTestBase):
    def parse_one(self, text: str, **kwargs) -> custom_rules.ParsedRule:
        rules = custom_rules.parse_rule(text, **kwargs)
        self.assertEqual(len(rules), 1, f"expected one rule for {text!r}, got {rules}")
        return rules[0]

    def test_adblock_subdomain_block(self) -> None:
        rule = self.parse_one("||example.org^")
        self.assertEqual((rule.rule_type, rule.action, rule.domain, rule.match_subdomains), ("block", "block", "example.org", True))
        self.assertEqual(rule.validation_state, "valid")

    def test_adblock_exact_block(self) -> None:
        rule = self.parse_one("|example.org^")
        self.assertEqual((rule.rule_type, rule.domain, rule.match_subdomains), ("block", "example.org", False))

    def test_adblock_allow(self) -> None:
        rule = self.parse_one("@@||example.org^")
        self.assertEqual((rule.rule_type, rule.action, rule.match_subdomains), ("allow", "allow", True))

    def test_plain_domain_adguard_vs_pihole_conformance(self) -> None:
        adguard = self.parse_one("tracker.example", plain_domain_subdomains=True)
        self.assertTrue(adguard.match_subdomains, "AdGuard plain-domain DNS rules cover subdomains")
        pihole = self.parse_one("tracker.example", plain_domain_subdomains=False)
        self.assertFalse(pihole.match_subdomains, "Pi-hole exact-domain entries are exact-host")
        self.assertEqual(adguard.rule_type, "block")
        self.assertEqual(pihole.rule_type, "block")

    def test_hosts_blocking_sentinels_and_rewrites(self) -> None:
        blocked = self.parse_one("0.0.0.0 ads.example.org")
        self.assertEqual((blocked.rule_type, blocked.domain, blocked.match_subdomains), ("block", "ads.example.org", False))
        loopback = self.parse_one("127.0.0.1 example.org")
        self.assertEqual((loopback.rule_type, loopback.rewrite_address, loopback.address_family), ("rewrite", "127.0.0.1", "ipv4"))
        rewrite = self.parse_one("192.168.1.50 internal.example.org")
        self.assertEqual((rewrite.rule_type, rewrite.rewrite_address, rewrite.match_subdomains), ("rewrite", "192.168.1.50", False))
        v6 = self.parse_one("::1 ipv6-example.org")
        self.assertEqual((v6.rule_type, v6.rewrite_address, v6.address_family), ("rewrite", "::1", "ipv6"))
        v6_sentinel = self.parse_one(":: blocked-v6.example.org")
        self.assertEqual(v6_sentinel.rule_type, "block")

    def test_hosts_aliases_and_inline_comment(self) -> None:
        rules = custom_rules.parse_rule("0.0.0.0 one.example two.example # office kiosk")
        self.assertEqual(len(rules), 2)
        self.assertEqual({r.domain for r in rules}, {"one.example", "two.example"})
        self.assertTrue(all(r.comment == "office kiosk" for r in rules))

    def test_comment_rules(self) -> None:
        bang = self.parse_one("! section header")
        hash_comment = self.parse_one("# hosts style comment")
        for rule in (bang, hash_comment):
            self.assertEqual((rule.rule_type, rule.action), ("comment", "none"))
            self.assertEqual(rule.validation_state, "valid")

    def test_regex_block_and_allow(self) -> None:
        block = self.parse_one("/^ads[0-9]+\\./")
        self.assertEqual((block.rule_type, block.action, block.pattern), ("regex_block", "block", "^ads[0-9]+\\."))
        allow = self.parse_one("@@/^good[0-9]+\\.example\\.org$/")
        self.assertEqual((allow.rule_type, allow.action), ("regex_allow", "allow"))

    def test_regex_posix_incompatibilities_rejected_as_unsupported(self) -> None:
        cases = {
            "/\\d+tracker/": "\\d",
            "/foo(?=bar)/": "(?",
            "/(a)\\1/": "\\1",
            "/a+?b/": "non-greedy",
            "/(?P<x>abc)/": "(?",
            "/\\w\\s\\b/": "\\w",
        }
        for text in cases:
            rule = self.parse_one(text)
            self.assertEqual(rule.validation_state, "unsupported", text)
            self.assertTrue(rule.unsupported_reason, text)

    def test_regex_limits_and_compile_failures(self) -> None:
        too_long = "/" + "a" * 600 + "/"
        self.assertEqual(self.parse_one(too_long).validation_state, "unsupported")
        broken = self.parse_one("/([unclosed/")
        self.assertEqual(broken.validation_state, "unsupported")
        self.assertIn("compile", broken.unsupported_reason)

    def test_control_characters_and_newlines_rejected(self) -> None:
        rule = self.parse_one("||example.org^\x07")
        self.assertEqual(rule.validation_state, "invalid")
        multiline = custom_rules.parse_rule("||a.example^\n||b.example^")
        self.assertEqual(multiline[0].validation_state, "invalid")

    def test_important_modifier_sets_priority(self) -> None:
        rule = self.parse_one("||urgent.example^$important")
        self.assertEqual(rule.priority, custom_rules.IMPORTANT_PRIORITY)
        self.assertEqual(rule.validation_state, "valid")

    def test_dnsrewrite_modifier_plain_and_typed(self) -> None:
        plain = self.parse_one("||nas.example^$dnsrewrite=192.168.1.9")
        self.assertEqual((plain.rule_type, plain.rewrite_address, plain.match_subdomains), ("rewrite", "192.168.1.9", True))
        typed = self.parse_one("|host.example^$dnsrewrite=NOERROR;A;1.2.3.4")
        self.assertEqual((typed.rule_type, typed.rewrite_address, typed.match_subdomains), ("rewrite", "1.2.3.4", False))
        typed6 = self.parse_one("|host6.example^$dnsrewrite=NOERROR;AAAA;fd00::9")
        self.assertEqual(typed6.address_family, "ipv6")

    def test_dnsrewrite_unsupported_forms(self) -> None:
        for text in (
            "||cname.example^$dnsrewrite=NOERROR;CNAME;other.example",
            "||nx.example^$dnsrewrite=NXDOMAIN;;",
            "||mismatch.example^$dnsrewrite=NOERROR;A;fd00::1",
        ):
            rule = self.parse_one(text)
            self.assertEqual(rule.validation_state, "unsupported", text)
            self.assertIn("dnsrewrite", rule.unsupported_reason)

    def test_narrowing_modifiers_never_activate_broadened_rule(self) -> None:
        for text, needle in (
            ("||ads.example^$client=192.168.1.7", "$client"),
            ("||ads.example^$dnstype=AAAA", "$dnstype"),
            ("||ads.example^$denyallow=good.example", "$denyallow"),
            ("||ads.example^$ctag=device_pc", "$ctag"),
            ("||ads.example^$badfilter", "$badfilter"),
            ("||ads.example^$unknownmod", "$unknownmod"),
        ):
            rule = self.parse_one(text)
            self.assertEqual(rule.validation_state, "unsupported", text)
            self.assertIn(needle, rule.unsupported_reason)

    def test_invalid_domain_and_address(self) -> None:
        self.assertEqual(self.parse_one("||not a domain^").validation_state, "invalid")
        self.assertEqual(self.parse_one("not_even..a..domain..").validation_state, "invalid")
        hosts = custom_rules.parse_rule("0.0.0.0 bad_host!name")
        self.assertEqual(hosts[0].validation_state, "invalid")

    def test_deployed_pattern_translation(self) -> None:
        self.assertEqual(custom_rules.deployed_pattern("^ads\\."), "^ads\\.")
        self.assertEqual(custom_rules.deployed_pattern("tracker\\.example$"), "tracker\\.example\\.?$")
        # escaped dollar is literal, so it must not be translated
        self.assertEqual(custom_rules.deployed_pattern("price\\$"), "price\\$")


class ModelTests(CustomRulesTestBase):
    def test_add_rule_and_duplicate_detection(self) -> None:
        first = custom_rules.add_rule("||dup.example^")
        self.assertEqual(first[0]["status"], "added")
        again = custom_rules.add_rule("||dup.example^")
        self.assertEqual(again[0]["status"], "duplicate")
        self.assertEqual(again[0]["id"], first[0]["id"])
        # same domain, opposite action is not a duplicate
        allow = custom_rules.add_rule("@@||dup.example^")
        self.assertEqual(allow[0]["status"], "added")

    def test_unsupported_and_invalid_rules_stored_inactive(self) -> None:
        custom_rules.add_rule("||ads.example^$client=10.0.0.9")
        custom_rules.add_rule("||broken domain^")
        rows = custom_rules.list_rules()
        by_state = {row["validation_state"]: row for row in rows}
        self.assertEqual(by_state["unsupported"]["enabled"], 0)
        self.assertEqual(by_state["invalid"]["enabled"], 0)
        self.assertTrue(by_state["unsupported"]["unsupported_reason"])
        with self.assertRaises(custom_rules.CustomRuleError):
            custom_rules.set_enabled(by_state["unsupported"]["id"], True)

    def test_bulk_add_reports_per_line_results(self) -> None:
        text = "\n".join(
            [
                "! imported set",
                "||bulk-a.example^",
                "@@||bulk-b.example^",
                "||bulk-a.example^",
                "/(?P<bad>x)/",
                "definitely not ~~ a rule",
                "",
            ]
        )
        summary = custom_rules.add_rules_bulk(text, source_system="import")
        self.assertEqual(summary["added_active"], 2)
        self.assertEqual(summary["duplicates"], 1)
        self.assertEqual(summary["unsupported"], 1)
        self.assertEqual(summary["invalid"], 1)
        self.assertEqual(summary["comments"], 1)
        self.assertEqual(len(summary["lines"]), 6)

    def test_update_toggle_delete_and_bulk_operations(self) -> None:
        rule_id = custom_rules.add_rule("||edit.example^")[0]["id"]
        custom_rules.update_rule(rule_id, "@@||edited.example^", comment="changed", enabled=False)
        row = custom_rules.get_rule(rule_id)
        self.assertEqual((row["rule_type"], row["enabled"], row["comment"]), ("allow", 0, "changed"))
        custom_rules.toggle_rule(rule_id)
        self.assertEqual(custom_rules.get_rule(rule_id)["enabled"], 1)
        other = custom_rules.add_rule("||other.example^")[0]["id"]
        result = custom_rules.bulk_set_enabled([rule_id, other], False)
        self.assertEqual(result["updated"], 2)
        self.assertEqual(custom_rules.bulk_delete([rule_id, other]), 2)
        self.assertIsNone(custom_rules.get_rule(rule_id))

    def test_list_filters_and_counts(self) -> None:
        custom_rules.add_rule("||list-a.example^", comment="alpha")
        custom_rules.add_rule("@@||list-b.example^")
        custom_rules.add_rule("/^listre\\./")
        custom_rules.add_rule("||list-c.example^$dnstype=TXT")
        self.assertEqual(len(custom_rules.list_rules(search="alpha")), 1)
        self.assertEqual(len(custom_rules.list_rules(rule_type="allow")), 1)
        self.assertEqual(len(custom_rules.list_rules(status="unsupported")), 1)
        counts = custom_rules.rule_counts()
        self.assertEqual(counts["total"], 4)
        self.assertEqual(counts["active"], 3)
        self.assertEqual(counts["unsupported"], 1)
        self.assertEqual(counts["regex"], 1)

    def test_source_system_and_import_job_id_attached(self) -> None:
        result = custom_rules.add_rule("||import.example^", source_system="adguard", import_job_id=7)
        row = custom_rules.get_rule(result[0]["id"])
        self.assertEqual((row["source_system"], row["import_job_id"]), ("adguard", 7))

    def test_legacy_migration_is_idempotent_and_preserves_rows(self) -> None:
        compiler.init_db()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO custom_rules(domain, action, enabled, comment, created_at) VALUES (?, 'block', 1, 'old block', '2025-01-01T00:00:00+00:00')",
                ("legacy-block.example",),
            )
            conn.execute(
                "INSERT INTO custom_rules(domain, action, enabled, comment, created_at) VALUES (?, 'allow', 0, 'old allow', '2025-01-02T00:00:00+00:00')",
                ("legacy-allow.example",),
            )
            conn.execute("UPDATE custom_rules SET migrated_to_v2=0")
            conn.commit()
        custom_rules.init_db()
        custom_rules.init_db()
        rows = [row for row in custom_rules.list_rules() if row["source_system"] == "legacy"]
        self.assertEqual(len(rows), 2)
        by_domain = {row["domain"]: row for row in rows}
        block = by_domain["legacy-block.example"]
        allow = by_domain["legacy-allow.example"]
        self.assertEqual((block["rule_type"], block["match_subdomains"], block["enabled"]), ("block", 1, 1))
        self.assertEqual((allow["rule_type"], allow["enabled"], allow["comment"]), ("allow", 0, "old allow"))
        self.assertEqual(allow["created_at"], "2025-01-02T00:00:00+00:00")
        # legacy table stays intact for backups/replication
        with self.connect() as conn:
            legacy = conn.execute("SELECT count(*) AS n, sum(migrated_to_v2) AS m FROM custom_rules").fetchone()
        self.assertEqual((legacy["n"], legacy["m"]), (2, 2))


class EvaluationTests(CustomRulesTestBase):
    def setUp(self) -> None:
        super().setUp()
        compiler.init_db()

    def evaluate(self, domain: str) -> dict:
        with self.connect() as conn:
            return custom_rules.evaluate_domain(conn, domain)

    def test_block_allow_and_rewrite_verdicts(self) -> None:
        custom_rules.add_rule("||blocked.example^")
        custom_rules.add_rule("@@||allowed.example^")
        custom_rules.add_rule("10.0.0.5 nas.example")
        self.assertEqual(self.evaluate("sub.blocked.example")["final_action"], "block")
        self.assertEqual(self.evaluate("deep.allowed.example")["final_action"], "allow")
        rewrite = self.evaluate("nas.example")
        self.assertEqual(rewrite["final_action"], "rewrite")
        self.assertIn("10.0.0.5", rewrite["response"])
        self.assertEqual(self.evaluate("unrelated.example")["final_action"], "resolve")

    def test_exact_rules_do_not_cover_subdomains(self) -> None:
        custom_rules.add_rule("0.0.0.0 exact.example")
        self.assertEqual(self.evaluate("exact.example")["final_action"], "block")
        self.assertEqual(self.evaluate("sub.exact.example")["final_action"], "resolve")

    def test_important_block_beats_allow(self) -> None:
        custom_rules.add_rule("@@||contested.example^")
        custom_rules.add_rule("||contested.example^$important")
        verdict = self.evaluate("contested.example")
        self.assertEqual(verdict["final_action"], "block")
        self.assertIn("important", verdict["response"])

    def test_allow_beats_normal_block_at_same_name(self) -> None:
        custom_rules.add_rule("||contested.example^")
        custom_rules.add_rule("@@||contested.example^")
        self.assertEqual(self.evaluate("contested.example")["final_action"], "allow")

    def test_more_specific_rule_wins_across_names(self) -> None:
        custom_rules.add_rule("@@||parent.example^")
        custom_rules.add_rule("||child.parent.example^")
        self.assertEqual(self.evaluate("child.parent.example")["final_action"], "block")
        self.assertEqual(self.evaluate("other.parent.example")["final_action"], "allow")

    def test_regex_precedence_and_rpz_reporting(self) -> None:
        custom_rules.add_rule("/^regexblock[0-9]*\\./")
        custom_rules.add_rule("@@/^regexpass\\./")
        self.assertEqual(self.evaluate("regexblock7.example")["final_action"], "block")
        self.assertEqual(self.evaluate("regexpass.example")["final_action"], "allow")
        compiler.COMPILED_RPZ.parent.mkdir(parents=True, exist_ok=True)
        compiler.COMPILED_RPZ.write_text(
            "$TTL 2h\n@ IN SOA localhost. hostmaster.localhost. 1 1h 15m 30d 2h\n@ IN NS localhost.\n\n"
            "listed.example CNAME .\n*.listed.example CNAME .\nregexpass.example CNAME .\n*.regexpass.example CNAME .\n"
        )
        verdict = self.evaluate("sub.listed.example")
        self.assertEqual(verdict["final_action"], "block")
        self.assertEqual(verdict["rpz"]["match"], "wildcard")
        # regex allow only bypasses regex blocks, not external RPZ entries
        self.assertEqual(self.evaluate("regexpass.example")["final_action"], "block")

    def test_comment_rules_have_no_dns_effect(self) -> None:
        custom_rules.add_rule("! block everything below")
        custom_rules.add_rule("# another note")
        self.assertEqual(self.evaluate("anything.example")["final_action"], "resolve")

    def test_local_zone_wins_over_custom_block(self) -> None:
        local_dns.add_record("A", "printer.home.arpa", "172.16.40.9")
        custom_rules.add_rule("||printer.home.arpa^")
        verdict = self.evaluate("printer.home.arpa")
        self.assertEqual(verdict["final_action"], "local")
        self.assertEqual(verdict["local_zone"], "home.arpa")


if __name__ == "__main__":
    unittest.main()
