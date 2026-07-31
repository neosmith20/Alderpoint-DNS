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

    def test_nested_quantifier_redos_shapes_rejected_as_unsupported(self) -> None:
        # These are valid POSIX ERE (no lookaround/backreferences/non-greedy)
        # and would pass posix_ere_incompatibility, but a quantified atom
        # directly inside a quantified group causes catastrophic
        # backtracking in Python's `re` engine, which evaluate_domain() uses
        # for the admin-facing "Test a domain" panel. dnsdist's own POSIX
        # regcomp is a non-backtracking automaton and unaffected, but the
        # same stored pattern must never be usable against Python's `re`.
        cases = [
            "/^(a+)+$/",
            "/(a*)*b/",
            "/(ab+)*c/",
            "/(a+)*(a+)*b/",
            "/^(.*)*$/",
        ]
        for text in cases:
            rule = self.parse_one(text)
            self.assertEqual(rule.validation_state, "unsupported", text)
            self.assertIn("backtracking", rule.unsupported_reason, text)

    def test_bounded_and_alternation_regex_stay_valid(self) -> None:
        # Regression guard: the nested-quantifier check must not reject
        # ordinary bounded repetition or alternation that happens to contain
        # a group.
        for text in (
            "/[a-z0-9]{3,10}\\.example/",
            "/(ads|tracking|metrics)\\.example/",
            "/(abc){2,4}\\.example/",
            "/^ads[0-9]+\\./",
        ):
            rule = self.parse_one(text)
            self.assertEqual(rule.validation_state, "valid", text)

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
        local_dns.add_record("A", "printer.home.arpa", "192.0.2.9")
        custom_rules.add_rule("||printer.home.arpa^")
        verdict = self.evaluate("printer.home.arpa")
        self.assertEqual(verdict["final_action"], "local")
        self.assertEqual(verdict["local_zone"], "home.arpa")


class CompileTests(CustomRulesTestBase):
    def setUp(self) -> None:
        super().setUp()
        compiler.init_db()

    def active(self) -> custom_rules.ActiveRuleSet:
        with self.connect() as conn:
            return custom_rules.collect_active(conn)

    def test_exact_block_has_no_wildcard_and_subdomain_block_has_both(self) -> None:
        custom_rules.add_rule("0.0.0.0 exact.example")
        custom_rules.add_rule("||wild.example^")
        text = compiler.render_rpz(set(), self.active())
        self.assertIn("exact.example CNAME .", text)
        self.assertNotIn("*.exact.example CNAME .", text)
        self.assertIn("wild.example CNAME .", text)
        self.assertIn("*.wild.example CNAME .", text)

    def test_rewrite_records_a_vs_aaaa_and_no_parent_takeover(self) -> None:
        custom_rules.add_rule("192.168.1.50 a.b.example.com")
        custom_rules.add_rule("fd00::9 a.b.example.com")
        text = compiler.render_rpz(set(), self.active())
        self.assertIn("a.b.example.com A 192.168.1.50", text)
        self.assertIn("a.b.example.com AAAA fd00::9", text)
        self.assertNotIn("*.a.b.example.com", text)
        for owner in ("b.example.com", "example.com"):
            for line in text.splitlines():
                self.assertFalse(line.startswith(f"{owner} ") or line.startswith(f"*.{owner} "), line)

    def test_allow_subtracts_covered_external_blocks_and_emits_passthru(self) -> None:
        custom_rules.add_rule("@@||good.example^")
        external = {"good.example", "sub.good.example", "bad.example"}
        active = self.active()
        remaining = custom_rules.subtract_allowed(external, active)
        self.assertEqual(remaining, {"bad.example"})
        text = compiler.render_rpz(remaining, active)
        self.assertIn("good.example CNAME rpz-passthru.", text)
        self.assertIn("*.good.example CNAME rpz-passthru.", text)
        self.assertIn("bad.example CNAME .", text)
        self.assertNotIn("sub.good.example", text)

    def test_exact_allow_subtracts_only_that_entry(self) -> None:
        custom_rules.add_rule("@@|only.example^")
        active = self.active()
        remaining = custom_rules.subtract_allowed({"only.example", "other.example"}, active)
        self.assertEqual(remaining, {"other.example"})
        text = compiler.render_rpz(remaining, active)
        self.assertIn("only.example CNAME rpz-passthru.", text)
        self.assertNotIn("*.only.example CNAME rpz-passthru.", text)

    def test_same_owner_conflicts_rewrite_allow_block_and_important(self) -> None:
        custom_rules.add_rule("10.0.0.1 conflict.example")
        custom_rules.add_rule("@@||conflict.example^")
        custom_rules.add_rule("||conflict.example^")
        active = self.active()
        text = compiler.render_rpz(set(), active)
        # rewrite wins the owner name; allow keeps only its wildcard; block is gone
        self.assertIn("conflict.example A 10.0.0.1", text)
        self.assertIn("*.conflict.example CNAME rpz-passthru.", text)
        self.assertNotIn("conflict.example CNAME .", text.replace("*.conflict.example CNAME rpz-passthru.", ""))
        custom_rules.add_rule("||important.example^$important")
        custom_rules.add_rule("@@||important.example^")
        text = compiler.render_rpz(set(), self.active())
        self.assertIn("important.example CNAME .", text)
        self.assertNotIn("important.example CNAME rpz-passthru.", text)

    def test_disabled_and_non_valid_rules_do_not_compile(self) -> None:
        rule_id = custom_rules.add_rule("||disabled.example^")[0]["id"]
        custom_rules.set_enabled(rule_id, False)
        custom_rules.add_rule("||narrowed.example^$client=10.0.0.8")
        custom_rules.add_rule("! just a comment")
        custom_rules.add_rule("# another comment")
        active = self.active()
        self.assertEqual(active.blocks, {})
        self.assertEqual(active.rewrites, {})
        text = compiler.render_rpz(set(), active)
        self.assertNotIn("disabled.example", text)
        self.assertNotIn("narrowed.example", text)
        self.assertNotIn("comment", text)

    def test_dnsdist_data_files_and_static_lua(self) -> None:
        custom_rules.add_rule("@@||passme.example^")
        custom_rules.add_rule("@@|exactpass.example^")
        custom_rules.add_rule("10.0.0.7 rewriteme.example")
        custom_rules.add_rule("/^ads[0-9]+\\.example$/")
        custom_rules.add_rule("@@/^good\\.example$/")
        data = custom_rules.render_dnsdist_data(self.active(), ["home.arpa"])
        suffixes = data[custom_rules.PASS_SUFFIX_DATA].splitlines()
        self.assertIn("home.arpa", suffixes)
        self.assertIn("passme.example", suffixes)
        exact = data[custom_rules.PASS_EXACT_DATA].splitlines()
        self.assertIn("exactpass.example", exact)
        self.assertIn("rewriteme.example", exact)
        # patterns land in data files verbatim except the trailing-$ translation
        self.assertEqual(data[custom_rules.REGEX_BLOCK_DATA].strip(), "^ads[0-9]+\\.example\\.?$")
        self.assertEqual(data[custom_rules.REGEX_ALLOW_DATA].strip(), "^good\\.example\\.?$")
        lua = custom_rules.render_dnsdist_lua(custom_rules.COMPILED_DNSDIST_DIR)
        for user_text in ("passme", "exactpass", "rewriteme", "ads[0-9]", "good\\."):
            self.assertNotIn(user_text, lua)
        self.assertIn("RegexRule(entry)", lua)
        self.assertIn('PoolAction("alderpointdns_bind")', lua)
        self.assertIn("RCodeAction(DNSRCode.NXDOMAIN)", lua)

    def test_include_migration_is_idempotent_and_backs_up(self) -> None:
        marker = 'addAction(AllRule(), PoolAction("alderpointdns_bind"))'
        custom_rules.DNSDIST_CONF.write_text("-- lab config\n" + marker + "\n")
        self.assertTrue(custom_rules.ensure_dnsdist_custom_include())
        first = custom_rules.DNSDIST_CONF.read_text()
        self.assertIn(str(custom_rules.custom_rules_lua_path()), first)
        self.assertLess(first.index("dofile(alderpointdnsCustomRulesConfig)"), first.index(marker))
        self.assertFalse(custom_rules.ensure_dnsdist_custom_include())
        self.assertEqual(custom_rules.DNSDIST_CONF.read_text(), first)
        self.assertTrue(list(custom_rules.BACKUP_DIR.glob("dnsdist.conf.pre-custom-rules.*")))

    def test_include_migration_requires_marker(self) -> None:
        custom_rules.DNSDIST_CONF.write_text("-- config without the expected marker\n")
        with self.assertRaises(custom_rules.CustomRuleError):
            custom_rules.ensure_dnsdist_custom_include()

    def test_packaging_conf_carries_the_include(self) -> None:
        text = (ROOT / "packaging" / "dnsdist.conf").read_text()
        self.assertIn("/var/lib/alderpointdns/compiled/dnsdist/custom-rules.conf", text)
        self.assertLess(
            text.index("RCodeAction(DNSRCode.REFUSED)"),
            text.index("custom-rules.conf"),
        )
        self.assertLess(
            text.index("custom-rules.conf"),
            text.index('addAction(AllRule(), PoolAction("alderpointdns_bind"))'),
        )


class DeployTests(CustomRulesTestBase):
    def setUp(self) -> None:
        super().setUp()
        compiler.init_db()
        marker = 'addAction(AllRule(), PoolAction("alderpointdns_bind"))'
        custom_rules.DNSDIST_CONF.write_text("-- lab config\n" + marker + "\n")

    def fake_run(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        return subprocess.CompletedProcess(command, 0, "ok\n")

    def failing_check_config(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if command[0] == "dnsdist":
            raise subprocess.CalledProcessError(1, command, "bad config")
        return subprocess.CompletedProcess(command, 0, "ok\n")

    def test_dnsdist_layer_restart_only_on_change(self) -> None:
        custom_rules.add_rule("/^blockme\\./")
        self.commands: list[list[str]] = []
        with self.connect() as conn:
            with mock.patch.object(custom_rules, "run", self.fake_run):
                info = custom_rules.deploy_dnsdist_layer(conn)
        self.assertTrue(info["changed"])
        self.assertTrue(any(command[:2] == ["systemctl", "restart"] for command in self.commands))
        self.assertTrue(any(command[:2] == ["dnsdist", "--check-config"] for command in self.commands))
        self.assertEqual(
            (custom_rules.COMPILED_DNSDIST_DIR / custom_rules.REGEX_BLOCK_DATA).read_text().strip(),
            "^blockme\\.",
        )
        self.commands = []
        with self.connect() as conn:
            with mock.patch.object(custom_rules, "run", self.fake_run):
                info = custom_rules.deploy_dnsdist_layer(conn)
        self.assertFalse(info["changed"])
        self.assertEqual(self.commands, [])

    def test_dnsdist_layer_rolls_back_on_check_failure(self) -> None:
        custom_rules.add_rule("/^first\\./")
        self.commands = []
        with self.connect() as conn:
            with mock.patch.object(custom_rules, "run", self.fake_run):
                custom_rules.deploy_dnsdist_layer(conn)
        before = (custom_rules.COMPILED_DNSDIST_DIR / custom_rules.REGEX_BLOCK_DATA).read_text()
        custom_rules.add_rule("/^second\\./")
        self.commands = []
        with self.connect() as conn:
            with mock.patch.object(custom_rules, "run", self.failing_check_config):
                with self.assertRaises(subprocess.CalledProcessError):
                    custom_rules.deploy_dnsdist_layer(conn)
        self.assertEqual(
            (custom_rules.COMPILED_DNSDIST_DIR / custom_rules.REGEX_BLOCK_DATA).read_text(),
            before,
        )

    def test_full_deploy_writes_custom_rpz_and_dnsdist_files(self) -> None:
        custom_rules.add_rule("||deployblock.example^")
        custom_rules.add_rule("@@||deployallow.example^")
        custom_rules.add_rule("10.0.0.3 deployrewrite.example")
        custom_rules.add_rule("/^deployregex\\./")
        self.commands = []
        with mock.patch.object(compiler, "run", self.fake_run), \
                mock.patch.object(custom_rules, "run", self.fake_run), \
                mock.patch.object(compiler, "resolves", lambda domain: True), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler, "resolves_to", lambda domain, rtype, address: True), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: 1), \
                mock.patch.object(compiler.dns_cache, "deploy_cache_options", lambda conn=None: 1), \
                mock.patch.object(compiler.upstream_dns, "deploy_upstreams", lambda conn=None: 1), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: None):
            deployment_id = compiler.deploy(download=False)
        rpz = compiler.COMPILED_RPZ.read_text()
        self.assertIn("deployblock.example CNAME .", rpz)
        self.assertIn("*.deployblock.example CNAME .", rpz)
        self.assertIn("deployallow.example CNAME rpz-passthru.", rpz)
        self.assertIn("deployrewrite.example A 10.0.0.3", rpz)
        self.assertIn(
            "deployregex",
            (custom_rules.COMPILED_DNSDIST_DIR / custom_rules.REGEX_BLOCK_DATA).read_text(),
        )
        with self.connect() as conn:
            row = conn.execute("SELECT status, active_domains FROM deployments WHERE id=?", (deployment_id,)).fetchone()
        self.assertEqual(row["status"], "deployed")
        self.assertEqual(row["active_domains"], 1)


class WebRouteTests(CustomRulesTestBase):
    def setUp(self) -> None:
        super().setUp()
        from fastapi.testclient import TestClient  # noqa: PLC0415

        from app import replication, webapp  # noqa: PLC0415

        self.webapp = webapp
        self.old["w_DB_PATH"] = webapp.DB_PATH
        webapp.DB_PATH = custom_rules.DB_PATH
        compiler.init_db()
        self.csrf = "test-csrf-token"
        session_id = "test-session-id"
        with self.connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES ('admin', 'x', 'now')")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, admin_id INTEGER, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT, csrf TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES (?, 1, 'now', 'now', '', '', ?)",
                (session_id, self.csrf),
            )
            conn.commit()
        from fastapi.templating import Jinja2Templates  # noqa: PLC0415

        self.patches = [
            mock.patch.object(webapp, "deploy_no_download", lambda: (0, "ok")),
            mock.patch.object(webapp, "deploy_no_download_or_raise", lambda: None),
            mock.patch.object(webapp, "global_service_status", lambda: {"label": "Active", "tone": "healthy", "detail": "test"}),
            mock.patch.object(replication, "autostart", lambda: None),
            # Render the templates checked out with this code, not the ones
            # installed at the live /opt/alderpointdns path.
            mock.patch.object(webapp, "TEMPLATES", Jinja2Templates(directory=str(ROOT / "web" / "templates"))),
        ]
        for patcher in self.patches:
            patcher.start()
        self.client = TestClient(webapp.app)
        self.client.cookies.set(
            "alderpointdns_session",
            webapp.serializer.dumps({"sid": session_id}),
        )

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.webapp.DB_PATH = self.old.pop("w_DB_PATH")
        super().tearDown()

    def test_page_renders_with_counts_filters_and_rules(self) -> None:
        custom_rules.add_rule("||page.example^", comment="page test")
        custom_rules.add_rule("||narrowed.example^$client=10.0.0.4")
        response = self.client.get("/custom-rules")
        self.assertEqual(response.status_code, 200)
        self.assertIn("||page.example^", response.text)
        self.assertIn("Unsupported", response.text)
        self.assertIn("Test a Domain", response.text)
        filtered = self.client.get("/custom-rules?status=unsupported")
        self.assertNotIn("||page.example^", filtered.text)
        self.assertIn("narrowed.example", filtered.text)

    def test_add_bulk_test_and_selected_routes(self) -> None:
        response = self.client.post(
            "/custom-rules/add",
            data={"rule_text": "||web-add.example^", "comment": "", "csrf": self.csrf},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        response = self.client.post(
            "/custom-rules/bulk",
            data={"rules_text": "||web-bulk.example^\nnot ~~ valid", "csrf": self.csrf},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Added 1 active rule(s)", response.text)
        response = self.client.post(
            "/custom-rules/test",
            data={"domain": "sub.web-add.example", "csrf": self.csrf},
        )
        self.assertIn("Blocked", response.text)
        ids = [str(row["id"]) for row in custom_rules.list_rules(status="enabled")]
        response = self.client.post(
            "/custom-rules/selected",
            data={"op": "disable", "ids": ids, "csrf": self.csrf},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(custom_rules.rule_counts()["active"], 0)
        response = self.client.post(
            "/custom-rules/selected",
            data={"op": "delete", "ids": ids, "csrf": self.csrf},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)

    def test_edit_toggle_delete_and_query_log_add(self) -> None:
        rule_id = custom_rules.add_rule("||web-edit.example^")[0]["id"]
        response = self.client.post(
            f"/custom-rules/{rule_id}/edit",
            data={"rule_text": "@@||web-edited.example^", "comment": "c", "enabled": "1", "csrf": self.csrf},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(custom_rules.get_rule(rule_id)["rule_type"], "allow")
        self.client.post(f"/custom-rules/{rule_id}/toggle", data={"csrf": self.csrf}, follow_redirects=False)
        self.assertEqual(custom_rules.get_rule(rule_id)["enabled"], 0)
        self.client.post(f"/custom-rules/{rule_id}/delete", data={"csrf": self.csrf}, follow_redirects=False)
        self.assertIsNone(custom_rules.get_rule(rule_id))
        response = self.client.post(
            "/custom-rules/add-from-query",
            data={"action": "block", "domain": "querylog.example", "csrf": self.csrf},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["location"], "/query-log")
        rows = custom_rules.list_rules(search="querylog.example")
        self.assertEqual(rows[0]["rule_text"], "||querylog.example^")
        self.assertEqual(rows[0]["comment"], "created from query log")

    def test_csrf_required(self) -> None:
        response = self.client.post(
            "/custom-rules/add",
            data={"rule_text": "||nocsrf.example^", "csrf": "wrong"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
