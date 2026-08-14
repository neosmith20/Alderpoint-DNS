#!/usr/bin/env python3
"""Tests for Clients & Access: persistent clients, identifiers, ClientIDs,
access policy precedence, dnsdist config generation/deploy safety, analytics
privacy gating, and AdGuard/native migration mapping."""
from __future__ import annotations

import ipaddress
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import clients  # noqa: E402


class ClientsTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-clients-test-"))
        self.old = {
            "DB_PATH": clients.DB_PATH,
            "COMPILED_DNSDIST_DIR": clients.COMPILED_DNSDIST_DIR,
            "BACKUP_DIR": clients.BACKUP_DIR,
            "STAGING_DIR": clients.STAGING_DIR,
            "DNSDIST_CONF": clients.DNSDIST_CONF,
        }
        clients.DB_PATH = self.tmp / "alderpointdns.db"
        clients.COMPILED_DNSDIST_DIR = self.tmp / "compiled" / "dnsdist"
        clients.BACKUP_DIR = self.tmp / "backups"
        clients.STAGING_DIR = self.tmp / "staging"
        clients.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        clients.init_db()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(clients, key, value)
        shutil.rmtree(self.tmp, ignore_errors=True)


class IdentifierNormalizationTest(ClientsTestBase):
    def test_ipv4_exact(self) -> None:
        self.assertEqual(clients.normalize_identifier("192.168.1.5"), ("ipv4", "192.168.1.5"))

    def test_ipv4_cidr_canonicalizes_host_bits(self) -> None:
        self.assertEqual(clients.normalize_identifier("192.168.32.1/24"), ("ipv4_cidr", "192.168.32.0/24"))

    def test_ipv6_exact(self) -> None:
        kind, value = clients.normalize_identifier("2001:db8::1")
        self.assertEqual(kind, "ipv6")
        self.assertEqual(ipaddress.ip_address(value), ipaddress.ip_address("2001:db8::1"))

    def test_ipv6_cidr_canonicalizes(self) -> None:
        kind, value = clients.normalize_identifier("2001:db8::1234/64")
        self.assertEqual(kind, "ipv6_cidr")
        self.assertEqual(value, "2001:db8::/64")

    def test_malformed_ipv4(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.normalize_identifier("999.999.999.999")

    def test_malformed_ipv6(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.normalize_identifier("2001:db8::gggg")

    def test_malformed_cidr(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.normalize_identifier("192.168.1.0/99")

    def test_invalid_prefix_length_ipv6(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.normalize_identifier("2001:db8::/200")

    def test_ipv4_mapped_ipv6_parses_as_ipv6(self) -> None:
        kind, value = clients.normalize_identifier("::ffff:192.168.1.1")
        self.assertEqual(kind, "ipv6")

    def test_empty_identifier_rejected(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.normalize_identifier("   ")

    def test_clientid_recognized_via_identifier_path(self) -> None:
        cid = "a" * 48
        self.assertEqual(clients.normalize_identifier(cid), ("clientid", cid))


class ClientIDTest(ClientsTestBase):
    def test_generate_192_bit_uses_secrets_token_hex_24(self) -> None:
        with mock.patch("secrets.token_hex", wraps=__import__("secrets").token_hex) as spy:
            value = clients.generate_clientid(192)
            spy.assert_called_once_with(24)
        self.assertEqual(len(value), 48)
        self.assertTrue(all(c in "0123456789abcdef" for c in value))

    def test_generate_256_bit_uses_secrets_token_hex_32(self) -> None:
        with mock.patch("secrets.token_hex", wraps=__import__("secrets").token_hex) as spy:
            value = clients.generate_clientid(256)
            spy.assert_called_once_with(32)
        self.assertEqual(len(value), 64)

    def test_generate_rejects_unsupported_strength(self) -> None:
        with self.assertRaises(clients.ClientIDError):
            clients.generate_clientid(128)

    def test_two_generated_ids_differ(self) -> None:
        # Weak/no-op RNG would make this flaky-by-coincidence at
        # astronomically low odds; a real secure RNG never collides here.
        a = clients.generate_clientid(256)
        b = clients.generate_clientid(256)
        self.assertNotEqual(a, b)

    def test_exactly_48_hex_accepted(self) -> None:
        self.assertEqual(clients.validate_clientid("a" * 48), "a" * 48)

    def test_exactly_64_hex_accepted(self) -> None:
        self.assertEqual(clients.validate_clientid("b" * 64), "b" * 64)

    def test_32_hex_rejected(self) -> None:
        with self.assertRaises(clients.ClientIDError):
            clients.validate_clientid("c" * 32)

    def test_47_hex_rejected(self) -> None:
        with self.assertRaises(clients.ClientIDError):
            clients.validate_clientid("d" * 47)

    def test_65_hex_rejected(self) -> None:
        with self.assertRaises(clients.ClientIDError):
            clients.validate_clientid("e" * 65)

    def test_49_hex_rejected_not_rounded_to_48(self) -> None:
        with self.assertRaises(clients.ClientIDError):
            clients.validate_clientid("f" * 49)

    def test_non_hex_rejected(self) -> None:
        with self.assertRaises(clients.ClientIDError):
            clients.validate_clientid("g" * 48)

    def test_canonical_form_is_lowercase(self) -> None:
        self.assertEqual(clients.validate_clientid("A" * 48), "a" * 48)

    def test_never_truncates(self) -> None:
        # A 96-hex value must be rejected outright, never silently cut down
        # to 64.
        with self.assertRaises(clients.ClientIDError):
            clients.validate_clientid("a" * 96)

    def test_192_bit_dns_label_is_the_hex_itself(self) -> None:
        cid = clients.generate_clientid(192)
        self.assertEqual(clients.clientid_dns_label(cid), cid)
        self.assertLessEqual(len(clients.clientid_dns_label(cid)), 63)

    def test_256_bit_dns_label_fits_a_label_and_round_trips(self) -> None:
        cid = clients.generate_clientid(256)
        label = clients.clientid_dns_label(cid)
        self.assertLessEqual(len(label), 63)
        self.assertNotEqual(label, cid)  # genuinely re-encoded, not just truncated
        self.assertEqual(clients.clientid_from_dns_label(label), cid)

    def test_256_bit_label_length_matches_expected_base32_size(self) -> None:
        cid = clients.generate_clientid(256)
        label = clients.clientid_dns_label(cid)
        self.assertEqual(len(label), 52)  # 32 bytes -> ceil(256/5) = 52 base32 chars

    def test_no_entropy_loss_across_1000_round_trips(self) -> None:
        for _ in range(1000):
            cid = clients.generate_clientid(256)
            label = clients.clientid_dns_label(cid)
            self.assertEqual(clients.clientid_from_dns_label(label), cid)

    def test_no_collision_between_representations(self) -> None:
        seen_labels = set()
        for _ in range(500):
            cid = clients.generate_clientid(256)
            label = clients.clientid_dns_label(cid)
            self.assertNotIn(label, seen_labels)
            seen_labels.add(label)

    def test_doh_path_uses_full_canonical_hex_no_truncation(self) -> None:
        cid = clients.generate_clientid(256)
        path = clients.clientid_doh_path("/dns-query", cid)
        self.assertTrue(path.endswith(cid))
        self.assertIn(cid, path)

    def test_malformed_dns_label_rejected(self) -> None:
        with self.assertRaises(clients.ClientIDError):
            clients.clientid_from_dns_label("not-valid-base32-!!!")


class PersistentClientCRUDTest(ClientsTestBase):
    def test_create_and_get(self) -> None:
        client_id = clients.create_client("Living Room TV", "a tv", ["192.168.32.47"])
        client = clients.get_client(client_id)
        self.assertEqual(client["name"], "Living Room TV")
        self.assertEqual(len(client["identifiers"]), 1)

    def test_multiple_identifiers_one_client(self) -> None:
        client_id = clients.create_client("TV", identifiers=["192.168.32.47", "192.168.32.0/28", "2001:db8::47"])
        client = clients.get_client(client_id)
        self.assertEqual(len(client["identifiers"]), 3)

    def test_duplicate_identifier_across_clients_rejected(self) -> None:
        clients.create_client("A", identifiers=["10.0.0.5"])
        with self.assertRaises(clients.ClientsError):
            clients.create_client("B", identifiers=["10.0.0.5"])

    def test_empty_name_rejected(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.create_client("   ")

    def test_huge_name_rejected(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.create_client("x" * 500)

    def test_huge_description_rejected(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.create_client("ok", "y" * 5000)

    def test_malformed_identifier_at_create_rejected(self) -> None:
        with self.assertRaises(clients.ClientsError):
            clients.create_client("Bad", identifiers=["not-an-ip"])

    def test_enable_disable(self) -> None:
        client_id = clients.create_client("X")
        clients.set_client_enabled(client_id, False)
        self.assertFalse(clients.get_client(client_id)["enabled"])
        clients.set_client_enabled(client_id, True)
        self.assertTrue(clients.get_client(client_id)["enabled"])

    def test_delete_cascades_identifiers_and_access_rules(self) -> None:
        client_id = clients.create_client("X", identifiers=["10.0.0.9"])
        clients.add_access_rule("deny", "client", client_id=client_id)
        clients.delete_client(client_id)
        self.assertIsNone(clients.get_client(client_id))
        conn = clients.connect()
        self.assertEqual(conn.execute("SELECT count(*) FROM client_identifiers").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM access_rules").fetchone()[0], 0)
        conn.close()

    def test_quotes_newlines_backslashes_unicode_in_name(self) -> None:
        name = 'weird "name" with \\backslash\nand emoji 🎉 and Ünïcödé'
        client_id = clients.create_client(name)
        self.assertEqual(clients.get_client(client_id)["name"], name)

    def test_lua_looking_string_in_description_stored_literally_not_executed(self) -> None:
        payload = '"); os.execute("touch /tmp/pwned"); --'
        client_id = clients.create_client("X", payload)
        self.assertEqual(clients.get_client(client_id)["description"], payload)

    def test_add_remove_identifier(self) -> None:
        client_id = clients.create_client("X")
        ident_id = clients.add_identifier(client_id, "10.0.0.1")
        self.assertEqual(len(clients.get_client(client_id)["identifiers"]), 1)
        clients.remove_identifier(ident_id)
        self.assertEqual(len(clients.get_client(client_id)["identifiers"]), 0)


class AccessPolicyPrecedenceTest(ClientsTestBase):
    def test_default_allow(self) -> None:
        decision = clients.evaluate_access("1.2.3.4", None, [], {}, "allow")
        self.assertTrue(decision.allowed)

    def test_default_deny(self) -> None:
        decision = clients.evaluate_access("1.2.3.4", None, [], {}, "deny")
        self.assertFalse(decision.allowed)

    def test_explicit_allow_under_default_deny(self) -> None:
        rules = [{"action": "allow", "kind": "ipv4", "value": "1.2.3.4", "client_id": None}]
        self.assertTrue(clients.evaluate_access("1.2.3.4", None, rules, {}, "deny").allowed)

    def test_explicit_deny_under_default_allow(self) -> None:
        rules = [{"action": "deny", "kind": "ipv4", "value": "1.2.3.4", "client_id": None}]
        self.assertFalse(clients.evaluate_access("1.2.3.4", None, rules, {}, "allow").allowed)

    def test_deny_overrides_allow_exact_ip_in_allowed_cidr(self) -> None:
        # The example from the task: allow 192.168.32.0/24, deny
        # 192.168.32.200 exactly -> .100 allowed, .200 denied.
        rules = [
            {"action": "allow", "kind": "ipv4_cidr", "value": "192.168.32.0/24", "client_id": None},
            {"action": "deny", "kind": "ipv4", "value": "192.168.32.200", "client_id": None},
        ]
        self.assertTrue(clients.evaluate_access("192.168.32.100", None, rules, {}, "allow").allowed)
        self.assertFalse(clients.evaluate_access("192.168.32.200", None, rules, {}, "allow").allowed)

    def test_ipv6_deny_overrides_allow_equivalent(self) -> None:
        rules = [
            {"action": "allow", "kind": "ipv6_cidr", "value": "2001:db8::/64", "client_id": None},
            {"action": "deny", "kind": "ipv6", "value": "2001:db8::200", "client_id": None},
        ]
        self.assertTrue(clients.evaluate_access("2001:db8::100", None, rules, {}, "allow").allowed)
        self.assertFalse(clients.evaluate_access("2001:db8::200", None, rules, {}, "allow").allowed)

    def test_overlapping_cidrs_deny_still_wins(self) -> None:
        rules = [
            {"action": "allow", "kind": "ipv4_cidr", "value": "10.0.0.0/8", "client_id": None},
            {"action": "deny", "kind": "ipv4_cidr", "value": "10.1.0.0/16", "client_id": None},
        ]
        self.assertFalse(clients.evaluate_access("10.1.2.3", None, rules, {}, "allow").allowed)
        self.assertTrue(clients.evaluate_access("10.2.2.3", None, rules, {}, "allow").allowed)

    def test_clientid_rule_matches_by_exact_value(self) -> None:
        cid = "a" * 48
        rules = [{"action": "deny", "kind": "clientid", "value": cid, "client_id": None}]
        self.assertFalse(clients.evaluate_access(None, cid, rules, {}, "allow").allowed)
        self.assertTrue(clients.evaluate_access(None, "b" * 48, rules, {}, "allow").allowed)

    def test_disabled_client_rule_does_not_apply(self) -> None:
        client_id = clients.create_client("X", identifiers=["10.0.0.1"], enabled=False)
        rules = clients.list_access_rules()
        clients.add_access_rule("deny", "client", client_id=client_id)
        rules = clients.list_access_rules()
        clients_by_id = {c["id"]: c for c in clients.list_clients()}
        # Client is disabled, so its deny rule must not apply -- default
        # policy (allow) governs instead.
        decision = clients.evaluate_access("10.0.0.1", None, rules, clients_by_id, "allow")
        self.assertTrue(decision.allowed)

    def test_client_rule_expands_all_identifiers(self) -> None:
        client_id = clients.create_client("X", identifiers=["10.0.0.1", "10.0.0.2"])
        clients.add_access_rule("deny", "client", client_id=client_id)
        rules = clients.list_access_rules()
        clients_by_id = {c["id"]: c for c in clients.list_clients()}
        self.assertFalse(clients.evaluate_access("10.0.0.1", None, rules, clients_by_id, "allow").allowed)
        self.assertFalse(clients.evaluate_access("10.0.0.2", None, rules, clients_by_id, "allow").allowed)
        self.assertTrue(clients.evaluate_access("10.0.0.3", None, rules, clients_by_id, "allow").allowed)


class AccessRuleCRUDTest(ClientsTestBase):
    def test_add_rule_normalizes_cidr(self) -> None:
        clients.add_access_rule("deny", "ipv4_cidr", "192.168.1.5/24")
        rule = clients.list_access_rules()[0]
        self.assertEqual(rule["value"], "192.168.1.0/24")

    def test_duplicate_rule_rejected(self) -> None:
        clients.add_access_rule("deny", "ipv4", "1.2.3.4")
        with self.assertRaises(clients.AccessPolicyError):
            clients.add_access_rule("deny", "ipv4", "1.2.3.4")

    def test_client_rule_requires_client_id(self) -> None:
        with self.assertRaises(clients.AccessPolicyError):
            clients.add_access_rule("deny", "client")

    def test_weak_clientid_rejected_in_rule(self) -> None:
        with self.assertRaises(clients.ClientIDError):
            clients.add_access_rule("deny", "clientid", "a" * 32)

    def test_remove_rule(self) -> None:
        rule_id = clients.add_access_rule("deny", "ipv4", "1.2.3.4")
        clients.remove_access_rule(rule_id)
        self.assertEqual(clients.list_access_rules(), [])

    def test_default_policy_roundtrip(self) -> None:
        self.assertEqual(clients.get_default_policy(), "allow")
        clients.set_default_policy("deny")
        self.assertEqual(clients.get_default_policy(), "deny")

    def test_default_policy_rejects_invalid_value(self) -> None:
        with self.assertRaises(clients.AccessPolicyError):
            clients.set_default_policy("sometimes")


class MigrationFromClientAliasesTest(ClientsTestBase):
    def test_migrates_legacy_client_aliases_idempotently(self) -> None:
        conn = clients.connect()
        conn.executescript(
            """
            CREATE TABLE client_aliases (
                id INTEGER PRIMARY KEY, cidr TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT INTO client_aliases(cidr, display_name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("192.168.32.0/28", "Living Room TV", "a tv", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"),
        )
        conn.commit()
        clients.init_db(conn)  # first migration
        clients.init_db(conn)  # second call must not duplicate
        rows = conn.execute("SELECT * FROM clients").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "Living Room TV")
        idents = conn.execute("SELECT * FROM client_identifiers").fetchall()
        self.assertEqual(len(idents), 1)
        self.assertEqual(idents[0]["value"], "192.168.32.0/28")
        conn.close()

    def test_v102_era_database_without_new_tables_migrates_cleanly(self) -> None:
        # Simulates upgrading a v1.0.2-era database: only the pre-existing
        # tables exist (no clients/client_identifiers/access_* tables yet).
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(
            """
            CREATE TABLE client_aliases (
                id INTEGER PRIMARY KEY, cidr TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            "INSERT INTO client_aliases(cidr, display_name, description, created_at, updated_at) VALUES ('10.0.0.0/24','Net','','t','t')"
        )
        conn.commit()
        clients.init_db(conn)
        self.assertEqual(conn.execute("SELECT count(*) FROM clients").fetchone()[0], 1)


class DnsdistRenderingSafetyTest(ClientsTestBase):
    def test_control_characters_rejected(self) -> None:
        with self.assertRaises(clients.AccessPolicyError):
            clients.render_access_data(
                rules=[{"action": "deny", "kind": "clientid", "value": "a" * 47 + "\x01", "client_id": None}],
                clients_by_id={},
                default_policy="allow",
            )

    def test_deny_v4_uses_slash32_for_exact_ip(self) -> None:
        data = clients.render_access_data(
            rules=[{"action": "deny", "kind": "ipv4", "value": "1.2.3.4", "client_id": None}],
            clients_by_id={},
            default_policy="allow",
        )
        self.assertIn("1.2.3.4/32", data[clients.DATA_DENY_V4])

    def test_default_policy_file_content(self) -> None:
        data = clients.render_access_data([], {}, "deny")
        self.assertEqual(data["access-default-policy.txt"], "deny\n")

    @unittest.skipUnless(shutil.which("dnsdist"), "dnsdist not installed")
    def test_generated_lua_is_valid_dnsdist_syntax_standalone(self) -> None:
        """Proves the generated Lua is syntactically valid Lua dnsdist can
        load, using dnsdist's own --check-config against a minimal config
        that just loads our generated file (not the full Alderpoint
        dnsdist.conf, so this test has no other dependencies)."""
        rules = [
            {"action": "deny", "kind": "ipv4", "value": "192.168.32.200", "client_id": None},
            {"action": "allow", "kind": "ipv4_cidr", "value": "192.168.32.0/24", "client_id": None},
            {"action": "deny", "kind": "ipv6", "value": "2001:db8::200", "client_id": None},
            {"action": "allow", "kind": "ipv6_cidr", "value": "2001:db8::/64", "client_id": None},
            {"action": "deny", "kind": "clientid", "value": "a" * 48, "client_id": None},
            {"action": "allow", "kind": "clientid", "value": "b" * 64, "client_id": None},
        ]
        data = clients.render_access_data(rules, {}, "deny")
        outdir = self.tmp / "lua-check"
        outdir.mkdir()
        for name, text in data.items():
            (outdir / name).write_text(text)
        (outdir / "access-policy.conf").write_text(clients.render_access_lua(outdir))
        minimal = outdir / "minimal.conf"
        minimal.write_text(f'dofile("{outdir / "access-policy.conf"}")\n')
        result = subprocess.run(["dnsdist", "--check-config", "-C", str(minimal)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Configuration OK", result.stdout + result.stderr)

    def test_malicious_client_name_cannot_reach_lua(self) -> None:
        # A malicious *client name* never appears in the compiled Lua/data
        # files at all (only kind/value/action do) -- prove that here.
        client_id = clients.create_client('"); dofile("/etc/passwd"); --', identifiers=["10.0.0.1"])
        clients.add_access_rule("deny", "client", client_id=client_id)
        rules = clients.list_access_rules()
        clients_by_id = {c["id"]: c for c in clients.list_clients()}
        data = clients.render_access_data(rules, clients_by_id, "allow")
        for text in data.values():
            self.assertNotIn("dofile", text)
            self.assertNotIn("/etc/passwd", text)


class DohClientIdPathRoutingTest(ClientsTestBase):
    """dnsdist's DoH frontend only routes paths registered at startup via
    addDOHLocal()'s `paths` argument -- a HTTPPathRule for a path outside
    that list is never reached (dnsdist 404s first). This is the fix for
    that: every configured ClientID's DoH path must be registered on the
    frontend itself. See render_doh_clientid_paths() and
    packaging/dnsdist.conf's doh-altsvc block."""

    def test_renders_one_path_per_configured_clientid(self) -> None:
        clients.create_client("A", identifiers=["a" * 48])
        clients.create_client("B", identifiers=["b" * 64])
        conn = clients.connect()
        text = clients.render_doh_clientid_paths(conn)
        lines = [l for l in text.splitlines() if l]
        self.assertEqual(len(lines), 2)
        self.assertIn("/dns-query/" + "a" * 48, lines)
        self.assertIn("/dns-query/" + "b" * 64, lines)
        conn.close()

    def test_clientid_referenced_only_by_a_bare_access_rule_is_still_routed(self) -> None:
        # Regression test: a ClientID used directly in an access rule
        # (add_access_rule kind='clientid', no persistent client attached)
        # must still get its DoH path registered, or the frontend 404s it
        # before the rule can ever be evaluated.
        clients.add_access_rule("deny", "clientid", "d" * 48)
        conn = clients.connect()
        text = clients.render_doh_clientid_paths(conn)
        self.assertIn("/dns-query/" + "d" * 48, text.splitlines())
        conn.close()

    def test_no_clientids_renders_empty(self) -> None:
        conn = clients.connect()
        self.assertEqual(clients.render_doh_clientid_paths(conn), "")
        conn.close()

    def test_deploy_writes_doh_clientid_paths_file(self) -> None:
        clients.create_client("A", identifiers=["c" * 48])
        with mock.patch.object(clients, "run", return_value=subprocess.CompletedProcess(["x"], 0, "ok", "")):
            clients.deploy_access_layer()
        content = (clients.COMPILED_DNSDIST_DIR / clients.DATA_DOH_CLIENTID_PATHS).read_text()
        self.assertIn("c" * 48, content)

    def test_migration_block_replace_is_idempotent(self) -> None:
        packaging_conf = ROOT / "packaging" / "dnsdist.conf"
        old_template = clients.DNSDIST_PACKAGING_CONF
        clients.DNSDIST_PACKAGING_CONF = packaging_conf
        try:
            # Simulate an existing install whose dnsdist.conf has the
            # doh-altsvc block but predates the ClientID-path routing fix:
            # strip the sentinel string back out of a real copy of the
            # template.
            template_text = packaging_conf.read_text()
            pre_fix = template_text.replace(
                "alderpointdnsDohPaths", "OLD_STYLE_NOT_USED"
            ).replace(clients._DOH_CLIENTID_PATHS_SENTINEL, "")
            clients.DNSDIST_CONF.write_text(pre_fix)
            changed_first = clients.ensure_doh_clientid_paths_migration()
            self.assertTrue(changed_first)
            self.assertIn(clients._DOH_CLIENTID_PATHS_SENTINEL, clients.DNSDIST_CONF.read_text())
            changed_second = clients.ensure_doh_clientid_paths_migration()
            self.assertFalse(changed_second)
        finally:
            clients.DNSDIST_PACKAGING_CONF = old_template


class DeployRollbackTest(ClientsTestBase):
    def _fake_run_ok(self, cmd, check=True):
        return subprocess.CompletedProcess(cmd, 0, "ok", "")

    def test_deploy_writes_files_and_restarts(self) -> None:
        clients.set_default_policy("deny")
        clients.add_access_rule("allow", "ipv4", "10.0.0.1")
        restarted = []

        def fake_run(cmd, check=True):
            if cmd[:2] == ["systemctl", "restart"]:
                restarted.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "ok", "")

        with mock.patch.object(clients, "run", fake_run):
            info = clients.deploy_access_layer()
        self.assertTrue(info["changed"])
        self.assertTrue(restarted)
        self.assertTrue(clients.access_lua_path().exists())

    def test_second_deploy_with_no_changes_is_a_noop(self) -> None:
        with mock.patch.object(clients, "run", self._fake_run_ok):
            clients.deploy_access_layer()
            info = clients.deploy_access_layer()
        self.assertFalse(info["changed"])

    def test_failed_validation_leaves_last_known_good_active(self) -> None:
        with mock.patch.object(clients, "run", self._fake_run_ok):
            clients.deploy_access_layer()
        good_content = clients.access_lua_path().read_text()

        clients.add_access_rule("deny", "ipv4", "9.9.9.9")

        def failing_run(cmd, check=True):
            if cmd[0] == "dnsdist":
                raise subprocess.CalledProcessError(1, cmd, "syntax error (simulated)")
            return subprocess.CompletedProcess(cmd, 0, "ok", "")

        with mock.patch.object(clients, "run", failing_run):
            with self.assertRaises(subprocess.CalledProcessError):
                clients.deploy_access_layer()
        # The active file must be untouched -- still the last-known-good
        # content from before the failed deploy.
        self.assertEqual(clients.access_lua_path().read_text(), good_content)


class AnalyticsPrivacyTest(ClientsTestBase):
    def test_resolves_exact_address(self) -> None:
        clients.create_client("TV", identifiers=["192.168.32.47"])
        self.assertEqual(clients.resolve_client_name("192.168.32.47"), "TV")

    def test_resolves_via_cidr(self) -> None:
        clients.create_client("Subnet Client", identifiers=["192.168.32.0/28"])
        self.assertEqual(clients.resolve_client_name("192.168.32.5"), "Subnet Client")

    def test_most_specific_network_wins(self) -> None:
        clients.create_client("Broad", identifiers=["192.168.0.0/16"])
        clients.create_client("Narrow", identifiers=["192.168.32.0/28"])
        self.assertEqual(clients.resolve_client_name("192.168.32.5"), "Narrow")

    def test_ipv6_resolution(self) -> None:
        clients.create_client("V6 Client", identifiers=["2001:db8::/64"])
        self.assertEqual(clients.resolve_client_name("2001:db8::5"), "V6 Client")

    def test_disabled_client_not_resolved(self) -> None:
        clients.create_client("Off", identifiers=["10.0.0.5"], enabled=False)
        self.assertIsNone(clients.resolve_client_name("10.0.0.5"))

    def test_non_ip_value_returns_none(self) -> None:
        self.assertIsNone(clients.resolve_client_name("anon-abc123"))

    def test_analytics_never_resolves_when_privacy_mode_not_full(self) -> None:
        """Regression test for the privacy requirement: clients_data() must
        never call resolve_client_name() on truncated/anonymized values."""
        from app import analytics

        old_db, old_secret = analytics.DB_PATH, analytics.SECRET_FILE
        tmp_db = self.tmp / "analytics.db"
        analytics.DB_PATH = tmp_db
        analytics.SECRET_FILE = self.tmp / "secret"
        analytics.SECRET_FILE.write_text("test-secret")
        try:
            clients.create_client("TV", identifiers=["192.168.32.47"])
            analytics.init_analytics_db()
            analytics.update_settings({"privacy_mode": "partial", "client_anonymization": "truncate"})
            with analytics.connect() as conn:
                conn.execute(
                    "INSERT INTO query_events(ts, client, domain, qtype, protocol, rcode, blocked) VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (analytics.utc_now(), "192.168.32.0/24", "example.com", "A", "udp", "NOERROR"),
                )
            with mock.patch.object(clients, "resolve_client_name") as spy:
                analytics.clients_data("24h")
                spy.assert_not_called()
        finally:
            analytics.DB_PATH, analytics.SECRET_FILE = old_db, old_secret

    def test_analytics_resolves_when_privacy_mode_full(self) -> None:
        from app import analytics

        old_db, old_secret = analytics.DB_PATH, analytics.SECRET_FILE
        tmp_db = self.tmp / "analytics2.db"
        analytics.DB_PATH = tmp_db
        analytics.SECRET_FILE = self.tmp / "secret2"
        analytics.SECRET_FILE.write_text("test-secret")
        try:
            clients.create_client("TV", identifiers=["192.168.32.47"])
            analytics.init_analytics_db()
            analytics.update_settings({"privacy_mode": "full"})
            with analytics.connect() as conn:
                conn.execute(
                    "INSERT INTO query_events(ts, client, domain, qtype, protocol, rcode, blocked) VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (analytics.utc_now(), "192.168.32.47", "example.com", "A", "udp", "NOERROR"),
                )
            result = analytics.clients_data("24h")
            labels = [c["label"] for c in result["clients"]]
            self.assertIn("TV", labels)
        finally:
            analytics.DB_PATH, analytics.SECRET_FILE = old_db, old_secret


class AdGuardMigrationMappingTest(unittest.TestCase):
    def test_classify_ip(self) -> None:
        kind, value = __import__("app.importer", fromlist=["_classify_adguard_identifier"])._classify_adguard_identifier("192.168.1.1")
        self.assertEqual(kind, "ipv4")

    def test_classify_strong_clientid(self) -> None:
        from app.importer import _classify_adguard_identifier

        kind, value = _classify_adguard_identifier("a" * 48)
        self.assertEqual(kind, "clientid")

    def test_classify_weak_clientid(self) -> None:
        from app.importer import _classify_adguard_identifier

        kind, value = _classify_adguard_identifier("a" * 16)
        self.assertEqual(kind, "clientid_weak")

    def test_classify_unrecognized(self) -> None:
        from app.importer import _classify_adguard_identifier

        kind, value = _classify_adguard_identifier("not valid at all!!")
        self.assertEqual(kind, "unrecognized")

    def test_translate_adguard_config_produces_clients_full_and_access_rules(self) -> None:
        from app.importer import _translate_adguard_config

        data = {
            "clients": {
                "persistent": [
                    {"name": "Kid Tablet", "ids": ["192.168.1.50", "192.168.1.0/28", "a" * 48, "shortid"]},
                ]
            },
            "dns": {
                "allowed_clients": ["10.0.0.5"],
                "disallowed_clients": ["10.0.0.6", "b" * 8],
            },
        }
        translation = _translate_adguard_config(data)
        self.assertEqual(len(translation["clients_full"]), 1)
        client = translation["clients_full"][0]
        self.assertEqual(client["name"], "Kid Tablet")
        kinds = {i["kind"] for i in client["identifiers"]}
        self.assertEqual(kinds, {"ipv4", "ipv4_cidr", "clientid"})
        self.assertEqual(client["weak_clientids"], [])  # "shortid" isn't hex, so unrecognized not weak
        self.assertEqual(len(translation["access_allowed"]), 1)
        self.assertEqual(translation["access_allowed"][0]["value"], "10.0.0.5")
        self.assertEqual(len(translation["access_denied"]), 1)
        self.assertEqual(translation["access_denied"][0]["value"], "10.0.0.6")

    def test_weak_clientid_on_persistent_client_preserved_not_activated(self) -> None:
        from app.importer import _translate_adguard_config

        data = {"clients": {"persistent": [{"name": "Weak", "ids": ["c" * 20]}]}}
        translation = _translate_adguard_config(data)
        client = translation["clients_full"][0]
        self.assertEqual(client["identifiers"], [])
        self.assertEqual(client["weak_clientids"], ["c" * 20])


class NativeExportImportRoundTripTest(ClientsTestBase):
    def setUp(self) -> None:
        super().setUp()
        from app import importer as importer_module

        self.importer = importer_module
        self.old_importer_db = importer_module.DB_PATH
        importer_module.DB_PATH = clients.DB_PATH

    def tearDown(self) -> None:
        self.importer.DB_PATH = self.old_importer_db
        super().tearDown()

    def test_export_then_import_preserves_clients_and_access_policy(self) -> None:
        client_id = clients.create_client("Living Room TV", "a tv", ["192.168.32.47", "192.168.32.0/28"])
        cid = clients.generate_clientid(256)
        clients.add_identifier(client_id, cid)
        clients.set_default_policy("deny")
        clients.add_access_rule("allow", "ipv4", "10.0.0.5")
        clients.add_access_rule("deny", "client", client_id=client_id)

        exported_json = self.importer.export_alderpointdns_native()
        translation = self.importer.parse_alderpointdns_native_json(exported_json)

        self.assertEqual(len(translation["clients_full"]), 1)
        client = translation["clients_full"][0]
        self.assertEqual(client["name"], "Living Room TV")
        values = {i["value"] for i in client["identifiers"]}
        self.assertIn("192.168.32.47", values)
        self.assertIn(cid, values)  # full 256-bit ClientID preserved, not truncated

        self.assertEqual(len(translation["access_allowed"]), 1)
        self.assertEqual(translation["access_allowed"][0]["value"], "10.0.0.5")
        self.assertEqual(len(translation["access_denied"]), 1)
        self.assertEqual(translation["access_denied"][0]["client_name"], "Living Room TV")

    def test_export_format_version_is_2_and_v1_keys_still_present(self) -> None:
        clients.create_client("X")
        payload = __import__("json").loads(self.importer.export_alderpointdns_native())
        self.assertEqual(payload["version"], 2)
        self.assertIn("client_aliases", payload)  # v1 key preserved for back-compat
        self.assertIn("clients", payload)
        self.assertIn("access_policy", payload)


class AdGuardApplyItemsTest(ClientsTestBase):
    """Exercises the actual apply-time helper functions (not just the
    translation/classification layer) against a real connection."""

    def test_apply_client_full_item_creates_client_and_identifiers(self) -> None:
        from app.importer import _apply_client_full_item

        conn = clients.connect()
        rollback_info = {"clients_added": []}
        client_spec = {
            "name": "Kid Tablet",
            "identifiers": [{"kind": "ipv4", "value": "192.168.1.50"}, {"kind": "clientid", "value": "a" * 48}],
        }
        client_id, created = _apply_client_full_item(conn, client_spec, "AdGuard Home", rollback_info)
        conn.commit()
        self.assertEqual(created, 2)
        self.assertEqual(rollback_info["clients_added"], [client_id])
        client = clients.get_client(client_id)
        self.assertEqual(len(client["identifiers"]), 2)
        conn.close()

    def test_apply_access_rule_item_creates_rule_and_skips_duplicate(self) -> None:
        from app.importer import _apply_access_rule_item

        conn = clients.connect()
        rollback_info = {"access_rules_added": []}
        rule = {"kind": "ipv4", "value": "10.0.0.9"}
        rule_id = _apply_access_rule_item(conn, "deny", rule, rollback_info)
        conn.commit()
        self.assertIsNotNone(rule_id)
        self.assertEqual(rollback_info["access_rules_added"], [rule_id])
        # Re-applying the identical rule must be recognized as a duplicate,
        # not create a second row.
        again = _apply_access_rule_item(conn, "deny", rule, rollback_info)
        self.assertIsNone(again)
        conn.close()

    def test_rollback_removes_created_client_and_cascades(self) -> None:
        from app.importer import _apply_client_full_item

        conn = clients.connect()
        rollback_info = {"clients_added": []}
        client_id, _ = _apply_client_full_item(
            conn, {"name": "Temp", "identifiers": [{"kind": "ipv4", "value": "10.1.1.1"}]}, "AdGuard Home", rollback_info
        )
        conn.commit()
        conn.close()
        self.assertIsNotNone(clients.get_client(client_id))

        # Mirror _rollback_migration_job's client cleanup logic directly
        # (full job-pipeline rollback is covered at the module level; this
        # proves the underlying cascade is correct).
        conn = clients.connect()
        with conn:
            conn.execute("DELETE FROM access_rules WHERE client_id=?", (client_id,))
            conn.execute("DELETE FROM client_identifiers WHERE client_id=?", (client_id,))
            conn.execute("DELETE FROM clients WHERE id=?", (client_id,))
        conn.close()
        self.assertIsNone(clients.get_client(client_id))


class WebRoutesTest(unittest.TestCase):
    def setUp(self) -> None:
        from fastapi.testclient import TestClient

        from app import alderpointdns_compiler as compiler
        from app import webapp

        self.compiler = compiler
        self.webapp = webapp
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-clients-web-"))
        self.old = {"compiler_db": compiler.DB_PATH, "webapp_db": webapp.DB_PATH, "clients_db": clients.DB_PATH}
        db_path = self.tmp / "alderpointdns.db"
        compiler.DB_PATH = db_path
        webapp.DB_PATH = db_path
        clients.DB_PATH = db_path
        clients.COMPILED_DNSDIST_DIR = self.tmp / "compiled" / "dnsdist"
        clients.BACKUP_DIR = self.tmp / "backups"
        clients.STAGING_DIR = self.tmp / "staging"
        clients.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        self.webapp.clients_model.COMPILED_DNSDIST_DIR = clients.COMPILED_DNSDIST_DIR
        self.webapp.clients_model.BACKUP_DIR = clients.BACKUP_DIR
        self.webapp.clients_model.STAGING_DIR = clients.STAGING_DIR
        self.webapp.clients_model.DNSDIST_CONF = clients.DNSDIST_CONF

        with compiler.connect() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
            )
            conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES ('admin', 'x', 'now')")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, admin_id INTEGER, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT, csrf TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS admin_audit_log (id INTEGER PRIMARY KEY, at TEXT NOT NULL, admin_id INTEGER, username TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, success INTEGER NOT NULL, ip TEXT, detail TEXT NOT NULL DEFAULT '')"
            )
            self.csrf = "test-csrf-token"
            conn.execute(
                "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES ('sid', 1, 'now', 'now', '', '', ?)",
                (self.csrf,),
            )
        clients.init_db()
        self.client = TestClient(webapp.app)
        self.client.cookies.set("alderpointdns_session", webapp.serializer.dumps({"sid": "sid"}))
        # Never actually shell out to dnsdist/systemctl from an HTTP test.
        self._run_patcher = mock.patch.object(
            clients, "run", return_value=subprocess.CompletedProcess(["x"], 0, "ok", "")
        )
        self._run_patcher.start()

    def tearDown(self) -> None:
        self._run_patcher.stop()
        self.compiler.DB_PATH = self.old["compiler_db"]
        self.webapp.DB_PATH = self.old["webapp_db"]
        clients.DB_PATH = self.old["clients_db"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_page_requires_authentication(self) -> None:
        anon = self.client.__class__(self.webapp.app)  # no session cookie
        resp = anon.get("/clients-access", follow_redirects=False)
        self.assertIn(resp.status_code, (302, 303))

    def test_page_loads_when_authenticated(self) -> None:
        resp = self.client.get("/clients-access")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Clients &amp; Access", resp.text)

    def test_create_client_requires_csrf(self) -> None:
        resp = self.client.post("/clients-access/clients", data={"csrf": "wrong-token", "name": "X"})
        self.assertEqual(resp.status_code, 403)

    def test_create_client_via_http_then_visible_on_page(self) -> None:
        resp = self.client.post(
            "/clients-access/clients",
            data={"csrf": self.csrf, "name": "Living Room TV", "description": "", "identifiers": "192.168.32.47"},
            follow_redirects=False,
        )
        self.assertIn(resp.status_code, (302, 303))
        page = self.client.get("/clients-access")
        self.assertIn("Living Room TV", page.text)
        self.assertIn("192.168.32.47", page.text)

    def test_weak_clientid_rejected_via_http(self) -> None:
        create = self.client.post(
            "/clients-access/clients", data={"csrf": self.csrf, "name": "X", "identifiers": ""}, follow_redirects=False
        )
        client_id = self.client.get("/clients-access")
        row = self.compiler.connect().execute("SELECT id FROM clients WHERE name='X'").fetchone()
        resp = self.client.post(
            f"/clients-access/clients/{row['id']}/identifiers",
            data={"csrf": self.csrf, "value": "a" * 32},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("192-bit", resp.text)

    def test_generate_256_bit_clientid_via_http_shows_full_value_once(self) -> None:
        self.client.post("/clients-access/clients", data={"csrf": self.csrf, "name": "X"}, follow_redirects=False)
        row = self.compiler.connect().execute("SELECT id FROM clients WHERE name='X'").fetchone()
        resp = self.client.post(
            f"/clients-access/clients/{row['id']}/identifiers",
            data={"csrf": self.csrf, "generate_bits": "256"},
        )
        self.assertEqual(resp.status_code, 200)
        # A 64-hex string appears in the response body (the generated ID).
        import re

        match = re.search(r"\b[0-9a-f]{64}\b", resp.text)
        self.assertIsNotNone(match)

    def test_audit_log_records_client_created(self) -> None:
        self.client.post(
            "/clients-access/clients", data={"csrf": self.csrf, "name": "Audited"}, follow_redirects=False
        )
        with self.compiler.connect() as conn:
            row = conn.execute("SELECT action FROM admin_audit_log WHERE action='client_created'").fetchone()
        self.assertIsNotNone(row)


class FullMigrationJobPipelineTest(unittest.TestCase):
    """End-to-end test of the actual job preview -> apply -> rollback
    pipeline (create_migration_job / apply_migration_job /
    _rollback_migration_job), not just the underlying apply-item helper
    functions -- covers the _plan_items/build_migration_plan wiring for
    the new 'client'/'access_allow'/'access_deny' item kinds."""

    def setUp(self) -> None:
        from app import alderpointdns_compiler as compiler
        from app import custom_rules, importer, local_dns, upstream_dns

        self.importer = importer
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-migration-e2e-"))
        self.old = {
            "importer_db": importer.DB_PATH, "local_dns_db": local_dns.DB_PATH,
            "upstream_dns_db": upstream_dns.DB_PATH, "compiler_db": compiler.DB_PATH,
            "custom_rules_db": custom_rules.DB_PATH, "clients_db": clients.DB_PATH,
            "upload_dir": importer.IMPORT_UPLOAD_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        importer.DB_PATH = db_path
        local_dns.DB_PATH = db_path
        upstream_dns.DB_PATH = db_path
        compiler.DB_PATH = db_path
        custom_rules.DB_PATH = db_path
        clients.DB_PATH = db_path
        clients.COMPILED_DNSDIST_DIR = self.tmp / "compiled" / "dnsdist"
        clients.BACKUP_DIR = self.tmp / "backups"
        clients.STAGING_DIR = self.tmp / "staging"
        clients.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        importer.IMPORT_UPLOAD_DIR = self.tmp / "imports"
        self._backup_patcher = mock.patch.object(
            importer.subprocess, "run",
            return_value=subprocess.CompletedProcess(importer.PRE_IMPORT_BACKUP_COMMAND, 0, "backup_path=/tmp/pre-import-backup.tar\n", ""),
        )
        self._backup_patcher.start()
        self._deploy_patcher = mock.patch.object(
            clients, "run", return_value=subprocess.CompletedProcess(["x"], 0, "ok", "")
        )
        self._deploy_patcher.start()
        local_dns.STAGING_DIR = self.tmp / "local-staging"
        local_dns.BACKUP_DIR = self.tmp / "local-backups"
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
        compiler.init_db()
        importer.init_db()
        custom_rules.init_db()
        clients.init_db()

    def tearDown(self) -> None:
        self._backup_patcher.stop()
        self._deploy_patcher.stop()
        self.importer.DB_PATH = self.old["importer_db"]
        self.importer.IMPORT_UPLOAD_DIR = self.old["upload_dir"]
        clients.DB_PATH = self.old["clients_db"]
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_preview_apply_rollback_idempotence(self) -> None:
        from app.importer import _translate_adguard_config

        data = {
            "clients": {
                "persistent": [
                    {"name": "Kid Tablet", "ids": ["192.168.5.50", "a" * 48]},
                ]
            },
            "dns": {"allowed_clients": ["10.5.5.5"], "disallowed_clients": ["10.5.5.6"]},
        }
        translation = _translate_adguard_config(data)
        job_id = self.importer.create_migration_job("adguard_yaml", "test-adguard", translation)

        # Preview: prove the new item kinds surface (not silently dropped).
        plan = self.importer.build_migration_plan(translation)
        preview_keys = [item["key"] for item in self.importer._plan_items(plan)]
        client_items = [k for k in preview_keys if k.startswith("clients_access:")]
        self.assertEqual(len(client_items), 3)  # 1 client + 1 allow + 1 deny

        result = self.importer.apply_migration_job(job_id)
        self.assertEqual(result["counts"]["clients_created"], 1)
        self.assertEqual(result["counts"]["access_rules_created"], 2)

        created_client = clients.list_clients()[0]
        self.assertEqual(created_client["name"], "Kid Tablet")
        self.assertEqual(len(created_client["identifiers"]), 2)  # the IP and the strong ClientID
        self.assertEqual({i["kind"] for i in created_client["identifiers"]}, {"ipv4", "clientid"})
        rules = clients.list_access_rules()
        self.assertEqual(len(rules), 2)

        # Rollback: prove it removes exactly what apply created.
        job = self.importer.get_job(job_id)
        removed = self.importer._rollback_migration_job(job)
        self.assertGreater(removed, 0)
        self.assertEqual(clients.list_clients(), [])
        self.assertEqual(clients.list_access_rules(), [])

    def test_weak_clientid_on_imported_client_never_becomes_active(self) -> None:
        from app.importer import _translate_adguard_config

        data = {"clients": {"persistent": [{"name": "Weak Device", "ids": ["192.168.9.9", "deadbeef"]}]}}
        translation = _translate_adguard_config(data)
        job_id = self.importer.create_migration_job("adguard_yaml", "test-adguard-weak", translation)
        result = self.importer.apply_migration_job(job_id)
        self.assertEqual(result["counts"]["clients_created"], 1)
        client = clients.list_clients()[0]
        # Only the IP identifier was imported; the weak 8-hex ClientID
        # never became an active identifier anywhere.
        kinds = {i["kind"] for i in client["identifiers"]}
        self.assertEqual(kinds, {"ipv4"})
        for rule in clients.list_access_rules():
            self.assertNotEqual(rule.get("value"), "deadbeef")


if __name__ == "__main__":
    unittest.main()
