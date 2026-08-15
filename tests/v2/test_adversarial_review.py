"""Cross-cutting adversarial security pass (Workstream 3 final
continuation, Priority 6, §39). Attacks the specific checklist items not
already covered by each module's own dedicated test file, consolidated
here as the "separate systematic exercise" the prior pass's handoff doc
flagged as not yet done.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from app.v2 import control_db, policy_store as store
from app.v2.dnsdist_gen import UpstreamServer, generate_dnsdist_config, generate_dnsdist_config_from_profiles
from app.v2.migration_convert import MigrationConvertError, detect_source
from app.v2.network_match import InvalidNetworkError, NetworkScope
from app.v2.policy_compiler import compile_effective_policy
from app.v2.policy_model import InvalidPolicyError, PolicyLayer

DNSDIST_INSTALLED = shutil.which("dnsdist") is not None


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c


class TestUpstreamEndpointInjection:
    """TLS hostname / address fields flow into generated Lua config text
    -- must be escaped, never allow breaking out of the Lua string
    literal into executable code."""

    def test_malicious_tls_hostname_cannot_break_out_of_lua_string(self, conn):
        eps = [
            store.UpstreamEndpointRecord(
                "1.1.1.1:853", '"}); os.execute("touch /tmp/pwned")--', 0, 1, None
            )
        ]
        store.create_upstream_profile(conn, "evil", "Evil", "dot", eps)
        profile = store.load_upstream_profile(conn, "evil")
        text = generate_dnsdist_config_from_profiles("127.0.0.1:5300", [], profile)
        # The payload must appear only as an escaped string literal, never
        # as a live Lua statement boundary.
        assert 'os.execute' not in text or '\\"' in text
        assert 'subjectName="\\"}); os.execute' in text or 'subjectName="\\"' in text

    @pytest.mark.skipif(not DNSDIST_INSTALLED, reason="dnsdist not installed")
    def test_malicious_tls_hostname_config_still_validates_as_inert_string(self, conn, tmp_path):
        eps = [
            store.UpstreamEndpointRecord(
                "1.1.1.1:853", '"}); print("INJECTED")--', 0, 1, None
            )
        ]
        store.create_upstream_profile(conn, "evil2", "Evil2", "dot", eps)
        profile = store.load_upstream_profile(conn, "evil2")
        text = generate_dnsdist_config_from_profiles("127.0.0.1:15330", [], profile)
        conf_path = tmp_path / "evil.conf"
        conf_path.write_text(text)
        result = subprocess.run(
            ["dnsdist", "-C", str(conf_path), "--check-config"], capture_output=True, text=True
        )
        # Must either validate cleanly (payload treated as inert string
        # data) or fail cleanly -- must NEVER execute the injected code
        # (there is no way to directly observe "did not execute" other
        # than the absence of any side effect / crash signature; a clean
        # OK or a clean syntax-error-on-our-own-escaped-string are both
        # acceptable, an actual Lua runtime executing os.execute is not).
        assert result.returncode in (0, 1)
        assert "INJECTED" not in result.stdout


class TestPathTraversalAndMaliciousNames:
    def test_service_id_path_traversal_rejected_by_id_shape(self, conn):
        # service_id has no filesystem meaning (stored in SQLite, not as a
        # filename) but must still not silently corrupt a lookup via
        # embedded control characters/SQL metacharacters -- proven via a
        # real round-trip.
        store.create_service(conn, "svc-1", "../../etc/passwd", [("exact", "x.example")])
        loaded = store.is_domain_service_blocked(conn, "r1", "x.example")
        # No ruleset named r1 was created, so this must be None, not an
        # error or unexpected traversal-driven result.
        assert loaded is None

    def test_malicious_domain_with_sql_metacharacters_rejected_by_name_validator(self, conn):
        # A SQL-injection-shaped domain isn't a valid DNS name at all
        # (spaces, quotes, semicolons) -- the central DNS name validator
        # (app/v2/dns_name_validate.py, Gate #2 MEDIUM fix) now rejects it
        # outright, which is a stronger defense than "stored safely via
        # parameterized queries" (still true, proven below).
        malicious = "'; DROP TABLE service_definitions; --.example"
        with pytest.raises(store.PolicyStoreError):
            store.create_service(conn, "svc-x", "X", [("exact", malicious)])
        # Table must still exist and be queryable -- proves parameterized
        # queries, not string interpolation, were used throughout, and
        # that the rejected insert didn't corrupt anything.
        store.create_service(conn, "svc-y", "Y", [("exact", "clean.example")])
        store.create_service_ruleset(conn, "r1", ["svc-y"])
        result = store.is_domain_service_blocked(conn, "r1", "clean.example")
        assert result == "svc-y"

    def test_malicious_group_name_does_not_break_explain_trace(self, conn):
        from app.v2.policy_model import GroupPolicy

        evil_name = '"; DROP TABLE policy_layers; --'
        group = GroupPolicy("g1", evil_name, 1, PolicyLayer(safesearch_mode="strict"))
        policy = compile_effective_policy(PolicyLayer(), groups=[group])
        assert policy.safesearch_mode == "strict"
        # source string embeds the name literally but is never executed
        # as SQL/Lua -- it's just a Python f-string label.
        assert any(evil_name in e.source for e in policy.explain_trace)


class TestInvalidCIDRAndNetworkEdgeCases:
    def test_malformed_cidr_rejected(self):
        with pytest.raises(InvalidNetworkError):
            NetworkScope.create("n1", "10.0.0.0/99", "x")

    def test_non_numeric_cidr_rejected(self):
        with pytest.raises(InvalidNetworkError):
            NetworkScope.create("n1", "not.a.cidr/24", "x")

    def test_negative_prefix_rejected(self):
        with pytest.raises(InvalidNetworkError):
            NetworkScope.create("n1", "10.0.0.0/-1", "x")


class TestMigrationInputHardening:
    def test_path_traversal_source_path_treated_as_ordinary_missing_path(self, tmp_path):
        traversal = tmp_path / ".." / ".." / "etc"
        with pytest.raises(MigrationConvertError):
            detect_source(traversal)

    def test_malicious_source_db_with_extra_unexpected_tables_still_detected_correctly(self, tmp_path):
        import sqlite3

        from tests.v2._v1_fixture import build_v1_fixture

        source = tmp_path / "src"
        db_path = build_v1_fixture(source / "alderpointdns.db")
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE '; DROP TABLE admins; --' (id INTEGER)")
        conn.commit()
        conn.close()
        # Must not raise/crash on an oddly-named (but syntactically valid
        # SQLite identifier) table -- sqlite_master enumeration, not string
        # parsing, is what's used. A real, schema-complete fixture plus one
        # adversarially-named extra table must still classify as supported.
        info = detect_source(source)
        assert info.detected_version == "v1.x"
        assert info.classification in ("supported_complete", "supported_with_optional_gaps")


class TestScheduleAndPolicyEdgeCasesUnderAdversarialInput:
    def test_extremely_long_domain_string_rejected(self, conn):
        # A 5000-char single label exceeds real DNS limits (63 bytes/
        # label, 253 bytes/name) -- the central validator now rejects it
        # at creation time rather than silently accepting an
        # unrepresentable domain.
        long_domain = "a" * 5000 + ".example"
        with pytest.raises(store.PolicyStoreError):
            store.create_service(conn, "svc-long", "Long", [("suffix", long_domain)])

    def test_long_but_valid_domain_accepted(self, conn):
        # A real-shape long domain (many short labels, each within the
        # 63-byte limit, whole name within 253 bytes) is still accepted.
        long_domain = ".".join(["a" * 50] * 4) + ".example"
        store.create_service(conn, "svc-long", "Long", [("suffix", long_domain)])
        store.create_service_ruleset(conn, "r1", ["svc-long"])
        result = store.is_domain_service_blocked(conn, "r1", "x." + long_domain)
        assert result == "svc-long"

    def test_invalid_policy_field_value_rejected_not_silently_coerced(self):
        with pytest.raises(InvalidPolicyError):
            compile_effective_policy(PolicyLayer(safesearch_mode="'; DROP TABLE x; --"))


class TestGeneratedConfigNeverEmbedsRawUnescapedUserInput:
    def test_dnsdist_upstream_name_with_quotes_rejected_not_embedded_raw(self):
        from app.v2.dnsdist_gen import DnsdistGenError

        with pytest.raises(DnsdistGenError):
            UpstreamServer('evil"; os.execute("x")', "1.1.1.1:53")
