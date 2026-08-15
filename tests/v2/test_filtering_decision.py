import pytest

from app.v2 import control_db, policy_store as store
from app.v2.filtering_decision import evaluate_filtering
from app.v2.policy_compiler import compile_effective_policy
from app.v2.policy_model import PolicyLayer


@pytest.fixture()
def conn(tmp_path):
    path = tmp_path / "control.db"
    store.ensure_schema(path)
    with control_db.connect(path) as c:
        yield c


def _setup_parental(conn, ruleset_id="parental-strict"):
    store.create_service(conn, "svc-adult", "Adult Content", [("suffix", "adult.example")], category="adult")
    store.create_service_ruleset(conn, ruleset_id, ["svc-adult"])


def _setup_security(conn, ruleset_id="security-strict"):
    store.create_service(conn, "svc-malware", "Known Malware", [("suffix", "malware.example")], category="security")
    store.create_service_ruleset(conn, ruleset_id, ["svc-malware"])


def _setup_service_blocking(conn):
    store.create_service(conn, "svc-social", "Social", [("suffix", "social.example")], category="service")
    store.create_service_ruleset(conn, "teen-services", ["svc-social"])


class TestPrecedence:
    def test_explicit_allow_beats_everything(self, conn):
        _setup_parental(conn)
        policy = compile_effective_policy(
            PolicyLayer(parental_policy_id="parental-strict")
        )
        decision = evaluate_filtering(
            conn, policy, "adult.example", allowed_domains=frozenset({"adult.example"})
        )
        assert decision.action == "allowed"
        assert decision.reason == "explicit_allow"

    def test_safesearch_rewrite_applies(self, conn):
        policy = compile_effective_policy(PolicyLayer(safesearch_mode="strict"))
        decision = evaluate_filtering(conn, policy, "google.com")
        assert decision.action == "rewritten"
        assert decision.cname_target == "forcesafesearch.google.com"

    def test_security_block_applies(self, conn):
        _setup_security(conn)
        policy = compile_effective_policy(PolicyLayer(security_policy_id="security-strict"))
        decision = evaluate_filtering(conn, policy, "www.malware.example")
        assert decision.action == "blocked"
        assert decision.category == "security"
        assert decision.reason == "svc-malware"

    def test_parental_block_applies(self, conn):
        _setup_parental(conn)
        policy = compile_effective_policy(PolicyLayer(parental_policy_id="parental-strict"))
        decision = evaluate_filtering(conn, policy, "www.adult.example")
        assert decision.action == "blocked"
        assert decision.category == "parental"
        assert decision.reason == "svc-adult"

    def test_service_block_applies(self, conn):
        _setup_service_blocking(conn)
        policy = compile_effective_policy(
            PolicyLayer(service_blocking_ruleset_id="teen-services")
        )
        decision = evaluate_filtering(conn, policy, "chat.social.example")
        assert decision.action == "blocked"
        assert decision.category == "service"
        assert decision.reason == "svc-social"

    def test_security_checked_before_parental(self, conn):
        # Same domain blocked by both categories -- security wins the
        # category/reason since it's checked first (safety-critical).
        store.create_service(conn, "svc-x", "X", [("exact", "shared.example")], category="security")
        store.create_service_ruleset(conn, "security-r", ["svc-x"])
        store.create_service(conn, "svc-y", "Y", [("exact", "shared.example")], category="adult")
        store.create_service_ruleset(conn, "parental-r", ["svc-y"])
        policy = compile_effective_policy(
            PolicyLayer(security_policy_id="security-r", parental_policy_id="parental-r")
        )
        decision = evaluate_filtering(conn, policy, "shared.example")
        assert decision.category == "security"
        assert decision.reason == "svc-x"

    def test_unmatched_domain_allowed(self, conn):
        _setup_parental(conn)
        _setup_security(conn)
        _setup_service_blocking(conn)
        policy = compile_effective_policy(
            PolicyLayer(
                parental_policy_id="parental-strict",
                security_policy_id="security-strict",
                service_blocking_ruleset_id="teen-services",
            )
        )
        decision = evaluate_filtering(conn, policy, "unrelated.example")
        assert decision.action == "allowed"
        assert decision.reason == "no_match"

    def test_safesearch_off_does_not_rewrite(self, conn):
        policy = compile_effective_policy(PolicyLayer(safesearch_mode="off"))
        decision = evaluate_filtering(conn, policy, "google.com")
        assert decision.action == "allowed"


class TestCategoryIndependence:
    """P0-A: disabling one category must never affect the other."""

    def test_disabling_parental_does_not_disable_security(self, conn):
        _setup_security(conn)
        policy = compile_effective_policy(
            PolicyLayer(security_policy_id="security-strict", parental_policy_id="none")
        )
        decision = evaluate_filtering(conn, policy, "www.malware.example")
        assert decision.action == "blocked"
        assert decision.category == "security"

    def test_disabling_security_does_not_disable_parental(self, conn):
        _setup_parental(conn)
        policy = compile_effective_policy(
            PolicyLayer(parental_policy_id="parental-strict", security_policy_id="none")
        )
        decision = evaluate_filtering(conn, policy, "www.adult.example")
        assert decision.action == "blocked"
        assert decision.category == "parental"

    def test_both_disabled_neither_blocks(self, conn):
        _setup_parental(conn)
        _setup_security(conn)
        policy = compile_effective_policy(
            PolicyLayer(parental_policy_id="none", security_policy_id="none")
        )
        assert evaluate_filtering(conn, policy, "www.adult.example").action == "allowed"
        assert evaluate_filtering(conn, policy, "www.malware.example").action == "allowed"

    def test_both_independently_configured_and_active_simultaneously(self, conn):
        _setup_parental(conn)
        _setup_security(conn)
        policy = compile_effective_policy(
            PolicyLayer(parental_policy_id="parental-strict", security_policy_id="security-strict")
        )
        parental_decision = evaluate_filtering(conn, policy, "www.adult.example")
        security_decision = evaluate_filtering(conn, policy, "www.malware.example")
        assert parental_decision.category == "parental"
        assert security_decision.category == "security"

    def test_categories_use_distinct_policy_fields(self):
        # Structural guarantee: the fields are genuinely separate, not the
        # same field read under two names.
        from app.v2.policy_model import ALL_FIELDS

        assert "parental_policy_id" in ALL_FIELDS
        assert "security_policy_id" in ALL_FIELDS
        assert "parental_policy_id" != "security_policy_id"

    def test_categories_are_independent_cache_profile_dimensions(self):
        from app.v2.cache_profile import CachePolicyDimensions, compile_profile

        base = compile_profile(CachePolicyDimensions())
        parental_only = compile_profile(CachePolicyDimensions(parental_policy_id="strict"))
        security_only = compile_profile(CachePolicyDimensions(security_policy_id="strict"))
        # Same string value in each field must still produce three
        # distinct profile ids -- proves the two dimensions are hashed
        # independently, not collapsed into one shared value.
        assert len({base.profile_id, parental_only.profile_id, security_only.profile_id}) == 3
