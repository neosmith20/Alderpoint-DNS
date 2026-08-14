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


def _setup_parental(conn):
    store.create_service(conn, "svc-adult", "Adult Content", [("suffix", "adult.example")], category="adult")
    store.create_service_ruleset(conn, "parental-strict", ["svc-adult"])


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
        assert decision.reason == "svc-social"

    def test_unmatched_domain_allowed(self, conn):
        _setup_parental(conn)
        _setup_service_blocking(conn)
        policy = compile_effective_policy(
            PolicyLayer(
                parental_policy_id="parental-strict",
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

    def test_parental_and_service_both_configured_parental_checked_first(self, conn):
        # Configure the same domain blocked by both categories -- parental
        # must win the reason/category since it's checked first.
        store.create_service(conn, "svc-x", "X", [("exact", "shared.example")], category="adult")
        store.create_service_ruleset(conn, "parental-r", ["svc-x"])
        store.create_service(conn, "svc-y", "Y", [("exact", "shared.example")], category="service")
        store.create_service_ruleset(conn, "service-r", ["svc-y"])
        policy = compile_effective_policy(
            PolicyLayer(parental_policy_id="parental-r", service_blocking_ruleset_id="service-r")
        )
        decision = evaluate_filtering(conn, policy, "shared.example")
        assert decision.category == "parental"
        assert decision.reason == "svc-x"
