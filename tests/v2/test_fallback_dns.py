import pytest

from app.v2.fallback_dns import FallbackDecision, PrimaryHealth, evaluate_fallback


class TestStrategyNone:
    def test_never_falls_back(self):
        health = PrimaryHealth(consecutive_failures=99)
        decision = evaluate_fallback("none", health, "dot", "plain")
        assert decision.use_fallback is False


class TestOnFailure:
    def test_healthy_primary_does_not_fall_back(self):
        health = PrimaryHealth(consecutive_failures=0)
        decision = evaluate_fallback("on_failure", health, "plain", "plain")
        assert decision.use_fallback is False

    def test_below_threshold_does_not_fall_back(self):
        health = PrimaryHealth(consecutive_failures=2, failure_threshold=3)
        decision = evaluate_fallback("on_failure", health, "plain", "plain")
        assert decision.use_fallback is False

    def test_at_threshold_falls_back(self):
        health = PrimaryHealth(consecutive_failures=3, failure_threshold=3)
        decision = evaluate_fallback("on_failure", health, "plain", "plain")
        assert decision.use_fallback is True


class TestPrivacyDowngradeGuard:
    def test_encrypted_to_plaintext_refused_by_default(self):
        health = PrimaryHealth(consecutive_failures=5)
        decision = evaluate_fallback("on_failure", health, "dot", "plain")
        assert decision.use_fallback is False
        assert "privacy" in decision.reason.lower() or "downgrade" in decision.reason.lower()

    def test_encrypted_to_plaintext_allowed_with_explicit_flag(self):
        health = PrimaryHealth(consecutive_failures=5)
        decision = evaluate_fallback("on_failure", health, "dot", "plain", allow_privacy_downgrade=True)
        assert decision.use_fallback is True

    def test_encrypted_to_encrypted_never_needs_the_flag(self):
        health = PrimaryHealth(consecutive_failures=5)
        decision = evaluate_fallback("on_failure", health, "dot", "doh")
        assert decision.use_fallback is True

    def test_plaintext_to_plaintext_never_needs_the_flag(self):
        health = PrimaryHealth(consecutive_failures=5)
        decision = evaluate_fallback("on_failure", health, "plain", "plain")
        assert decision.use_fallback is True

    def test_no_fallback_transport_configured_no_downgrade_check_needed(self):
        health = PrimaryHealth(consecutive_failures=5)
        decision = evaluate_fallback("on_failure", health, "dot", None)
        assert decision.use_fallback is True


class TestAlwaysParallel:
    def test_always_eligible_regardless_of_health(self):
        health = PrimaryHealth(consecutive_failures=0)
        decision = evaluate_fallback("always_parallel", health, "plain", "plain")
        assert decision.use_fallback is True

    def test_always_parallel_still_respects_privacy_guard(self):
        health = PrimaryHealth(consecutive_failures=0)
        decision = evaluate_fallback("always_parallel", health, "doh", "plain")
        assert decision.use_fallback is False
