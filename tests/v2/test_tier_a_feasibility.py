#!/usr/bin/env python3
"""Tests for app/v2/tier_a_feasibility.py (Workstream 2, §26-27, §33 TIER A)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import tier_a_feasibility as ta  # noqa: E402


def _valid_record(**overrides):
    base = dict(
        qname="example.com", qtype="A", cache_profile_id="p1",
        absolute_expiration_ts=1300.0, dnssec_state=ta.DnssecState.SECURE,
        resolver_upstream_profile_id="isp", domain_routing_context_id="default",
        ecs_context=None,
    )
    base.update(overrides)
    return ta.CachedAnswerRecord(**base)


_CURRENT_CONTEXT = dict(
    current_cache_profile_id="p1", current_upstream_profile_id="isp",
    current_domain_routing_context_id="default", current_ecs_context=None,
)


class TestTtlNeverResets(unittest.TestCase):
    def test_remaining_ttl_is_expiration_minus_now_not_original_ttl(self):
        # Entry originally cached with 300s TTL at ts=1000 (expiration=1300).
        record = _valid_record(absolute_expiration_ts=1300.0)
        # "Reboot" happens at ts=1260 -> only 40s should remain, not 300s.
        decision = ta.evaluate_restore(record, now=1260.0, **_CURRENT_CONTEXT)
        self.assertTrue(decision.allowed)
        self.assertAlmostEqual(decision.remaining_ttl_seconds, 40.0)

    def test_expired_entry_rejected(self):
        record = _valid_record(absolute_expiration_ts=1300.0)
        decision = ta.evaluate_restore(record, now=1301.0, **_CURRENT_CONTEXT)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "expired")
        self.assertIsNone(decision.remaining_ttl_seconds)

    def test_exactly_at_expiration_is_rejected_not_zero_ttl_restored(self):
        record = _valid_record(absolute_expiration_ts=1300.0)
        decision = ta.evaluate_restore(record, now=1300.0, **_CURRENT_CONTEXT)
        self.assertFalse(decision.allowed)

    def test_no_original_ttl_field_exists_on_the_record(self):
        """Structural guarantee, not just a runtime check: there is nothing
        called 'ttl' or 'original_ttl' on the record for restore logic to
        accidentally read instead of computing from absolute expiration."""
        field_names = set(ta.CachedAnswerRecord.__dataclass_fields__)
        self.assertNotIn("ttl", field_names)
        self.assertNotIn("original_ttl", field_names)


class TestDnssecValidity(unittest.TestCase):
    def test_secure_is_trustworthy(self):
        record = _valid_record(dnssec_state=ta.DnssecState.SECURE)
        decision = ta.evaluate_restore(record, now=1000.0, **_CURRENT_CONTEXT)
        self.assertTrue(decision.allowed)

    def test_insecure_is_trustworthy(self):
        record = _valid_record(dnssec_state=ta.DnssecState.INSECURE)
        decision = ta.evaluate_restore(record, now=1000.0, **_CURRENT_CONTEXT)
        self.assertTrue(decision.allowed)

    def test_bogus_is_rejected(self):
        record = _valid_record(dnssec_state=ta.DnssecState.BOGUS)
        decision = ta.evaluate_restore(record, now=1000.0, **_CURRENT_CONTEXT)
        self.assertFalse(decision.allowed)
        self.assertIn("dnssec", decision.reason)

    def test_unknown_is_rejected(self):
        """Uncertainty must fail closed — 'unknown' is not treated as
        equivalent to 'insecure'."""
        record = _valid_record(dnssec_state=ta.DnssecState.UNKNOWN)
        decision = ta.evaluate_restore(record, now=1000.0, **_CURRENT_CONTEXT)
        self.assertFalse(decision.allowed)


class TestContextMismatchRejected(unittest.TestCase):
    def test_cache_profile_mismatch_rejected(self):
        record = _valid_record(cache_profile_id="p1")
        decision = ta.evaluate_restore(
            record, now=1000.0, current_cache_profile_id="p2",
            current_upstream_profile_id="isp", current_domain_routing_context_id="default",
            current_ecs_context=None,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("profile", decision.reason)

    def test_upstream_mismatch_rejected(self):
        record = _valid_record(resolver_upstream_profile_id="isp")
        decision = ta.evaluate_restore(
            record, now=1000.0, current_cache_profile_id="p1",
            current_upstream_profile_id="isp-backup", current_domain_routing_context_id="default",
            current_ecs_context=None,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("upstream", decision.reason)

    def test_domain_routing_mismatch_rejected(self):
        record = _valid_record(domain_routing_context_id="default")
        decision = ta.evaluate_restore(
            record, now=1000.0, current_cache_profile_id="p1",
            current_upstream_profile_id="isp", current_domain_routing_context_id="split-tunnel",
            current_ecs_context=None,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("routing", decision.reason)

    def test_ecs_context_mismatch_rejected(self):
        record = _valid_record(ecs_context="1.2.3.0/24")
        decision = ta.evaluate_restore(
            record, now=1000.0, current_cache_profile_id="p1",
            current_upstream_profile_id="isp", current_domain_routing_context_id="default",
            current_ecs_context="5.6.7.0/24",
        )
        self.assertFalse(decision.allowed)
        self.assertIn("ecs", decision.reason.lower())

    def test_matching_ecs_context_allowed(self):
        record = _valid_record(ecs_context="1.2.3.0/24", absolute_expiration_ts=2000.0)
        decision = ta.evaluate_restore(
            record, now=1000.0, current_cache_profile_id="p1",
            current_upstream_profile_id="isp", current_domain_routing_context_id="default",
            current_ecs_context="1.2.3.0/24",
        )
        self.assertTrue(decision.allowed)


class TestNegativeCaching(unittest.TestCase):
    def test_negative_entry_follows_same_validity_rules(self):
        record = _valid_record(is_negative=True, absolute_expiration_ts=1300.0)
        decision = ta.evaluate_restore(record, now=1260.0, **_CURRENT_CONTEXT)
        self.assertTrue(decision.allowed)
        self.assertAlmostEqual(decision.remaining_ttl_seconds, 40.0)

    def test_expired_negative_entry_rejected(self):
        record = _valid_record(is_negative=True, absolute_expiration_ts=1300.0)
        decision = ta.evaluate_restore(record, now=2000.0, **_CURRENT_CONTEXT)
        self.assertFalse(decision.allowed)


class TestUncertainValidityFailsClosed(unittest.TestCase):
    def test_every_rejection_path_returns_no_ttl(self):
        """A rejected decision must never carry a remaining_ttl_seconds a
        careless caller could accidentally use anyway."""
        bad_records = [
            _valid_record(absolute_expiration_ts=1.0),  # expired
            _valid_record(dnssec_state=ta.DnssecState.BOGUS),
            _valid_record(cache_profile_id="different"),
        ]
        for record in bad_records:
            decision = ta.evaluate_restore(record, now=1000.0, **_CURRENT_CONTEXT)
            self.assertFalse(decision.allowed)
            self.assertIsNone(decision.remaining_ttl_seconds)


if __name__ == "__main__":
    unittest.main()
