#!/usr/bin/env python3
"""Tests for app/v2/cache_profile.py (Workstream 2, §15-16, §33 CACHE PROFILE)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import cache_profile as cp  # noqa: E402


class TestDeterminism(unittest.TestCase):
    def test_same_dimensions_produce_same_id(self):
        d1 = cp.CachePolicyDimensions(safesearch_mode="strict")
        d2 = cp.CachePolicyDimensions(safesearch_mode="strict")
        p1 = cp.compile_profile(d1)
        p2 = cp.compile_profile(d2)
        self.assertEqual(p1.profile_id, p2.profile_id)

    def test_default_dimensions_are_deterministic_across_calls(self):
        p1 = cp.compile_profile(cp.CachePolicyDimensions())
        p2 = cp.compile_profile(cp.CachePolicyDimensions())
        self.assertEqual(p1.profile_id, p2.profile_id)

    def test_profile_id_is_a_stable_short_hex_string(self):
        p = cp.compile_profile(cp.CachePolicyDimensions())
        self.assertRegex(p.profile_id, r"^[0-9a-f]{32}$")


class TestAnswerAffectingChangesAlterProfile(unittest.TestCase):
    def _base(self):
        return cp.CachePolicyDimensions()

    def test_safesearch_change_alters_profile(self):
        base = cp.compile_profile(self._base())
        changed = cp.compile_profile(cp.CachePolicyDimensions(safesearch_mode="strict"))
        self.assertNotEqual(base.profile_id, changed.profile_id)
        self.assertFalse(cp.is_compatible(base, changed))

    def test_filtering_profile_change_alters_profile(self):
        base = cp.compile_profile(self._base())
        changed = cp.compile_profile(cp.CachePolicyDimensions(filtering_profile_id="kids-strict"))
        self.assertNotEqual(base.profile_id, changed.profile_id)

    def test_upstream_routing_change_alters_profile(self):
        base = cp.compile_profile(self._base())
        changed = cp.compile_profile(cp.CachePolicyDimensions(upstream_profile_id="isp-backup"))
        self.assertNotEqual(base.profile_id, changed.profile_id)

    def test_blocking_response_mode_change_alters_profile(self):
        base = cp.compile_profile(self._base())
        changed = cp.compile_profile(cp.CachePolicyDimensions(blocking_response_mode="null_ip"))
        self.assertNotEqual(base.profile_id, changed.profile_id)

    def test_ecs_mode_change_alters_profile(self):
        base = cp.compile_profile(self._base())
        changed = cp.compile_profile(cp.CachePolicyDimensions(ecs_mode="enabled"))
        self.assertNotEqual(base.profile_id, changed.profile_id)

    def test_domain_routing_change_alters_profile(self):
        base = cp.compile_profile(self._base())
        changed = cp.compile_profile(cp.CachePolicyDimensions(domain_routing_ruleset_id="split-tunnel-1"))
        self.assertNotEqual(base.profile_id, changed.profile_id)

    def test_every_field_independently_changes_the_id(self):
        base = cp.compile_profile(cp.CachePolicyDimensions())
        for field_name in cp.CachePolicyDimensions.__dataclass_fields__:
            kwargs = {field_name: "some-different-value-xyz"}
            variant = cp.compile_profile(cp.CachePolicyDimensions(**kwargs))
            self.assertNotEqual(
                base.profile_id, variant.profile_id,
                f"changing {field_name!r} did not alter the profile id",
            )


class TestNonAnswerAffectingMetadataDoesNotAppearInDimensions(unittest.TestCase):
    def test_dimensions_has_no_display_name_or_ui_metadata_fields(self):
        """The structural guarantee: display name / notes / timestamps are
        not fields on CachePolicyDimensions at all, so they cannot possibly
        affect the profile id — this is the actual mechanism behind "display
        name changes don't invalidate the cache", not a runtime check."""
        forbidden_field_names = {"display_name", "name", "notes", "created_at", "updated_at", "description"}
        actual_fields = set(cp.CachePolicyDimensions.__dataclass_fields__)
        self.assertEqual(actual_fields & forbidden_field_names, set())

    def test_two_clients_with_identical_policy_get_identical_profile(self):
        """Simulates two different clients whose *display metadata* differs
        but whose answer-affecting policy is identical — they must compile
        to the same effective cache profile (cache sharing, not
        per-client caching)."""
        client_a_policy = cp.CachePolicyDimensions(safesearch_mode="strict", upstream_profile_id="isp")
        client_b_policy = cp.CachePolicyDimensions(safesearch_mode="strict", upstream_profile_id="isp")
        profile_a = cp.compile_profile(client_a_policy)
        profile_b = cp.compile_profile(client_b_policy)
        self.assertTrue(cp.is_compatible(profile_a, profile_b))


class TestCacheProfileRegistry(unittest.TestCase):
    def test_equivalent_clients_share_one_profile_object(self):
        registry = cp.CacheProfileRegistry()
        p1 = registry.get_or_compile(cp.CachePolicyDimensions(safesearch_mode="strict"))
        p2 = registry.get_or_compile(cp.CachePolicyDimensions(safesearch_mode="strict"))
        self.assertIs(p1, p2)
        self.assertEqual(registry.distinct_profile_count(), 1)

    def test_many_clients_few_distinct_policies_yields_few_profiles(self):
        registry = cp.CacheProfileRegistry()
        # 100 "clients", but only 3 distinct policy combinations.
        policies = [
            cp.CachePolicyDimensions(safesearch_mode="off"),
            cp.CachePolicyDimensions(safesearch_mode="strict"),
            cp.CachePolicyDimensions(safesearch_mode="moderate"),
        ]
        for i in range(100):
            registry.get_or_compile(policies[i % 3])
        self.assertEqual(registry.distinct_profile_count(), 3)

    def test_no_control_db_or_io_dependency(self):
        """Compiling/comparing profiles must be pure computation — no
        filesystem, network, or database access. Verified structurally: the
        module imports only stdlib (hashlib, json, dataclasses)."""
        import app.v2.cache_profile as mod
        source = Path(mod.__file__).read_text()
        for banned in ("sqlite3", "import socket", "requests", "open(", "subprocess"):
            self.assertNotIn(banned, source)


if __name__ == "__main__":
    unittest.main()
