#!/usr/bin/env python3
"""Tests for app.v2.auth_hash — Argon2id password hashing contract."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from app.v2 import auth_hash  # noqa: E402

# Use cheap params for fast tests; the real defaults are covered by the
# benchmark script (benchmarks/v2_argon2_bench.py), not by unit tests.
_FAST_HASHER = auth_hash.make_hasher(time_cost=1, memory_cost_kib=8192, parallelism=1)


class TestHashAndVerify(unittest.TestCase):
    def test_correct_password_verifies(self):
        encoded = auth_hash.hash_password("correct horse battery staple", hasher=_FAST_HASHER)
        result = auth_hash.verify_password(encoded, "correct horse battery staple", hasher=_FAST_HASHER)
        self.assertTrue(result.ok)
        self.assertIsNone(result.error)

    def test_wrong_password_fails(self):
        encoded = auth_hash.hash_password("correct horse battery staple", hasher=_FAST_HASHER)
        result = auth_hash.verify_password(encoded, "wrong password", hasher=_FAST_HASHER)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "mismatch")

    def test_hash_is_argon2id(self):
        encoded = auth_hash.hash_password("some-password", hasher=_FAST_HASHER)
        self.assertTrue(encoded.startswith("$argon2id$"))

    def test_unique_salts_for_same_password(self):
        h1 = auth_hash.hash_password("same-password", hasher=_FAST_HASHER)
        h2 = auth_hash.hash_password("same-password", hasher=_FAST_HASHER)
        self.assertNotEqual(h1, h2)  # different salts -> different encoded hash

    def test_malformed_hash_fails_safely_not_crashes(self):
        result = auth_hash.verify_password("not-a-real-hash", "anything", hasher=_FAST_HASHER)
        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)

    def test_empty_string_hash_fails_safely(self):
        result = auth_hash.verify_password("", "anything", hasher=_FAST_HASHER)
        self.assertFalse(result.ok)


class TestPepper(unittest.TestCase):
    def test_pepper_changes_the_hash_material(self):
        encoded_no_pepper = auth_hash.hash_password("pw", hasher=_FAST_HASHER)
        result_wrong_pepper = auth_hash.verify_password(
            encoded_no_pepper, "pw", pepper="some-pepper", hasher=_FAST_HASHER
        )
        self.assertFalse(result_wrong_pepper.ok)

    def test_matching_pepper_verifies(self):
        encoded = auth_hash.hash_password("pw", pepper="root-only-pepper", hasher=_FAST_HASHER)
        result = auth_hash.verify_password(encoded, "pw", pepper="root-only-pepper", hasher=_FAST_HASHER)
        self.assertTrue(result.ok)


class TestNeedsRehash(unittest.TestCase):
    def test_needs_rehash_true_when_params_upgraded(self):
        weak_hasher = auth_hash.make_hasher(time_cost=1, memory_cost_kib=8192, parallelism=1)
        strong_hasher = auth_hash.make_hasher(time_cost=2, memory_cost_kib=16384, parallelism=1)

        encoded = auth_hash.hash_password("pw", hasher=weak_hasher)
        result = auth_hash.verify_password(encoded, "pw", hasher=strong_hasher)
        self.assertTrue(result.ok)
        self.assertTrue(result.needs_rehash)

    def test_needs_rehash_false_when_params_match(self):
        encoded = auth_hash.hash_password("pw", hasher=_FAST_HASHER)
        result = auth_hash.verify_password(encoded, "pw", hasher=_FAST_HASHER)
        self.assertTrue(result.ok)
        self.assertFalse(result.needs_rehash)

    def test_verify_and_maybe_rehash_produces_new_hash_when_stale(self):
        weak_hasher = auth_hash.make_hasher(time_cost=1, memory_cost_kib=8192, parallelism=1)
        strong_hasher = auth_hash.make_hasher(time_cost=2, memory_cost_kib=16384, parallelism=1)

        encoded = auth_hash.hash_password("pw", hasher=weak_hasher)
        result, new_hash = auth_hash.verify_and_maybe_rehash(encoded, "pw", hasher=strong_hasher)
        self.assertTrue(result.ok)
        self.assertIsNotNone(new_hash)
        # The new hash must itself verify correctly under the strong hasher.
        recheck = auth_hash.verify_password(new_hash, "pw", hasher=strong_hasher)
        self.assertTrue(recheck.ok)
        self.assertFalse(recheck.needs_rehash)

    def test_verify_and_maybe_rehash_no_new_hash_when_fresh(self):
        encoded = auth_hash.hash_password("pw", hasher=_FAST_HASHER)
        result, new_hash = auth_hash.verify_and_maybe_rehash(encoded, "pw", hasher=_FAST_HASHER)
        self.assertTrue(result.ok)
        self.assertIsNone(new_hash)

    def test_verify_and_maybe_rehash_no_new_hash_on_wrong_password(self):
        encoded = auth_hash.hash_password("pw", hasher=_FAST_HASHER)
        result, new_hash = auth_hash.verify_and_maybe_rehash(encoded, "wrong", hasher=_FAST_HASHER)
        self.assertFalse(result.ok)
        self.assertIsNone(new_hash)


if __name__ == "__main__":
    unittest.main()
