"""Integration test: app/v2/auth_concurrency.py's limiter wired into
app/v2/auth_hash.py's real Argon2id hash/verify calls (§38)."""

import threading

import pytest
from argon2 import PasswordHasher

from app.v2.auth_concurrency import HashConcurrencyLimiter, TooManyConcurrentHashesError
from app.v2.auth_hash import hash_password, verify_and_maybe_rehash, verify_password


@pytest.fixture()
def fast_hasher():
    # Cheap params so the test runs quickly -- concurrency behavior is
    # what's under test, not Argon2id's real timing.
    return PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


class TestLimiterWiredIntoRealHashing:
    def test_hash_password_respects_limiter(self, fast_hasher):
        limiter = HashConcurrencyLimiter(max_concurrent=1)
        results = []
        errors = []

        def worker():
            try:
                results.append(hash_password("pw", hasher=fast_hasher, limiter=limiter))
            except TooManyConcurrentHashesError:
                errors.append(1)

        # Occupy the single slot manually, then try a real hash call
        # concurrently -- it must be rejected, not silently allowed
        # through or blocked forever.
        with limiter.slot():
            t = threading.Thread(target=worker)
            t.start()
            t.join(timeout=5)

        assert results == []
        assert errors == [1]

    def test_verify_password_respects_limiter_and_error_is_distinguishable(self, fast_hasher):
        limiter = HashConcurrencyLimiter(max_concurrent=1)
        encoded = hash_password("correct-horse", hasher=fast_hasher)

        with limiter.slot():
            with pytest.raises(TooManyConcurrentHashesError):
                verify_password(encoded, "correct-horse", hasher=fast_hasher, limiter=limiter)

    def test_normal_operation_without_saturation_unaffected(self, fast_hasher):
        limiter = HashConcurrencyLimiter(max_concurrent=3)
        encoded = hash_password("pw", hasher=fast_hasher, limiter=limiter)
        result = verify_password(encoded, "pw", hasher=fast_hasher, limiter=limiter)
        assert result.ok

    def test_omitting_limiter_preserves_existing_behavior(self, fast_hasher):
        # Backward compatibility: every pre-existing caller that doesn't
        # pass limiter= must work exactly as before.
        encoded = hash_password("pw", hasher=fast_hasher)
        result = verify_password(encoded, "pw", hasher=fast_hasher)
        assert result.ok

    def test_verify_and_maybe_rehash_respects_limiter(self, fast_hasher):
        # Real defect found live during RC12 concurrent-login load
        # testing: verify_and_maybe_rehash (what app/v2/webapp.py's
        # /api/login actually calls) had no limiter= parameter at all,
        # so the login endpoint's own _hash_limiter was silently
        # dropped -- concurrent logins ran fully unbounded Argon2id
        # instead of the 4th+ being fast-rejected with 503 as designed.
        # This pins the fix: a saturated limiter must reject a real
        # verify_and_maybe_rehash call, not silently let it through.
        limiter = HashConcurrencyLimiter(max_concurrent=1)
        encoded = hash_password("correct-horse", hasher=fast_hasher)

        with limiter.slot():
            with pytest.raises(TooManyConcurrentHashesError):
                verify_and_maybe_rehash(encoded, "correct-horse", hasher=fast_hasher, limiter=limiter)

    def test_verify_and_maybe_rehash_normal_operation_unaffected(self, fast_hasher):
        limiter = HashConcurrencyLimiter(max_concurrent=3)
        encoded = hash_password("pw", hasher=fast_hasher, limiter=limiter)
        result, new_hash = verify_and_maybe_rehash(encoded, "pw", hasher=fast_hasher, limiter=limiter)
        assert result.ok
