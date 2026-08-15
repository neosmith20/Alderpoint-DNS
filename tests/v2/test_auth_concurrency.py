import threading
import time

import pytest

from app.v2.auth_concurrency import (
    DEFAULT_MAX_CONCURRENT_HASHES,
    HashConcurrencyLimiter,
    TooManyConcurrentHashesError,
)


class TestBasicLimiting:
    def test_default_limit_is_conservative(self):
        assert DEFAULT_MAX_CONCURRENT_HASHES <= 4

    def test_single_slot_acquired_and_released(self):
        limiter = HashConcurrencyLimiter(max_concurrent=1)
        with limiter.slot():
            assert limiter.in_flight == 1
        assert limiter.in_flight == 0

    def test_invalid_max_concurrent_rejected(self):
        with pytest.raises(ValueError):
            HashConcurrencyLimiter(max_concurrent=0)


class TestConcurrencyEnforcement:
    def test_exceeding_limit_raises_immediately_not_blocks(self):
        limiter = HashConcurrencyLimiter(max_concurrent=1)
        with limiter.slot():
            with pytest.raises(TooManyConcurrentHashesError):
                with limiter.slot():
                    pass  # never reached

    def test_slot_released_on_exception_inside_block(self):
        limiter = HashConcurrencyLimiter(max_concurrent=1)
        with pytest.raises(RuntimeError):
            with limiter.slot():
                raise RuntimeError("simulated hash failure")
        # Must be released even though the body raised -- otherwise one
        # failed hash would permanently reduce capacity.
        assert limiter.in_flight == 0
        with limiter.slot():
            assert limiter.in_flight == 1

    def test_real_concurrent_threads_respect_the_limit(self):
        limiter = HashConcurrencyLimiter(max_concurrent=2)
        max_observed = [0]
        lock = threading.Lock()
        rejections = [0]

        def worker():
            try:
                with limiter.slot():
                    with lock:
                        max_observed[0] = max(max_observed[0], limiter.in_flight)
                    time.sleep(0.05)
            except TooManyConcurrentHashesError:
                with lock:
                    rejections[0] += 1

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert max_observed[0] <= 2  # never exceeded the configured limit
        assert rejections[0] > 0  # some requests were genuinely rejected, not queued
