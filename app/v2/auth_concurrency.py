"""V2 Argon2id concurrency protection (Workstream 3 final continuation,
§38).

A single Argon2id hash at the evidence-backed default parameters
(``time_cost=4, memory_cost=256 MiB, parallelism=2``, see
``app/v2/auth_hash.py``/``docs/v2/hardware-memory-profile-results.md``)
allocates ~256 MiB of working memory for the duration of the hash/verify
call. N simultaneous login attempts (real or malicious/DoS-shaped) each
running their own Argon2id call would multiply that -- a small number of
concurrent logins is enough to exhaust a 1-2 GiB appliance's memory
budget well before the actual host memory cap, degrading (or, per
Workstream 2's constrained-memory evidence, catastrophically slowing) the
whole system rather than just the login path.

This module bounds concurrent Argon2id operations with a simple counting
semaphore: requests beyond the configured limit are rejected immediately
(fail fast with a clear error) rather than queued indefinitely (an
unbounded queue would itself be a memory-exhaustion vector, and a
slow-but-eventually-served login under attack is not meaningfully better
than a fast, clear rejection) or allowed to proceed uncontrolled.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

# Conservative default: at 256 MiB per concurrent hash, 3 concurrent
# operations is ~768 MiB of transient working set -- fits inside the 1 GiB
# candidate profile with room for everything else already measured
# resident (V1 baseline ~457 MB), without requiring the caller to reason
# about the exact number themselves.
DEFAULT_MAX_CONCURRENT_HASHES = 3


class TooManyConcurrentHashesError(RuntimeError):
    """Raised when the concurrency limit is already saturated -- callers
    should map this to a 429/503-shaped response, not a generic 500."""


class HashConcurrencyLimiter:
    def __init__(self, max_concurrent: int = DEFAULT_MAX_CONCURRENT_HASHES):
        if max_concurrent <= 0:
            raise ValueError("max_concurrent must be positive")
        self.max_concurrent = max_concurrent
        self._sem = threading.Semaphore(max_concurrent)
        self._lock = threading.Lock()
        self._in_flight = 0

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self._in_flight

    @contextmanager
    def slot(self) -> Iterator[None]:
        acquired = self._sem.acquire(blocking=False)
        if not acquired:
            raise TooManyConcurrentHashesError(
                f"too many concurrent password-hash operations in flight "
                f"(limit: {self.max_concurrent}) -- rejected to protect memory, retry shortly"
            )
        with self._lock:
            self._in_flight += 1
        try:
            yield
        finally:
            with self._lock:
                self._in_flight -= 1
            self._sem.release()
