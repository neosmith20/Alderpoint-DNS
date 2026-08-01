#!/usr/bin/env python3
"""Shared helper for retrying SQLite writes that hit SQLITE_BUSY / SQLITE_LOCKED.

Used where a write cannot simply be skipped (unlike e.g. session last_seen
bookkeeping, which retries a couple of times and then gives up quietly) but
also must never retry forever -- a bounded, jittered backoff either succeeds
or raises DatabaseBusyError so the caller can return a controlled response
instead of an unhandled traceback.
"""
from __future__ import annotations

import random
import sqlite3
import time
from typing import Callable, TypeVar

T = TypeVar("T")

DEFAULT_ATTEMPTS = 5
DEFAULT_BASE_DELAY = 0.05
DEFAULT_MAX_DELAY = 1.0


class DatabaseBusyError(RuntimeError):
    """Raised when a write could not complete after exhausting the retry budget."""


def is_lock_error(exc: BaseException) -> bool:
    return isinstance(exc, sqlite3.OperationalError) and ("locked" in str(exc).lower() or "busy" in str(exc).lower())


def retry_on_locked(
    func: Callable[[], T],
    *,
    attempts: int = DEFAULT_ATTEMPTS,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
) -> T:
    """Runs `func()`, retrying with bounded exponential backoff plus jitter
    only when SQLite reports the database as locked/busy. Any other
    exception propagates immediately. Once `attempts` is exhausted, raises
    DatabaseBusyError (chained to the original OperationalError) instead of
    retrying indefinitely."""
    last_exc: sqlite3.OperationalError | None = None
    for attempt in range(attempts):
        try:
            return func()
        except sqlite3.OperationalError as exc:
            if not is_lock_error(exc):
                raise
            last_exc = exc
            if attempt < attempts - 1:
                delay = min(max_delay, base_delay * (2**attempt))
                time.sleep(delay + random.uniform(0, delay * 0.25))
    raise DatabaseBusyError(str(last_exc)) from last_exc
