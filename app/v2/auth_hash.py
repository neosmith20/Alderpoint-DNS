"""V2 Argon2id password-hashing contract.

Scope (V2 Workstream 1): a thin, explicit wrapper around argon2-cffi
implementing the security contract from
``docs/v2/roadmap-reference/v2-architecture-plan.md`` §3.3:

- Argon2id
- unique random salt per password (argon2-cffi does this by default)
- parameters encoded into the stored hash string (argon2-cffi does this by
  default via the PHC string format)
- no plaintext/reversible storage
- automatic needs-rehash detection
- automatic rehash after successful authentication (caller-driven, see
  ``verify_and_maybe_rehash``)

Not implemented in Workstream 1: the pepper. See
``docs/v2/architecture-map.md`` for the recommendation and rationale; this
module exposes an optional ``pepper`` parameter so a later workstream can
wire it in without changing the call signature callers already use.
"""

from __future__ import annotations

from dataclasses import dataclass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.v2.auth_concurrency import HashConcurrencyLimiter

try:  # argon2-cffi >= 23 renamed InvalidHash -> InvalidHashError
    from argon2.exceptions import InvalidHashError
except ImportError:  # pragma: no cover - depends on installed argon2-cffi version
    from argon2.exceptions import InvalidHash as InvalidHashError

# Recommended parameters, see docs/v2/architecture-map.md "Argon2id
# recommendation" for the benchmark data this was chosen from (measured on
# the actual 4 vCPU / 3.8 GiB test server: ~440-460ms per hash/verify at
# these settings). These are the module defaults for the roadmap's "normal"
# appliance profile (2 vCPU / 2 GiB); callers may override for testing
# (fast/insecure params) or for a constrained "low-end" 1 vCPU / 512 MiB
# target, which needs its own re-verification before shipping — see the
# open-risk note in docs/v2/architecture-map.md.
DEFAULT_TIME_COST = 4
DEFAULT_MEMORY_COST_KIB = 262144  # 256 MiB
DEFAULT_PARALLELISM = 2
DEFAULT_HASH_LEN = 32
DEFAULT_SALT_LEN = 16


def make_hasher(
    *,
    time_cost: int = DEFAULT_TIME_COST,
    memory_cost_kib: int = DEFAULT_MEMORY_COST_KIB,
    parallelism: int = DEFAULT_PARALLELISM,
) -> PasswordHasher:
    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=DEFAULT_HASH_LEN,
        salt_len=DEFAULT_SALT_LEN,
    )


_default_hasher = make_hasher()


def hash_password(
    password: str,
    *,
    pepper: str | None = None,
    hasher: PasswordHasher | None = None,
    limiter: "HashConcurrencyLimiter | None" = None,
) -> str:
    """Return an encoded Argon2id hash (PHC string, includes salt + params).

    ``limiter`` (``app/v2/auth_concurrency.py``, §38) bounds how many
    concurrent Argon2id operations may run at once, protecting memory
    under concurrent-login load; omitted by default (``None``) so existing
    callers/tests are unaffected -- a real deployment wires one shared
    limiter instance through every login/hash call site.
    """
    hasher = hasher or _default_hasher
    material = password if pepper is None else f"{pepper}{password}"
    if limiter is None:
        return hasher.hash(material)
    with limiter.slot():
        return hasher.hash(material)


@dataclass
class VerifyResult:
    ok: bool
    needs_rehash: bool = False
    error: str | None = None


def verify_password(
    encoded_hash: str,
    password: str,
    *,
    pepper: str | None = None,
    hasher: PasswordHasher | None = None,
    limiter: "HashConcurrencyLimiter | None" = None,
) -> VerifyResult:
    """Verify a password against an encoded hash.

    Malformed/foreign hashes fail closed (ok=False, error set) rather than
    raising — callers should not need a try/except around every login check.
    A saturated ``limiter`` (§38) is deliberately NOT treated the same way:
    ``TooManyConcurrentHashesError`` propagates rather than being folded
    into ``VerifyResult(ok=False)``, so a caller can distinguish "wrong
    password" from "system under load, retry" and respond accordingly
    (e.g. a 503, not a fake login failure that could confuse a real user
    or get logged as a suspicious failed-auth attempt it isn't).
    """
    hasher = hasher or _default_hasher
    material = password if pepper is None else f"{pepper}{password}"
    if limiter is not None:
        with limiter.slot():
            return _do_verify(hasher, encoded_hash, material)
    return _do_verify(hasher, encoded_hash, material)


def _do_verify(hasher: PasswordHasher, encoded_hash: str, material: str) -> VerifyResult:
    try:
        hasher.verify(encoded_hash, material)
    except VerifyMismatchError:
        return VerifyResult(ok=False, error="mismatch")
    except InvalidHashError as exc:
        return VerifyResult(ok=False, error=f"invalid_hash: {exc}")
    except Exception as exc:  # defensive: never let a malformed hash crash auth
        return VerifyResult(ok=False, error=f"unexpected: {exc}")

    needs_rehash = hasher.check_needs_rehash(encoded_hash)
    return VerifyResult(ok=True, needs_rehash=needs_rehash)


def verify_and_maybe_rehash(
    encoded_hash: str,
    password: str,
    *,
    pepper: str | None = None,
    hasher: PasswordHasher | None = None,
    limiter: "HashConcurrencyLimiter | None" = None,
) -> tuple[VerifyResult, str | None]:
    """Verify, and if the stored hash's parameters are stale, compute a fresh
    hash under current parameters. Returns (result, new_encoded_hash_or_None).

    Caller is responsible for persisting new_encoded_hash if not None — this
    module never touches control.db directly.

    ``limiter`` is forwarded to both the verify and the (rare) rehash
    calls. Real defect found live during real concurrent-login load
    testing: this function previously had no ``limiter`` parameter at
    all, so the login endpoint's call into it was structurally unable
    to engage ``HashConcurrencyLimiter`` no matter what the caller
    passed -- exactly the unbounded-concurrent-Argon2id DoS shape
    ``auth_concurrency.py``'s own module docstring describes as the
    threat this exists to prevent. 5 concurrent real logins against a
    real installed package (2 vCPU / 2 GiB) measured ~349s per
    request (vs. ~0.5s single-request baseline) instead of the fourth
    and fifth being fast-rejected with 503 as designed.
    """
    result = verify_password(encoded_hash, password, pepper=pepper, hasher=hasher, limiter=limiter)
    if not result.ok or not result.needs_rehash:
        return result, None
    new_hash = hash_password(password, pepper=pepper, hasher=hasher, limiter=limiter)
    return result, new_hash
