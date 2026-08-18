# Real Argon2id concurrency-DoS defect found live, fixed, RC13 verified

Roadmap item: Argon2id full-stack validation re-check. Found via real
concurrent-login load testing against a real installed RC12 package
(2 vCPU / 2 GiB podman container), not from code review alone.

## What was found

`app/v2/auth_concurrency.py`'s `HashConcurrencyLimiter` exists
specifically to fail fast (503) on concurrent Argon2id operations
beyond a configured cap, because a single hash allocates ~256 MiB and
several concurrent ones can genuinely exhaust a small appliance's
memory and starve its CPU (documented in that module's own docstring).
`app/v2/webapp.py`'s `/api/login` was supposed to be protected by this
via `_hash_limiter` -- but `app/v2/auth_hash.py`'s
`verify_and_maybe_rehash` (what `/api/login` actually calls) had **no
`limiter` parameter at all**, so the limiter passed at the call site
was structurally unable to reach the real verify call. The signup path
(`hash_password(..., limiter=_hash_limiter)`) was correctly protected;
only login was not.

**Real, live measured impact (RC12, 2 vCPU / 2 GiB, real installed
package):** 5 truly concurrent real `/api/login` requests all
succeeded with `200`, but took **~349 seconds each** (vs. ~0.5s
single-request baseline at the same host load) -- real, severe CPU/
memory contention from 5 unbounded concurrent Argon2id operations
(each internally using 2 threads at 256 MiB), not a clean, fast 503 as
the architecture's own threat model intends. This is exactly the
concurrent-login DoS shape `auth_concurrency.py` was built to prevent,
left open on the one endpoint that most needs it.

## Fix

- `app/v2/auth_hash.py`: `verify_and_maybe_rehash` gained a `limiter`
  parameter, forwarded to both the `verify_password` and (rehash-path)
  `hash_password` calls.
- `app/v2/webapp.py`: `/api/login`'s call site now passes
  `limiter=_hash_limiter`.
- Regression coverage added: `tests/v2/test_auth_concurrency_integration.py`
  (`test_verify_and_maybe_rehash_respects_limiter`,
  `test_verify_and_maybe_rehash_normal_operation_unaffected` -- the
  library-level gap) and `tests/v2/test_webapp.py`
  (`test_login_rejects_fast_with_503_when_hash_limiter_saturated` --
  pins the fix at the actual HTTP boundary, which is what the original
  gap escaped through since no existing test exercised
  `verify_and_maybe_rehash` under a saturated limiter at all).

Full suite (`tests/v2/` + `tests/`): 875 + 2064 passed, 0 failures,
after the fix.

## Live re-verification (RC13, real installed package)

Fresh RC13 `.deb` built and installed clean (`systemctl --failed`:
zero units). 6 truly concurrent real `/api/login` requests against
the live service:

- 3 succeeded (`200`) in ~3.8s each (still real CPU contention under
  concurrent Argon2id at 2 vCPU, but bounded and expected -- not the
  349s pathology).
- 3 were rejected immediately (`503 auth_busy`) in ~30ms each --
  exactly the fast-fail behavior the architecture document describes.

Confirms the fix is live and correct in the real packaged artifact,
not just at the unit-test level.

## Conclusion

This closes the last structural gap in the Argon2id concurrency
protection story for V2: both the signup and login paths are now
genuinely bounded. No further Argon2id-related defects found in this
pass. Superseded findings: the RC12 hardware/performance matrix single
-request timings (`docs/v2/hardware-performance-matrix-rc12.md`)
remain accurate for their own scope (single-request-at-a-time DNS
load, not concurrent-login load) and are not affected by this fix.
