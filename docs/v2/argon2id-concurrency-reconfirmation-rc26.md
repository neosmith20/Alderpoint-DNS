# Argon2id full-stack concurrency re-validation, through RC26

Roadmap continuation: re-verifying `app/v2/auth_concurrency.py`'s
`HashConcurrencyLimiter` (the RC13 fix,
`docs/v2/argon2id-concurrency-defect-and-rc13-fix.md`) still correctly
protects `/api/login` now that all five encrypted DNS transports and
the new DNSCrypt provisioning surface exist, via a real running
instance (`uvicorn app.v2.webapp:app`, real threads, real Argon2id
computation -- no mocks) rather than assuming the RC13 result still
holds unchanged.

## Concurrent valid-login pressure

8 real concurrent `POST /api/login` requests with the correct
password, against `DEFAULT_MAX_CONCURRENT_HASHES=3`:

```
login 0: HTTP 503 in 0.056s
login 1: HTTP 503 in 0.052s
login 2: HTTP 200 in 0.758s
login 3: HTTP 503 in 0.055s
login 4: HTTP 503 in 0.051s
login 5: HTTP 200 in 0.794s
login 6: HTTP 200 in 0.792s
login 7: HTTP 503 in 0.049s

succeeded: 3, fast-rejected (503): 5
```

Exactly the limiter's own configured bound succeeded (real Argon2id
verify completing in ~0.75-0.8s each); every request beyond it was
rejected in ~50ms, not queued -- matching the module's own design intent
("fail fast... not queued indefinitely") and RC13's original result
shape.

## Concurrent invalid-login pressure (the actual DoS shape an attacker would use)

10 real concurrent requests with wrong passwords:

```
401 (real auth-failure verify completed): 3
503 (fast concurrency-reject): 7
```

Confirms the limiter protects the failure path identically to the
success path -- Argon2id must still compute the hash to determine a
password is wrong (no cheap early-exit exists or should exist, that
would be a timing side-channel), so this is the real attack shape the
RC13 fix exists to bound, re-confirmed still bounded correctly.

## Real memory measurement under peak concurrent load

`VmRSS` of the real running webapp process, before/during/after the
3-concurrent-hash burst above:

```
baseline:                    70,428 KB  (~69 MiB)
peak during 3 concurrent hashes: 857,136 KB  (~837 MiB), VmPeak 1,614,568 KB (~1.58 GiB)
after load (immediate):      70,752 KB  (~69 MiB) -- clean return, no leak
```

This closely matches the module's own documented estimate ("~256 MiB
per concurrent hash... 3 concurrent operations is ~768 MiB of transient
working set") -- measured peak (~837 MiB total, ~768 MiB of which is
attributable to the three concurrent hashes above the ~69 MiB baseline)
lines up almost exactly with that design rationale, empirically
confirming the estimate the `DEFAULT_MAX_CONCURRENT_HASHES=3` bound was
chosen against, not just assuming the prior documentation was still
accurate.

**Real hardware-sizing implication surfaced by this measurement**: on
the smallest supported 1 GiB profile, a concurrent-login burst at the
limiter's own configured bound transiently consumes roughly 82% of
total system memory (837 MiB of 1024 MiB) for the duration of those
hashes (well under a second in this environment) before returning to
baseline. This is not a defect -- the limiter is doing exactly its job,
and the RC13 fix's entire point was making this bounded and transient
rather than unbounded -- but it is a real, concrete data point for the
hardware minimum/recommended memory conclusion: a 1 GiB appliance has
very little headroom for concurrent DNS/analytics load during a
login burst at the current default bound. Worth revisiting whether
`DEFAULT_MAX_CONCURRENT_HASHES` should scale down further on detected
low-memory profiles, or whether 1 GiB should be documented as a harder
floor than "supported" -- a product decision, not resolved here.

## What this does not cover

This pass re-verified the concurrency-limiter's correctness and
measured its real memory footprint under a synthetic concurrent-login
burst on this development host -- it did not repeat the full 1/2/4 GiB
constrained-profile matrix from `docs/v2/hardware-performance-matrix-rc12.md`
under simultaneous real DNS + analytics load (that full hardware
matrix re-verification remains open, see the handoff report), nor did
it test login concurrency while a real memory-constrained (podman
`--memory=1g`) container is simultaneously serving live DNS traffic
under load -- a combination worth testing together, tracked as the
next step of this specific item.
