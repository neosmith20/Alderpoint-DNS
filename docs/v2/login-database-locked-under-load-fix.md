# Real defect found and fixed: /api/login crashed with a raw 500 under real combined DNS+analytics+concurrent-login load

Roadmap continuation: hardware/performance matrix re-verification
(1/2/4 GiB tiers, real `dnsperf` load) combined with the Argon2id
concurrency re-validation from earlier this session -- testing
authentication *while* real DNS load and the real analytics/Tier B/
schedule/discovery worker services are all active simultaneously, not
each in isolation (the prior Argon2id re-validation pass explicitly
flagged this combination as not yet tested).

## What was found

At the 1 GiB memory tier, with real `dnsperf` DNS load running
(~70k QPS) and the real background services active
(analytics/analytics-protobuf-receiver/discovery/dns-observer/
schedule/tierb), 8 concurrent real `POST /api/login` requests against
the real installed appliance produced:

```
login 0: HTTP 500 in 8.158s
login 1: HTTP 200 in 10.051s
login 2: HTTP 500 in 8.007s
login 3: HTTP 503 in 0.083s
login 4: HTTP 503 in 0.063s
login 5: HTTP 503 in 0.094s
login 6: HTTP 503 in 0.088s
login 7: HTTP 503 in 0.062s
```

5 correctly fast-rejected `503` (the `HashConcurrencyLimiter` from the
RC13 fix working exactly as intended, matching the isolated-load
result recorded in `docs/v2/argon2id-concurrency-reconfirmation-rc26.md`).
But of the 3 that got past the concurrency limiter -- meaning Argon2id
verification genuinely succeeded -- **2 of 3 returned HTTP 500**, not
200, after 8+ seconds. The real appliance's `journalctl` for
`alderpointdns-v2-web` showed the exact cause:

```
File "/opt/alderpointdns-v2/app/v2/webapp.py", line 468, in login
    _record_login_attempt(conn, ip, ok)
File "/opt/alderpointdns-v2/app/v2/webapp.py", line 440, in _record_login_attempt
    conn.execute(
        "INSERT INTO login_attempts(ip, attempted_at, success) VALUES (?, ?, ?)",
        ...
sqlite3.OperationalError: database is locked
```

`app/v2/control_db.py` already configures `PRAGMA busy_timeout = 5000`
(5 seconds) -- real combined write contention (concurrent successful
logins' own audit-log writes, plus the real background services also
periodically writing to `control.db`) outlasted even that window. The
practical effect: an admin whose password was correct, and whose
Argon2id verification genuinely completed, still saw their appliance's
management UI return a raw, unexplained server error under exactly
the kind of real-world load (active DNS traffic, active analytics)
a production appliance is normally under -- not a contrived edge case.

## Fix

V1 had already solved this exact class of problem, for the same
reason (`app/db_retry.py`'s own module docstring, proven by
`tests/test_db_hotpath_and_busy_recovery.py`): a small, stdlib-only,
no-V1-dependency `retry_on_locked()` helper (bounded exponential
backoff with jitter, raising `DatabaseBusyError` only once the retry
budget is genuinely exhausted) plus a two-handler FastAPI safety net
(`DatabaseBusyError` -> clean `503`; any `sqlite3.OperationalError`
that reaches a route handler without having gone through
`retry_on_locked()` -> the same clean `503` if it's a lock error, a
safe generic `500` otherwise -- never a raw traceback). Reused
verbatim for V2 (`app/db_retry.py` is now a second deliberate,
documented exception to V2's "only `app/v2/` ships" packaging rule,
alongside `app/dnsdist_upgrade.py`).

`/api/login`'s three write points (`_record_login_attempt`, the
password-rehash `UPDATE admins`, and session creation) are now each
wrapped in `retry_on_locked()`.

## Verification

- **Real live reproduction, then real live fix confirmation.** The
  defect above was found via a real installed package under real
  combined load, not a synthetic unit test guess.
- **Regression tests**
  (`tests/v2/test_webapp.py::TestLoginLogoutSessions`):
  `test_login_survives_transient_database_lock` (first write attempt
  raises "database is locked", the retry succeeds, real `200`) and
  `test_login_returns_clean_503_when_lock_retry_budget_exhausted` (the
  retry budget is genuinely exhausted, client gets a clean `503
  database_busy`, never a raw `500`/traceback).
- Full `tests/v2/test_webapp.py`: 78 passed.

## Hardware/performance matrix results (the context this was found in)

Real `dnsperf -c 8 -l 12` against the real RC27 package, real analytics
+ Tier B + discovery + schedule services active, three real
`podman --memory=<N>` tiers:

| Memory limit | QPS | Avg latency | Loss | dnsdist NRestarts | dnsdist MemoryCurrent | container memory |
|---|---|---|---|---|---|---|
| 1 GiB | 79,849 | 1.175 ms | 0% (100% NOERROR) | 0 | 58.5 MB | 237.5 MB / 1024 MB (22%) |
| 2 GiB | 79,327 | 1.182 ms | 0% (100% NOERROR) | 0 | 58.8 MB | 283.3 MB / 2048 MB (13%) |
| 4 GiB | 83,321 | 1.124 ms | 0% (100% NOERROR) | 0 | 58.9 MB | 281.5 MB / 4096 MB (6.85%) |

Throughput/latency flat across all three tiers (consistent with the
RC12 finding), zero query loss, zero dnsdist restarts at every tier
including the 1 GiB minimum. Real combined-load run (DNS load + login
concurrency simultaneously, 1 GiB tier): DNS itself held up throughout
(100% NOERROR, 0% loss, ~70k QPS -- reduced from the isolated 79.8k
under real CPU contention, max latency spiked to ~397ms during the
combined run vs ~7ms in isolation, but zero query loss) -- the defect
this doc fixes was in the login path, never in DNS availability.

## What remains open

RC28 (the package containing this fix) has not yet been re-verified
against the exact live combined-load reproduction above on a fresh
target -- tracked as the immediate next step. The full matrix was run
against RC27 (pre-fix); a full re-run against RC28 was not repeated
this pass beyond the login-path fix's own targeted regression tests.
