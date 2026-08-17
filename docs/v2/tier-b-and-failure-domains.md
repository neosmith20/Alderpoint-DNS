# Tier B validation + failure-domain pass (roadmap Priorities 5/6)

Real installed `alderpointdns-v2` package, real systemd units, real
`dnsdist`, on this session's real KVM host.

## Real defect found and fixed: Tier B prewarm never actually resolved anything

`scripts/v2/alderpointdns_v2_ctl.py`'s `tier-b-worker` subcommand -- the
actual systemd-invoked entry point (`alderpointdns-v2-tierb.service`) --
had its own inline `resolve_fn` that sent a zero-byte UDP packet to the
configured DNS address/port and returned `True` as soon as `sendto()`
didn't raise. It never built a real DNS query, never used
`entry.qname`/`entry.qtype` at all, and never waited for or checked a
response. `run_prewarm`'s reported stats were therefore meaningless, and
in production this worker never actually warmed anything -- a cold cache
stayed cold regardless of how many times it "successfully" ran.

A real, correct, already-tested resolve function
(`app/v2/tier_b_worker.py`'s `make_udp_resolve_fn`,
`tests/v2/test_tier_b_worker.py`) existed the entire time but was never
wired into the actual packaged entry point -- only exercised by tests
calling the library directly. Same category of bug as the RPZ/local-DNS
wiring gap fixed earlier this branch: a correct implementation existed,
disconnected from the real invocation path.

Fixed: `cmd_tier_b_worker` now calls `make_udp_resolve_fn` instead of its
own inline fake. Added `tests/v2/test_ctl_tier_b_worker_wiring.py` (3
tests): a real isolated-dnsdist resolve succeeds, the identical call
against a closed port correctly fails (the old fake could never tell
these apart), and a source-level guard against reintroducing the fake.

Also confirmed, by reading (not fixed, already honestly self-documented
in the code): `app/v2/analytics_pipeline.py`'s own docstring states
plainly that "nothing calls `ingest()` from a live DNS path yet -- no
such path exists in this workstream." Grep-verified still true: no
`RemoteLogger`/protobuf-logging directive is ever emitted into the live
dnsdist config by `dnsdist_gen.py` or `dnsdist_policy_runtime.py`, so in
today's real deployment, `record_query`/Tier B's working-set index is
never populated from real production DNS traffic -- only from whatever an
operator or script writes into `analytics/inbox/*.jsonl` (a real,
already-implemented path, used deliberately for this session's testing
below) or injects via `--inject-test-event`. This is a known, pre-existing
gap in the analytics data-source wiring, not something this session
introduced or attempted to fix (a real dnsdist protobuf-logging
integration is a separate, larger feature).

Rebuilt as private11 (SHA-256
`cedc7aea615d19def4037016a23b77a0b4ee8d06e2df0d9050a68c0ae54666cc`) --
all results below are against this artifact.

## Tier B: real cold vs. prewarm comparison

Seeded a real 15-domain working set through the real pipeline (wrote
`analytics/inbox/seed1.jsonl`, drained via
`alderpointdns-v2-ctl analytics-worker --once`, which submits through
`AnalyticsPipeline` exactly as production code would, ending in a real
`tier_b_flush()` to `tierb/working-set.json`). Verified the index ranked
by real popularity (`example.com` hit_count=20 highest, descending).

- **Cold** (restart `dnsdist` to clear its packet cache, no prewarm run,
  query all 15 domains once each): avg **31.57 ms** per first-touch query
  (real upstream round-trips; individual domains ranged 13-89 ms).
- **Prewarm** (restart `dnsdist` again, run the now-fixed
  `tier-b-worker --once` first, *then* query the same 15 domains): avg
  **17.24 ms** -- a real, measured ~45% latency reduction from the fix,
  because the prewarm run now actually performs real queries that
  populate dnsdist's packet cache before the simulated clients ask.

## Tier B: corruption / kill / removal

- **Corrupted state file** (`working-set.json` overwritten with invalid
  JSON): `tier-b-worker --once` exits 0, reports `attempted 0` (clean
  degrade to cold/empty, matching `tier_b_prewarm.load()`'s documented
  "never raises" contract), and a live DNS query immediately after still
  returns `NOERROR`.
- **State file removed entirely**: same clean degrade, exit 0, DNS
  unaffected.
- **Killed mid-prewarm** (seeded a 200-domain working set, started
  `tier-b-worker --once --max-names 200` in the background, `kill -9`ed
  the real process ~1.5s into its rate-limited run): process confirmed
  gone (`pgrep` empty); a DNS query issued immediately after still
  returned `NOERROR`; `alderpointdns-v2-dnsdist.service` stayed `active`
  throughout. (Architecture note: `_tick_once()` never calls
  `tier_b_flush()` -- the prewarm tick only *reads* the snapshot and
  replays queries, it does not rewrite the state file -- so there is no
  partial-write risk to test for this specific worker; the state file's
  own atomic-write contract is exercised separately by
  `tests/v2/test_tier_b_prewarm.py`.)

**Required result confirmed**: corrupting/killing/removing Tier B state
produces a cold cache, never a DNS outage.

## Failure-domain pass

With DNS actively answering (`example.com` query succeeding throughout),
stopped each optional component individually, confirmed `NOERROR`
immediately after each stop, then restarted it before moving to the next:

`alderpointdns-v2-web`, `-analytics`, `-tierb`, `-schedule`,
`-discovery`, `-dns-observer`, `-replication` -- **all seven
independently confirmed to have zero effect on DNS answering.**

**Combination test**: stopped all seven simultaneously -- DNS still
answered `NOERROR`.

**Storage failure after runtime already compiled** (the specific case the
roadmap calls out): with `dnsdist` already running against its promoted
config,
- `control.db` **moved away entirely** (not just the reading service
  stopped) -- DNS still answered `NOERROR`.
- `secrets/` directory **moved away entirely** -- DNS still answered
  `NOERROR`.

Confirms the architecture's stated design invariant
(`dnsdist_policy_runtime.py`'s own docstring: "DNS answering is
intentionally independent of the management UI, analytics, discovery,
replication, DuckDB, and Tier B workers... this unit only reads the
already-promoted runtime artifact") holds under real, not just
documented, conditions -- including the harshest version tested (control
state removed from disk entirely, not merely a stopped service).

**One real observation, not a fix**: starting `alderpointdns-v2-web`
with `control.db` missing did not fail or crash-loop -- it started
`active` and returned `HTTP 401` (unauthenticated) normally. This is
because `sqlite3.connect()` silently creates a new, empty database file
at a missing path rather than raising. Functionally safe (no crash, no
corruption, no silent data-loss risk beyond what already happened when
the file was removed) and arguably a reasonable degrade choice matching
this codebase's general "fail open to a fresh/cold state, not fail
closed" pattern elsewhere (Tier B, migration health-check) -- but it
means an accidentally-deleted `control.db` produces no operator-visible
signal at all, silently starting a blank appliance instead. Flagged for
awareness, not changed this session.

## Tests

`tests/v2`: 823 passed (820 + 3 new in
`test_ctl_tier_b_worker_wiring.py`). No regressions.
