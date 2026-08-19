# V2 Architecture Map — Workstream 1 Summary

**Status:** V2 Workstream 1 output, consolidating `docs/v2/storage-audit.md`,
`docs/v2/failure-domains.md`, and `docs/v2/benchmark-results.md` into the confirmed architecture.
Amended after the Dex architecture gate review (see "Architecture gate remediation" below) — that
section is the most current statement of a few decisions (pepper, hardware profiles, notification
secrets) that changed from this document's first pass.

**Architecture lock-in:** after Dex Gate #1 passed ("ALDERPOINT DNS V2 WORKSTREAM 1 ARCHITECTURE
VERIFIED AND READY FOR WORKSTREAM 2"), this document plus the public roadmap
(`docs/v2-architecture-plan.md`, `docs/v2-adguard-parity-matrix.md`, `V2_ROADMAP.md`) were updated
to record the Workstream 1 decisions — including the new RAM-first DNS cache / effective cache
profile / Tier A-B recovery requirement below — as durable project requirements, not
conversation-only context. No runtime/source behavior changed in that commit; documentation only.

**Workstream 2 (runtime storage integration):** turned the frozen shapes above into real,
production-shaped (not yet live-wired) implementations — real Parquet writer with segment
validation, a partition-pruning DuckDB reader (the gate 1 proof that was outstanding after
Workstream 1), real filesystem-based retention, an isolated aggregate SQLite WAL runtime, config
filesystem hardening (ownership contract, symlink rejection), a secret-store foundation, durable
(crash-survivable) migration state, the effective-cache-profile compiler, and a Tier B prewarm
prototype — plus a Tier A feasibility assessment recommending it be deferred. See
`docs/v2/handoff-workstream-2.md`'s "Workstream 2 delivered" section for the full list and
`docs/v2/v1-performance-baseline.md` / `docs/v2/hardware-memory-profile-results.md` /
`docs/v2/tier-a-feasibility.md` for the new supporting evidence. None of this is wired into the live
v1.1.1 runtime — every module lives under `app/v2/`, tested only against disposable tempdir/dev
paths.

**Workstream 3 (partial — policy engine + staged deployment):** built the unified policy hierarchy
(global -> network -> group -> client -> schedule override), a deterministic side-effect-free
effective-policy compiler with a full explain trace, and wired it into Workstream 2's cache-profile
compiler (proving non-answer-affecting fields never change the cache profile and answer-affecting
ones always do). Also built a generic stage->validate->promote->rollback runtime-deployment
abstraction and a dnsdist config-generation prototype validated against the real installed dnsdist
binary (found and fixed a real `--check-config` positional-argument footgun in the process). This
was an intentionally partial first pass against a much larger requested scope. A subsequent "deep
continuation" pass in the same branch substantially expanded this: real control.db policy storage
with round-trip proof, a policy preview/explain service, real BIND/RPZ generation validated against
the installed `named-checkzone`, real SafeSearch/parental/malware/service filtering decision logic,
upstream profile storage + domain routing + ECS compiled into real dnsdist config, a real analytics
ingestion pipeline (normalized event -> Parquet + aggregates + Tier B in one place), an analytics
query service, notification-provider CRUD wired to the secret store (plaintext-absence proven via
raw on-disk inspection), Tier B wired to a real isolated dnsdist subprocess end-to-end, and
fallback-DNS decision logic with a privacy-downgrade guard — 431 `tests/v2/` tests total, 13
checkpoint commits. See `docs/v2/handoff-workstream-4.md` for the full delivered/blocked/not-reached
breakdown per queue item and next-session priority order. Still nothing is wired into the live
v1.1.1 runtime.

## Storage ownership (confirmed)

| Store | Path | Contents | Status |
|---|---|---|---|
| Config | `/etc/alderpointdns/alderpointdns.yaml` | Operator desired-state: listeners, upstream strategy, analytics policy, feature toggles | Schema + atomic-write implemented (`app/v2/config.py`), not wired to live path |
| Control | `/var/lib/alderpointdns/control.db` | Admins, sessions, audit log, clients/identifiers/groups, policies, job history, replication metadata, migration state, notification-provider metadata + secret references (never secret values) | Schema-versioned SQLite WAL prototype implemented (`app/v2/control_db.py`), not wired to live path |
| Raw analytics | `/var/lib/alderpointdns/analytics/queries/YYYY/MM/DD/HH-<segment>.parquet` | Raw per-query history | **Decided: Parquet + Zstd + DuckDB** (see benchmark-results.md; Zstd default corrected to level 6, see remediation section) |
| Aggregate analytics | small dedicated SQLite WAL db (path TBD, sibling to control.db, e.g. `/var/lib/alderpointdns/analytics/aggregates.db`) | Minute/hour/day rollup counters | **Decided: dedicated SQLite WAL**, separate file from control.db |
| Secrets | `/etc/alderpointdns/` root-owned dedicated files (existing v1 pattern) | TLS keys, API creds; notification-provider secret values (new, scaffold-level decision only, see remediation section) | Pattern preserved from v1. **No Argon2id pepper file** — pepper is deferred, see remediation section (this reverses this document's original recommendation) |

## Confirmed control-db schema boundary

See `app/v2/control_db.py` for the actual DDL. Enforced by test
(`tests/v2/test_control_db.py::TestNoQueryHistoryGuard`,
`TestMigrationForbiddenSchemaGuard`): no table whose name contains `query_event`, `raw_quer`, or
`query_log` may exist in control.db. This guard exists specifically so a future workstream cannot
accidentally reintroduce v1's architecture mistake (raw history sharing the control database) while
extending the schema.

**Enforcement point (fixed after Dex architecture review, see below):** the invariant is checked
inside `_run_guarded_transaction`, the single choke point both `initialize()` and
`apply_migration_in_transaction()` go through — BEGIN → check invariant on the schema as it stands
→ run the migration body → check invariant again on the actual post-execution `sqlite_master` state
→ COMMIT, with ROLLBACK on any failure at any step. Originally (Workstream 1 first pass) the guard
was only invoked post-hoc after `initialize()`'s own commit and was never called at all from
`apply_migration_in_transaction()`, so a migration could `CREATE TABLE query_events (...)`, commit
successfully, and violate the invariant with no error — Dex proved this concretely and it is fixed
as of this remediation. See `docs/v2/architecture-map.md`'s "Architecture gate remediation" section
below for the full writeup and adversarial test list.

## Confirmed config schema

See `app/v2/config.py`. `schema_version` field is mandatory and currently pinned to `1` with no
migrator registered — a real version-2 schema change needs an explicit migrator before
`schema_version: 2` will load. Atomic write is temp-file + `fsync` + `os.replace` + parent-directory
fsync, mode `0640`.

## Argon2id recommendation (evidence retained, not finalized — see Dex remediation below)

Benchmarked on this test server (4 vCPU / 3.8 GiB) via `benchmarks/v2_argon2_bench.py`:

| time_cost | memory_cost | parallelism | hash (ms) | verify (ms) |
|---|---|---|---|---|
| 2 | 19 MiB (library default) | 1 | 27.7 | 27.5 |
| 2 | 64 MiB | 2 | 60.6 | 68.8 |
| 3 | 64 MiB | 2 | 96.3 | 85.3 |
| 3 | 128 MiB | 2 | 170.9 | 174.6 |
| 4 | 128 MiB | 2 | 223.7 | 207.9 |
| 3 | 256 MiB | 4 | 201.6 | 203.0 |
| **4** | **256 MiB** | **2** | **437.4** | **456.0** (Dex independently reproduced ~443-449ms) |
| 5 | 256 MiB | 2 | 573.5 | 536.5 |

`app/v2/auth_hash.py`'s current `DEFAULT_*` constants (`time_cost=4, memory_cost=256MiB,
parallelism=2`) are **kept as the working evidence base, not declared final**. Dex's review found
this benchmark measured Argon2id in isolation (a standalone address-space-limited hash operation),
not under realistic constrained *complete-appliance* memory pressure (OS + BIND + dnsdist +
FastAPI + analytics writer + aggregate store + DuckDB all resident at once). See "V2 hardware
target profiles" below for the corrected test matrix this needs to be re-run against before it's
treated as final, and `docs/v2/handoff-workstream-2.md` for this as an explicit Workstream 2
prerequisite.

## Pepper decision: DEFERRED (Dex architecture review)

**Do not implement or default-enable an Argon2id pepper in V2 Workstream 1 or its remediation.**
This reverses this document's earlier "yes" recommendation — Dex's review is the current decision
of record.

What stays mandatory regardless of the pepper decision:

- Argon2id (not any weaker/faster hash)
- unique random salt per password (already true, library default via `argon2-cffi`)
- no plaintext/reversible password storage

What's deferred and why: a pepper is a second secret whose loss independently bricks every admin
credential, on top of whatever `control.db`/backup/restore/replication/HA guarantees V2 ends up
providing. Workstream 1 has not yet designed or proven those recovery guarantees (see the
notification-secret architecture below, which is the same class of problem — "a secret that isn't
in the ordinary backup path is a confidentiality win and an availability risk at the same time").
Committing to a pepper before that groundwork exists risks shipping a foot-gun: an admin who loses
`/etc/alderpointdns/argon2-pepper` without realizing its backup was never captured would have every
admin account permanently unrecoverable, with no way to detect the gap until the worst possible
moment (a restore).

**Revisit condition:** pepper may be reconsidered once backup/restore/replication/HA behavior can
guarantee recovery of every secret it introduces — i.e., once the same due diligence this section
originally skipped has actually been done. `app/v2/auth_hash.py`'s `pepper` parameter is left in
place (it's harmless, optional, defaults to `None`) so that groundwork doesn't require an API
change later, but nothing calls it with a non-`None` value and no pepper file is created by any
code in this repository.

## V2 hardware target profiles (Dex architecture review)

The historical V1 public documentation lists 512 MiB as minimum test hardware. **That is not the
V2 engineering target.** Recorded profiles for V2 engineering purposes (private decision — the
public hardware requirements are unchanged until real runtime benchmarks justify updating them):

| Profile | Status |
|---|---|
| 512 MiB | Unsupported stress/torture profile only — not a V2 target |
| 1 GiB | Candidate minimum, to be tested |
| 2 GiB | Expected supported minimum, if 1 GiB doesn't retain comfortable operational headroom |
| 4 GiB | Recommended/reference profile |

The final supported V2 minimum must be set from full-runtime measurements — OS overhead, BIND,
dnsdist, FastAPI/Python, analytics writer, aggregate store, DuckDB queries, Argon2id, updates/
migrations, realistic DNS traffic, and memory spikes all resident together, not any one component
benchmarked alone. If 1 GiB operates comfortably under that full workload it may become the
minimum; if it only "technically works" while swapping/thrashing with no headroom, 2 GiB becomes
the minimum instead. This is a Workstream 2 prerequisite (see `docs/v2/handoff-workstream-2.md`) —
V2 features and Argon2id parameters must not be crippled merely to preserve the old 512 MiB V1
number, and this workstream does not change the public-facing hardware requirements.

## Notification secret architecture (frozen decision, Dex-confirmed)

`notification_providers.secret` (v1: webhook tokens/API keys for notification delivery, see
`docs/v2/storage-audit.md`) may **not** move into operator-readable YAML, and may not sit as
ordinary plaintext in control.db either — both were flagged as open gaps in the original Workstream
1 audit; Dex confirmed the gap and required the decision be frozen now rather than left for
Workstream 2 to reinvent.

**Frozen split:**

- **control.db** (`notification_providers` table, unchanged shape from the audit): provider
  metadata (kind, name, enabled, config_json, test-result bookkeeping) **plus a secret
  reference/key identifier only** — never the secret value itself.
- **Dedicated root-controlled secret storage** (exact mechanism not designed in this remediation —
  scaffold-level decision only): holds the actual secret value, keyed by the reference stored in
  control.db.

**Future requirements for whoever implements the secret store (Workstream 2+):**

- encrypted, or otherwise appropriately protected, at rest
- least-privilege access (not readable by the same principal that can read arbitrary control.db
  rows over the admin API, if that's a meaningfully different privilege boundary once designed)
- backed up only through the protected/encrypted secret-backup path — never swept up incidentally
  by a plain control.db copy
- restore-to-new-appliance support explicitly designed, not assumed
- replication semantics explicitly designed (replicating a secret store is a different problem than
  replicating ordinary control-plane rows)

This remediation does **not** implement the secret subsystem — no new table, no new file format, no
code. The point of this section is that Workstream 2 has one frozen shape to build against instead
of inventing its own on the day it gets there.

## Failure domains

See `docs/v2/failure-domains.md` for the full contract. Summary: DNS answering never depends on a
live control.db/analytics lookup per query (already true in v1.1.1, frozen as an invariant for V2);
analytics ingestion is asynchronous with a bounded queue and explicit oldest-first drop on overflow
(`app/v2/analytics_ingest.py::BoundedQueue`); segment writes use temp-name-then-atomic-rename so a
reader can never observe partial history (`app/v2/analytics_ingest.py::SegmentWriter`,
`ParquetDuckDbBackend.ingest`); host DNS independence is unchanged from v1.1.1.

## DNS cache architecture: RAM-first, effective cache profile, Tier A/B recovery (owner-locked)

Owner-approved V2 architectural requirement, locked alongside this commit. Copied into the public
roadmap (`docs/v2-architecture-plan.md` §3.6, `docs/v2-adguard-parity-matrix.md` "Alderpoint beyond
parity") at summary level; this section is the fuller engineering detail for Workstream 2.

**Implementation status (Gate #3 architecture correction, post-RC30):** a Gate #3 review found this
locked hot path had never actually been implemented -- V2 forwarded straight from dnsdist to public
upstreams, with no BIND tier, from inception through RC30. Investigated and confirmed as real
implementation drift, not a later superseding architecture decision (no document or commit ever
descoped BIND; every workstream handoff treated a full BIND build-out as a tracked, budget-deferred
gap, never a removed requirement -- see `docs/v2/build-reproducibility-fix.md`'s sibling
investigation for the Gate #3 process and `docs/v2/bind-backend-v2.md` for the fix). RC31 implements
the real tier: `app/v2/bind_gen.py` (isolated V2 `named.conf` generation/validation), a packaged
`alderpointdns-v2-bind.service`, and `app/v2/dnsdist_policy_runtime.py`/`app/v2/runtime_compile.py`
routing ordinary (plain-transport, non-ECS, default-upstream) recursive traffic through it. See
`docs/v2/bind-backend-v2.md` for the full design, scope, and known bounded follow-ups (per-profile
BIND view differentiation, DoT/DoH forwarding through BIND).

**RAM-first hot path.** Client -> dnsdist RAM packet cache -> compiled runtime policy/routing ->
BIND RAM recursive cache -> upstream only on miss. The DNS lookup/cache hot path must never
synchronously depend on disk, SQLite, control.db, the aggregate store, DuckDB, Parquet, FastAPI, the
web UI, or the analytics/audit subsystems. DNS cache latency takes precedence over analytics
convenience.

**Effective cache profile — first-class compiled concept.** Cached answers may only be shared
between clients when the properties that can affect the returned answer are compatible: filtering
policy, SafeSearch, parental controls, service blocking, blocking response mode, upstream/routing
profile, fallback/strategy behavior, ECS state, domain-routing rules, and any other answer-producing
policy. Do not create one cache per individual client (wasteful); do not use one unrestricted global
cache when policy differences could produce different answers (incorrect). Clients with equivalent
answer-producing policy share one profile's cache. Must be compiled, deterministic, cheap to
evaluate, and independent of per-query database lookups — this is a runtime-policy-compiler concern,
not a database lookup.

**Tier A — safe direct restore (optional).** May directly restore a cached answer after restart only
when provably correct: absolute expiration time, remaining (not original) TTL, DNSSEC validity/
state, effective cache-profile generation, resolver/upstream context, domain-routing context, ECS
context where applicable, negative-caching semantics, and any other validity-affecting metadata. A
reboot must never reset an entry's original TTL — an entry with 300s original and 40s remaining at
reboot may be restored with at most ~40s remaining. If validity is uncertain, do not directly
restore it; fall through to Tier B or normal cold resolution. Tier A is optional for eventual
production — if its complexity/security/correctness risk outweighs measured benefit, V2 may ship
Tier B alone.

**Tier B — popularity-based prewarm.** Persists a bounded recent/popular DNS working-set index (name
identity/popularity, not trusted old answers). After DNS services are available: select recently/
frequently used names, resolve them through the normal Alderpoint path, obtain fresh TTLs, perform
normal DNSSEC validation, apply current policy/profile behavior, populate RAM caches naturally.
Asynchronous, background, rate-limited, bounded, non-blocking, safe after unclean power loss.

**Persistent warm-state storage.** A separate bounded subsystem — not Parquet query history, not
DuckDB, not control.db raw analytics, not management UI state. Conceptually
`/var/lib/alderpointdns/cache/` (exact format/path to be benchmarked in Workstream 2). Requirements:
bounded size, asynchronous updates, coalesced/batched persistence, no per-query fsync, no synchronous
hot-path disk dependency, atomic/last-known-good snapshots where practical, corruption detection,
safe cleanup, disposable/non-authoritative. Missing/stale/corrupt/incompatible state must simply
fall back to a normal cold cache with no effect on DNS functionality.

**Power-loss behavior.** Design for abrupt power loss, not just graceful shutdown. Periodic
asynchronous persistence during normal operation should mean a crash loses only the last several
seconds/minutes of warm-state metadata, never DNS correctness.

**Startup order.** DNS availability comes first: dnsdist/BIND become operational and clients can
resolve immediately; cache recovery/prewarm begins in the background afterward. Never a "restoring
cache, please wait" gate before DNS is usable. Tier A restore (if implemented) must not make startup
fragile; Tier B always runs after DNS is already available.

**Cache failure domain.** Persistent cache state is explicitly non-authoritative. Failure of the
warm-index storage, Tier A state, Tier B state, the cache recovery worker, or the disk cache
subsystem must degrade only to a cold cache — never a DNS outage, service startup failure,
management-DB failure, or analytics-failure propagation. Consistent with the existing failure-domain
contract in `docs/v2/failure-domains.md`.

**Memory priority.** DNS cache is a latency-critical first-class RAM resource. Analytics/query
operations must not casually starve it. Workstream 2+ should establish bounded memory budgeting
between dnsdist's packet cache, BIND's recursive cache, FastAPI, the analytics writer, DuckDB, the
aggregate store, Argon2id's transient use, and OS/filesystem cache. Under memory pressure, optional
analytics performance should degrade before DNS reliability/latency wherever reasonably possible. No
hard-coded final cache sizes yet — benchmark them (see gate below).

**Cache recovery benchmark gate (Workstream 2+ acceptance criteria).** Simulate abrupt power loss/
restart and compare (A) pure cold cache, (B) Tier B popularity prewarm, (C) Tier A+B hybrid if Tier A
is proven safe enough to implement. Measure: time until DNS is available; cache-hit latency p50/p95/
p99; upstream query count/volume; CPU/RAM/disk-write overhead; recovery/prewarm network activity;
time to reach ~50%/90%/99% of prior working-set effectiveness. Use realistic repeated-client/domain
distributions — random synthetic names can't benefit meaningfully from cache reuse and would
understate the benefit.

## Open items / conflicts between docs and implementation evidence

None found that require overriding the roadmap. One clarification worth recording: the roadmap
doesn't specify the aggregate store's exact file path — `architecture-plan.md` §3.5 lists it as "a
small dedicated `analytics.db`" without pinning a path the way it does for `control.db` and the raw
Parquet directory. This document proposes
`/var/lib/alderpointdns/analytics/aggregates.db` as a sibling of the raw-history directory; not
yet implemented, flagged for Workstream 2 to confirm or adjust.

## Architecture gate remediation (Dex review)

Dex independently reviewed branch `v2/architecture-storage-foundation` @ `eec4198` and returned
**ARCHITECTURE NOT READY** on one release-gate-level blocker, plus several smaller confirmed
decisions. This section is the record of that review and what changed as a result; treat it as the
most current statement wherever it overlaps with earlier sections of this document.

**Blocker (fixed): control.db migration invariant not enforced.** `apply_migration_in_transaction()`
could execute arbitrary migration SQL, commit successfully, and never check the forbidden-table
invariant — Dex proved this concretely by having a migration `CREATE TABLE query_events (...)` and
watching it commit. Root cause: the guard (`_assert_no_forbidden_tables`) was only ever called from
`initialize()`, and even there it ran *after* that function's own commit, not inside the
transaction. Fix: both `initialize()` and `apply_migration_in_transaction()` now route through a
single `_run_guarded_transaction()` choke point (`app/v2/control_db.py`) that checks the invariant
against the live `sqlite_master` schema both before and after the migration body executes, all
inside one open transaction, rolling back completely on any violation — pre-existing or newly
introduced, by CREATE, ALTER...RENAME, or any other DDL. Proven by eight adversarial tests
(`tests/v2/test_control_db.py::TestMigrationForbiddenSchemaGuard`, cases A-H): normal migration
commits; CREATE of a forbidden table rolls back completely; an allowed mutation immediately
followed by a forbidden CREATE in the same migration rolls back *both*, not just the forbidden one;
RENAME-into-forbidden-name is caught (proving the guard isn't a text search over migration SQL, it
re-reads the actual schema); a failed-SQL migration rolls back with schema version unchanged; a
database that already has a forbidden table refuses any further migration, including otherwise-
valid statements in the same call; `initialize()` independently refuses a forbidden schema; and
control tables with incidentally query-like names (`saved_queries`, `statistics_settings`) are
correctly *not* flagged, proving the fix didn't turn into an over-broad name-fragment ban.

**Confirmed without change:** overall V2 architecture direction; Parquet+Zstd+DuckDB as the raw-
history technology (Dex independently reproduced comparable throughput/disk numbers at 100k rows,
see `docs/v2/benchmark-results.md`); SQLite WAL rejected for raw history, kept for the aggregate
store; config prototype (`app/v2/config.py`) directionally safe (safe_load, schema validation, temp
file + fsync + replace + directory fsync, mode 0640).

**Changed by this review:** pepper deferred (was "yes", now "no, not in V2 Workstream 1" — see
above); hardware target profiles corrected away from the historical 512 MiB V1 minimum (see above);
notification-secret architecture frozen as control.db-holds-reference /
dedicated-store-holds-value (was an open gap, now a scaffold-level decision, see above); Parquet
Zstd default corrected from level 9 to level 6 (see `docs/v2/benchmark-results.md` "Zstd default
correction"); benchmark harness peak-RSS measurement fixed to be per-backend rather than
process-cumulative (see `docs/v2/benchmark-results.md` "Benchmark harness memory isolation fix").

**New Workstream 2 gates** (full detail in `docs/v2/handoff-workstream-2.md`): prove partition
pruning actually limits Parquet file scans for time-bounded queries (not just that the flat-file
benchmark was fast); durable (not memory-only) migration state with crash/reboot restart and
idempotent stage continuation; config file ownership/group/parent-directory hardening and symlink
rejection policy; a safe V1 performance baseline before any runtime-behavior-changing work begins;
Argon2id re-benchmarked under realistic full-appliance memory pressure at the corrected 1/2/4 GiB
profiles, not as a standalone hash in isolation.

**Explicitly not this workstream's problem:** Dex reproduced a combined-test-suite hang (the same
one this session's own regression run hit and worked around by running files individually) even
with `tests/v2/` excluded — evidence points to a pre-existing V1 test-order/global-state/AnyIO-portal
issue, not anything V2 introduced. Recorded as technical debt to resolve before release-quality V2
CI, not addressed in this remediation.
