# V2 Workstream 2 — Delivered Scope + Original Handoff (historical)

**Status: Workstream 2 is now complete.** This document originally shipped as the Workstream 1 ->
Workstream 2 handoff (recommended scope, gates 1-13). That content is kept below as the historical
record of what was asked for. **See `docs/v2/handoff-workstream-3.md` for the current, forward-
looking handoff** — what Workstream 2 actually delivered, what's still a prototype vs. real-wired,
and the recommended Workstream 3 scope. The gates below are cross-referenced from there as
addressed/still-open rather than repeated.

**Original status note (Workstream 1 -> 2 handoff):** Handoff from Workstream 1
(`v2/architecture-storage-foundation` branch, started at `381851f91fa75cb4274d10450383cb9f024e4b61`),
amended after the Dex architecture gate review and its remediation (branch reviewed at `eec4198`,
remediation on top of it — see `docs/v2/architecture-map.md` "Architecture gate remediation" for the
full writeup), and further amended after Dex Gate #1 passed ("ALDERPOINT DNS V2 WORKSTREAM 1
ARCHITECTURE VERIFIED AND READY FOR WORKSTREAM 2") with an architecture-lock-in documentation commit
adding the RAM-first DNS cache / effective cache profile / Tier A-B recovery requirement (gates
9-13 below).

## What Workstream 1 + remediation delivered (don't redo this)

- Branch `v2/architecture-storage-foundation`, roadmap docs copied into `docs/v2/roadmap-reference/`
- `docs/v2/storage-audit.md` — full v1 table -> V2 storage classification
- `docs/v2/failure-domains.md` — frozen failure-domain contract
- `app/v2/config.py` — YAML desired-state schema + atomic write (schema only, not wired to live path)
- `app/v2/control_db.py` — control.db schema prototype + migration-transaction primitives, **with
  the forbidden-raw-history-table invariant now enforced inside the transaction itself** (both
  `initialize()` and `apply_migration_in_transaction()` route through `_run_guarded_transaction()`,
  which checks the invariant against the live `sqlite_master` schema before and after the migration
  body runs, all inside one open transaction) — this was the Dex-identified release-gate blocker,
  fixed and proven with 8 adversarial tests (`TestMigrationForbiddenSchemaGuard`, cases A-H)
- `app/v2/auth_hash.py` — Argon2id wrapper, benchmark evidence retained
  (`time_cost=4, memory_cost=256MiB, parallelism=2`, **not yet finalized** — see gate below), pepper
  plumbing present but **not enabled by default and not to be enabled without further review** (see
  gate below)
- `app/v2/analytics_ingest.py` — bounded queue + segment rotation + atomic promotion prototype
- `benchmarks/v2_analytics/` — reusable benchmark harness + results; **decision: Parquet+Zstd+DuckDB
  for raw history, dedicated SQLite WAL for aggregates** (Dex-confirmed independently); Zstd default
  corrected to level 6; per-backend memory measurement now subprocess-isolated
- `app/v2/migration.py` — pipeline state machine scaffold (stages mostly stubbed; state machine
  itself is real and tested); **durable state is a gate below, current implementation is
  memory-only**
- `docs/v2/architecture-map.md` — frozen decisions for notification-secret storage split
  (control.db holds metadata + reference only, dedicated store holds the value) and V2 hardware
  target profiles (512MiB unsupported / 1GiB candidate / 2GiB expected / 4GiB recommended,
  replacing the historical V1 512MiB minimum as the V2 engineering target — public docs unchanged)
- Test suites (post-remediation totals): `tests/v2/test_config_schema.py` (17),
  `tests/v2/test_control_db.py` (16, was 8 — +8 adversarial guard tests),
  `tests/v2/test_argon2.py` (13), `tests/v2/test_analytics_prototype.py` (14),
  `tests/v2/test_migration_scaffold.py` (10) — see final report for pass/fail status.

## Mandatory Workstream 2 gates (from the Dex review — do not skip)

These are prerequisites, not nice-to-haves. Each one exists because Workstream 1's prototypes prove
a shape works in isolation, not that it's safe to run for real.

1. **Parquet partition pruning must be proven, not assumed.** The Workstream 1 benchmark used flat
   per-batch segment files in one directory to isolate storage-format comparison from directory
   layout — it says nothing about whether a "last hour" query against the real
   `YYYY/MM/DD/HH-<segment>.parquet` layout actually skips historical partitions rather than
   scanning every file. Workstream 2 must ship a reader (Hive-style partition pruning, row-group
   statistics pruning, or both) and a test proving a bounded recent-time-range query touches only
   the relevant partition files. This is a mandatory acceptance test, not optional polish.
2. **Migration state must become durable before runtime wiring.** `app/v2/migration.py`'s
   `MigrationState` is in-memory only — fine for Workstream 1's state-machine scaffolding, not
   acceptable once migration can actually run against a real installation. Required before runtime
   migration wiring: durable stage state (survives process restart), crash/reboot restart,
   idempotent stage continuation from durable state (not just from an in-memory object a caller
   happens to still hold), backup integrity verification as an explicit stage, generated-DNS-config
   validation before commit, a late commit point (already designed — `commit` is the last stage —
   but must stay late as real stages replace stubs), and confirmation that the V1 source stays
   untouched through `preview` with the real (not stub) `preview` logic.
3. **Config filesystem hardening.** `app/v2/config.py` is directionally safe (`yaml.safe_load`,
   schema validation, temp file + fsync + `os.replace` + parent-directory fsync, mode `0640`) but
   before real runtime wiring, Workstream 2 must add: an explicit root/helper ownership contract
   (who writes this file, under what UID), an explicit group-ownership contract (matching the
   existing `/etc/alderpointdns` convention), hardened parent-directory permissions, and a defined
   symlink policy for `load_file()` — it currently follows symlinks with no special handling, which
   is fine for a prototype reading a path only Workstream 1's own code chose, not fine once
   `/etc/alderpointdns/alderpointdns.yaml` is a real path other privileged code opens.
4. **A safe V1 performance baseline is a prerequisite, not a nice-to-have**, before Workstream 2
   changes any authoritative runtime behavior. `docs/performance-baseline.md` (existing v1 doc) does
   not cover enough — capture, without disruptive stress against the live test appliance: DNS
   latency, approximate QPS, CPU, RAM, analytics overhead, query-log latency, DB/storage size. This
   gives Workstream 2 something concrete to avoid regressing.
5. **Argon2id parameters are not finalized.** Current evidence (`time_cost=4, memory_cost=256MiB,
   parallelism=2`, ~440-460ms, Dex independently reproduced ~443-449ms) was measured as a standalone
   hash operation, not under realistic full-appliance memory pressure. Workstream 2 must re-test
   against the corrected hardware profiles (1 GiB candidate minimum, 2 GiB expected supported
   minimum, 4 GiB recommended — see `docs/v2/architecture-map.md`) with the *complete* runtime
   resident (OS + BIND + dnsdist + FastAPI + analytics writer + aggregate store + DuckDB queries +
   updates/migrations + realistic DNS traffic + memory spikes), not Argon2id in isolation. Do not
   optimize defaults around the old 512MiB V1 minimum.
6. **Notification secret subsystem is a frozen shape, not a built system.** `docs/v2/architecture-
   map.md` freezes control.db-holds-reference / dedicated-store-holds-value, but no code exists yet.
   Workstream 2 (or later) must actually build the dedicated secret store: encrypted-at-rest,
   least-privilege access, its own backup path (not swept up by an ordinary control.db copy),
   restore-to-new-appliance support, and explicitly designed replication semantics.
7. **Pepper stays deferred.** Do not enable `app/v2/auth_hash.py`'s `pepper` parameter by default or
   create a pepper file anywhere. Revisit only once backup/restore/replication/HA recovery
   guarantees exist for every secret V2 introduces — which is downstream of gate 6 above, not
   independent of it.
8. **Test-suite shared-state hang is pre-existing V1 technical debt**, not a Workstream 1/2
   architecture blocker. Dex reproduced a combined-pytest-suite hang even with `tests/v2/` excluded
   (evidence: first V1 `TestClient` request in a combined run hangs, same test passes standalone,
   AnyIO portal/event loop idle — a test-order/global-state/runner issue). Resolve before
   release-quality V2 CI depends on a single combined test run, but do not let it block Workstream 2
   feature work; per-file test execution (as this workstream's regression checks used) is an
   acceptable interim workaround.
9. **Effective cache profile must become a first-class compiled runtime concept** before any DNS
   cache-sharing logic ships. See `docs/v2/architecture-map.md` "DNS cache architecture" for the
   full requirement — clients may only share a cached answer when their filtering/SafeSearch/
   parental/service-blocking/blocking-response-mode/upstream-routing/ECS/domain-routing state is
   equivalent. Do not ship one client-per-cache design or one unrestricted global cache; either is a
   correctness or resource-efficiency defect, not a style choice.
10. **Cache persistence (Tier A/Tier B) is a new subsystem, not built code.** Same status as the
    notification secret store (gate 6): the architecture is frozen (`docs/v2/architecture-map.md`),
    nothing exists yet. Tier B (popularity-based prewarm, always re-resolving through the normal
    path for fresh TTL/DNSSEC/policy) is the baseline; Tier A (direct restore of provably-still-valid
    entries) is optional and may be dropped if its risk outweighs measured benefit. Persistent
    warm-state storage must be its own bounded subsystem (proposed
    `/var/lib/alderpointdns/cache/`), never Parquet/DuckDB/control.db/UI state repurposed for this.
11. **Cache failure/startup invariants must hold from the first implementation, not be bolted on
    later:** DNS availability at boot never waits on cache recovery/prewarm; failure of any
    persistence-tier component degrades only to a cold cache, never to a DNS outage or failure
    propagating into control.db/analytics; design for abrupt power loss specifically (periodic
    async persistence, not graceful-shutdown-only capture).
12. **DNS cache memory-budget benchmark is required before finalizing cache sizes.** Establish
    bounded memory budgeting between dnsdist's packet cache, BIND's recursive cache, FastAPI, the
    analytics writer, DuckDB, the aggregate store, Argon2id transient use, and OS/filesystem cache —
    do not hard-code final sizes without measuring the full appliance under load first (ties into
    gate 4's V1 baseline and gate 5's full-appliance Argon2id retest).
13. **Cache-recovery benchmark gate** (acceptance criteria, not optional polish): simulate abrupt
    power loss/restart and compare cold cache vs. Tier B prewarm vs. Tier A+B hybrid (if Tier A is
    implemented) on time-to-DNS-available, cache-hit latency p50/p95/p99, upstream query volume,
    CPU/RAM/disk overhead, and time to ~50%/90%/99% of prior working-set effectiveness, using
    realistic repeated-client/domain traffic rather than random synthetic names.

## Recommended Workstream 2 scope (after the gates above)

Per the original brief's explicit non-goals for Workstream 1 (§18) and the roadmap's Day 2-3 target
("Storage/failure-domain redesign... implement winning analytics storage approach"), Workstream 2
should, once the gates above are satisfied:

1. **Wire the config/control-db/analytics prototypes into the real runtime**, replacing v1's
   monolithic `alderpointdns.db` per the storage-audit map — nothing in `app/*.py` (the live v1
   modules) has been touched by Workstream 1 or this remediation.
2. **Implement the Parquet raw-history writer for real** against the analytics ingestion queue,
   replacing the stub in `app/v2/analytics_ingest.py`'s `SegmentWriter` (currently JSONL, chosen for
   zero extra deps in the prototype) with the benchmarked Parquet+Zstd+DuckDB path, including the
   partitioned layout and the pruning-proof reader from gate 1.
3. **Implement the aggregate SQLite store** (`analytics/aggregates.db`, path proposed in
   `docs/v2/architecture-map.md`, not yet built) and its rollup-writer.
4. **Begin the unified policy engine** (roadmap §4) using `control_db.py`'s `policies` table as the
   starting schema — the precedence model (global -> network -> group -> client -> emergency) is
   documented in the roadmap but not implemented anywhere yet.
5. **Real `migrate_config`/`migrate_control`/`migrate_clients`/`migrate_secrets` stage logic** in
   `app/v2/migration.py`, replacing the stubs, following the storage-audit table-by-table map, built
   on the durable state machine from gate 2.
6. Do **not** yet build: SafeSearch, parental controls, service blocking/schedules, per-client
   upstreams, domain routing, fallback DNS, upstream strategies, ECS, native HTTPS UI — those stay
   deferred per the roadmap's Day 4-8 sequencing, after the storage foundation is actually load-
   bearing, not just prototyped.

## Known open risks to carry forward

- Argon2id parameters unverified under realistic constrained full-appliance memory pressure (gate 5).
- Notification secret subsystem is a frozen design, not built code (gate 6).
- Pepper deferred pending gate 6/backup-recovery guarantees (gate 7).
- Aggregate store path (`analytics/aggregates.db`) is a Workstream 1 proposal, not roadmap-pinned —
  confirm with the roadmap owner or just proceed with it; low risk either way since it's an isolated
  new path.
- Parquet row-group-size (50,000, still provisional — 10k/50k/100k were indistinguishable at
  benchmark scale) and Zstd level (corrected to 6, verified against 3/9 at one dataset size only) —
  acceptable provisional defaults, revisit if real ingest/query profiles diverge materially from the
  synthetic benchmark once real traffic is flowing through it.
- Partition pruning unproven (gate 1) — treat any "Parquet is fast" claim as scoped to the flat-file
  benchmark until the pruning reader exists and is tested.
- Migration state durability unimplemented (gate 2) — do not wire real migration execution before it
  exists.
- 3M-row benchmark point did not complete in the Workstream 1 session (disk-I/O-bound on shared test
  hardware); the 100k/1M trend already supports the raw-history-backend decision and this is not
  blocking.
- DNS cache persistence (Tier A/Tier B) and the effective cache profile are frozen architecture
  decisions, not built code (gates 9-11) — same status as the notification secret store, just
  locked in later (after Dex Gate #1).
- Cache memory budgeting and the cache-recovery benchmark (gates 12-13) are unmeasured; do not
  finalize cache sizes or claim recovery-time numbers until they're run.
