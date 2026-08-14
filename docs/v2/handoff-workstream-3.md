# V2 Workstream 3 — Handoff

**Status:** Handoff from Workstream 2 (`v2/architecture-storage-foundation` branch), which turned
the Dex-verified Workstream 1 architecture into real, production-shaped (but not live-wired)
implementations. Nothing in `app/v2/` is called by the running v1.1.1 service — every module here
is additive, tested only against disposable tempdir/dev paths. See
`docs/v2/handoff-workstream-2.md` for the original gate list (1-13) this workstream was scoped
against; this document records what got addressed, what's still a prototype, and what Workstream 3
should do next.

## What Workstream 2 delivered

| Area | Module | Status |
|---|---|---|
| Real Parquet writer | `app/v2/parquet_writer.py` | Batched, `YYYY/MM/DD/HH-<segment>.parquet` partitioned, Zstd level 6, atomic temp->final promotion, schema+row-count validation before promotion, restart-safe segment-index seeding (no filename collision across process restarts), never raises into caller. 13 tests. |
| Partition-pruning DuckDB reader | `app/v2/analytics_query.py` | Gate 1 (Dex's outstanding item) — proven, not assumed: `enumerate_partition_files` prunes at the directory-name level before DuckDB ever opens a file; `test_last_hour_query_prunes_to_relevant_partitions_only` proves an 11-day, 11-segment tree scans ≤2 files for a "last hour" query. Query helpers are parameterized (bound params, allowlisted filter columns) — SQL-injection-safe. 10 tests. |
| Real retention | `app/v2/retention.py` | Age-based and size-cap deletion, oldest-first, `protect_most_recent` defense in depth, never touches temp files (by glob construction), errors recorded not raised. 8 tests. |
| Aggregate SQLite WAL runtime | `app/v2/aggregates_db.py` | Own file, own WAL/busy_timeout, bounded time-bucket + dimension-count schema, transactional rollup, rebuildable from raw Parquet via the pruning reader, proven isolated from control.db (corrupting one doesn't touch the other). 9 tests. |
| Analytics failure isolation | `tests/v2/test_analytics_failure_isolation.py` | Disk-full, read-only directory, all-corrupt-directory, aggregate-DB-locked/corrupt, bounded-queue overflow, worker-restart-without-collision — all proven non-fatal to the caller. 8 tests. |
| Config filesystem hardening | `app/v2/config.py` additions | Symlink rejection (`load_file`/`atomic_write`, `O_NOFOLLOW` defense in depth), `harden_parent_directory`/`verify_ownership` (root:alderpointdns contract, best-effort chown), unknown-key rejection already existed and is now explicitly tested. 12 new tests (29 total in the config test files). |
| Secret store foundation | `app/v2/secret_store.py` | File-per-secret under a `0700` directory, `0600` files, stable validated IDs (path-traversal-proof allowlist pattern), symlink-refusing CRUD, `export_all`/`import_all` backup/restore hooks (plaintext by design — caller's job to encrypt). 25 tests. |
| Durable migration state | `app/v2/migration_state.py` + `app/v2/migration.py` changes | Atomically-persisted `MigrationRecord` (JSON, same temp+fsync+replace pattern as config), persisted after every stage attempt including the very first (so even a crash before stage 1 completes is resumable), crash-injection-tested at **every** stage boundary in `mig.STAGES` via `test_crash_restart_at_every_stage_boundary`, idempotent resume proven (no stage re-executes), source never mutated at any restart point. 21 tests. |
| Effective cache profile | `app/v2/cache_profile.py` | Deterministic SHA-256-based profile ID from a fixed answer-affecting dimension set; structurally cannot be influenced by non-answer-affecting metadata (those fields don't exist on the dataclass); `CacheProfileRegistry` proves many-clients/few-profiles dedup. 15 tests. |
| Tier B prewarm | `app/v2/tier_b_prewarm.py` | Bounded (`WorkingSetIndex`, eviction by recency-decayed popularity), coalesced snapshot persistence (no per-query I/O — verified structurally), corrupted/truncated/missing snapshot all degrade to a fresh empty index (never raise), rate-limited/bounded/pressure-aware `run_prewarm` replay loop. 21 tests. |
| Tier A feasibility | `app/v2/tier_a_feasibility.py` + `docs/v2/tier-a-feasibility.md` | Correctness proven (TTL-never-resets structural guarantee, DNSSEC/context validity all independently checked, negative caching covered, fail-closed on uncertainty) — 16 tests. **Recommendation: defer, ship Tier B only** — see the doc for why (unmeasured benefit, added hot-path metadata-capture complexity, DNSSEC-classification risk). |
| V1 performance baseline | `docs/v2/v1-performance-baseline.md` | Real, bounded, local-only measurement against the live appliance: DNS cached/uncached latency percentiles, single-process QPS floor, per-service RSS, `query_events` query latency, storage sizes. |
| Hardware/memory evidence | `docs/v2/hardware-memory-profile-results.md` | Real cgroup-constrained (`systemd-run --scope -p MemoryMax=`) Argon2id measurements closing the "untested under memory pressure" gap for that one component; combined with the V1 RSS baseline into an evidence-based (not final) 2 GiB recommended-minimum call, with 1 GiB flagged candidate-only pending the full concurrent test below. |

**Test totals:** `tests/v2/` grew from 70 (post-Workstream-1-remediation) to **218** (148 new,
all passing). V1 regression subset (8 files, 279 tests, same files exercised in the prior
remediation) still green.

## Gates from `docs/v2/handoff-workstream-2.md` — current status

1. **Partition pruning** — ✅ proven (see table above). Reader is real; not yet wired to a live
   ingestion path.
2. **Durable migration state** — ✅ delivered. Real stages (`migrate_config`, `migrate_control`,
   etc.) are still stubs per the original Workstream 1 scope decision — durability is proven for the
   state machine itself, not for real per-stage migration logic, which Workstream 3 still needs to
   write.
3. **Config filesystem hardening** — ✅ delivered (symlink policy, ownership contract, parent-dir
   mode). Not yet applied to a real `/etc/alderpointdns/alderpointdns.yaml` deployment — this
   workstream only hardened the module, not an actual deployed file.
4. **V1 performance baseline** — ✅ delivered, see table above.
5. **Argon2id full-appliance memory testing** — 🟡 partial. Real cgroup-constrained evidence exists
   for Argon2id alone; the full BIND+dnsdist+web+analytics+DuckDB+Argon2id concurrent test under a
   memory cap was not run this session (see `docs/v2/hardware-memory-profile-results.md` "What this
   session did NOT do" for the explicit gap list) — carried forward as a Workstream 3 prerequisite.
6. **Notification secret subsystem** — ✅ foundation delivered (`app/v2/secret_store.py`). Not yet
   wired to actual notification-provider CRUD flows or a real backup/replication pipeline — those
   still need building.
7. **Pepper stays deferred** — ✅ still true, unchanged. `secret_store.py` is generic and could
   technically hold one, but nothing calls it that way.
8. **Test-suite shared-state hang** — unchanged pre-existing V1 debt, not touched this workstream
   either (per repeated explicit instruction not to burn a session on it without direct evidence V2
   worsens it).
9-13 (cache profile / Tier A-B / cache invariants / memory budget / cache-recovery benchmark) — see
below, this workstream's main net-new area.

## Mandatory Workstream 3 gates (do not skip)

1. **Full concurrent-everything memory test.** BIND + dnsdist + the real (not stub) V2
   analytics/DuckDB stack + Argon2id, all resident and under synthetic load simultaneously, at the 1
   GiB / 2 GiB / 4 GiB profiles, to actually confirm or revise the 2 GiB recommended-minimum call in
   `docs/v2/hardware-memory-profile-results.md`. This requires either a second constrained
   environment or a maintenance-window test against a non-live appliance — do not attempt against
   the live v1.1.1 test host without an explicit new authorization, since it risks resource
   contention with the real service.
2. **Wire the real Parquet writer into the analytics ingestion path**, replacing
   `app/v2/analytics_ingest.py`'s JSONL stub, including the pruning reader from gate 1 above serving
   real query-log/dashboard requests.
3. **Real per-stage migration logic** (`migrate_config`, `migrate_control`, `migrate_clients`,
   `migrate_policies`, `migrate_secrets`, `migrate_analytics`, `generate_runtime_config`, `validate`,
   `health_check`), built on the now-durable state machine, following the table-by-table map in
   `docs/v2/storage-audit.md`.
4. **Wire effective cache profiles into a real policy compiler** — `app/v2/cache_profile.py` is a
   pure, tested compiler with no caller yet; Workstream 3 needs the actual policy-to-dimensions
   mapping (reading `control_db.py`'s `policies`/`clients`/`client_groups` tables) that produces a
   `CachePolicyDimensions` instance per client.
5. **Wire Tier B into a real background worker** — `run_prewarm`'s `resolve_fn` needs a real
   implementation calling into the actual DNS resolution path (once one exists to call).
6. **Run the cache-recovery benchmark gate** (cold vs. Tier B vs. Tier A+B, if Tier A's
   recommendation is revisited) — cannot happen until a real cache implementation exists to
   benchmark; this is likely a Workstream 4+ item depending on how fast policy engine + cache
   wiring lands.
7. **Notification-provider CRUD + real backup/replication pipeline** built on
   `app/v2/secret_store.py`'s foundation.
8. **Config file real deployment**: apply `harden_parent_directory`/`verify_ownership` to an actual
   `/etc/alderpointdns/alderpointdns.yaml` path as part of wiring the config schema into the running
   app, including the root-helper ownership contract this module assumes but doesn't itself enforce
   end-to-end.
9. Carry forward unchanged from Workstream 2: pepper deferred, test-suite hang is pre-existing V1
   debt.

## Known open risks to carry forward

- 2 GiB hardware minimum recommendation is evidence-based but not final — gate 1 above is the
  confirming (or revising) test.
- Migration stage logic is still entirely stub — durability was the Workstream 2 deliverable, not
  correctness of the stages themselves.
- Tier A deferred by recommendation, not forced — revisit only if the cache-recovery benchmark
  (once runnable) shows Tier B alone is materially insufficient.
- `app/v2/parquet_writer.py`'s segment-index restart-seeding scans the partition directory on first
  write per process — fine at realistic per-hour segment counts, not benchmarked at pathological
  segment-count-per-directory scale.
- Aggregate store rebuild (`aggregates_db.rebuild_range_from_reader`) is a recompute, not a merge —
  a caller doing a true rebuild must clear the target bucket range first or accept double-counting;
  documented in the function's docstring, not yet enforced by an API guard.
