# V2 Workstream 2 — Recommended Scope

**Status:** Handoff from Workstream 1 (`v2/architecture-storage-foundation` branch,
started at `381851f91fa75cb4274d10450383cb9f024e4b61`).

## What Workstream 1 delivered (don't redo this)

- Branch `v2/architecture-storage-foundation`, roadmap docs copied into `docs/v2/roadmap-reference/`
- `docs/v2/storage-audit.md` — full v1 table -> V2 storage classification
- `docs/v2/failure-domains.md` — frozen failure-domain contract
- `app/v2/config.py` — YAML desired-state schema + atomic write (schema only, not wired to live path)
- `app/v2/control_db.py` — control.db schema prototype + migration-transaction primitives (prototype
  only, not wired to live path)
- `app/v2/auth_hash.py` — Argon2id wrapper, benchmarked parameters
  (`time_cost=4, memory_cost=256MiB, parallelism=2`), pepper plumbing (not wired to real login)
- `app/v2/analytics_ingest.py` — bounded queue + segment rotation + atomic promotion prototype
- `benchmarks/v2_analytics/` — reusable benchmark harness + results; **decision: Parquet+Zstd+DuckDB
  for raw history, dedicated SQLite WAL for aggregates**
- `app/v2/migration.py` — pipeline state machine scaffold (stages mostly stubbed; state machine
  itself is real and tested)
- Test suites: `tests/v2/test_config_schema.py` (17), `tests/v2/test_control_db.py` (8),
  `tests/v2/test_argon2.py` (13), `tests/v2/test_analytics_prototype.py` (14),
  `tests/v2/test_migration_scaffold.py` (10) — see final report for pass/fail status.

## Recommended Workstream 2 scope

Per the original brief's explicit non-goals for Workstream 1 (§18) and the roadmap's Day 2-3 target
("Storage/failure-domain redesign... implement winning analytics storage approach"), Workstream 2
should:

1. **Wire the config/control-db/analytics prototypes into the real runtime**, replacing v1's
   monolithic `alderpointdns.db` per the storage-audit map — this is the actual "implement" step
   Workstream 1 deliberately deferred (Workstream 1 built and tested the primitives in isolation
   under `app/v2/`; nothing in `app/*.py` — the live v1 modules — was touched).
2. **Implement the Parquet raw-history writer for real** against the analytics ingestion queue,
   replacing the stub in `app/v2/analytics_ingest.py`'s `SegmentWriter` (currently JSONL, chosen
   for zero extra deps in the prototype) with the benchmarked Parquet+Zstd+DuckDB path, including
   the `YYYY/MM/DD/HH-<segment>.parquet` partition layout that wasn't exercised in the flat-file
   benchmark.
3. **Implement the aggregate SQLite store** (`analytics/aggregates.db`, path proposed in
   `docs/v2/architecture-map.md`, not yet built) and its rollup-writer.
4. **Resolve the two open items flagged in Workstream 1:**
   - low-end (1 vCPU / 512 MiB) Argon2id parameter re-verification (see
     `docs/v2/architecture-map.md` "Open risk")
   - `notification_providers.secret` secret-separation gap identified in `docs/v2/storage-audit.md`
5. **Begin the unified policy engine** (roadmap §4) using `control_db.py`'s `policies` table as the
   starting schema — the precedence model (global -> network -> group -> client -> emergency) is
   documented in the roadmap but not implemented anywhere yet.
6. **Real `migrate_config`/`migrate_control`/`migrate_clients`/`migrate_secrets` stage logic** in
   `app/v2/migration.py`, replacing the stubs, following the storage-audit table-by-table map.
7. Do **not** yet build: SafeSearch, parental controls, service blocking/schedules, per-client
   upstreams, domain routing, fallback DNS, upstream strategies, ECS, native HTTPS UI — those stay
   deferred per the roadmap's Day 4-8 sequencing, after the storage foundation is actually load-
   bearing, not just prototyped.

## Known open risks to carry forward

- Argon2id low-end hardware parameters unverified (see above).
- `notification_providers.secret` secret-separation gap (see `docs/v2/storage-audit.md`).
- Aggregate store path (`analytics/aggregates.db`) is a Workstream 1 proposal, not roadmap-pinned —
  confirm with the roadmap owner or just proceed with it; low risk either way since it's an
  isolated new path.
- Parquet row-group-size/Zstd-level were tested at one value each, not grid-searched — acceptable
  default per benchmark-results.md's reasoning, revisit only if real ingest/query profiles diverge
  materially from the synthetic benchmark once real traffic is flowing through it.
- 3M-row benchmark point did not complete in the Workstream 1 session (disk-I/O-bound on shared test
  hardware); the 100k/1M trend already supports the decision, but if `scale-3000000.json` finishes
  later, append it to `docs/v2/benchmark-results.md` for completeness.
