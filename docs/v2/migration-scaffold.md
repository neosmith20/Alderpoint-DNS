# V1 -> V2 Migration Scaffold

**Status:** V2 Workstream 1 output. Implementation: `app/v2/migration.py`. Tests:
`tests/v2/test_migration_scaffold.py` (10/10 passing, none of which open the live
`/var/lib/alderpointdns/alderpointdns.db`).

## Pipeline

`detect -> backup -> preview -> migrate_config -> migrate_control -> migrate_clients ->
migrate_policies -> migrate_secrets -> migrate_analytics -> generate_runtime_config -> validate ->
health_check -> commit`

Matches `docs/v2/roadmap-reference/v2-architecture-plan.md` §7 exactly, in order.

## What's real vs. stubbed in Workstream 1

- **Real:** the state machine — stage sequencing, restart/idempotency (`resume_state` skips
  already-completed stages), rollback semantics (a failure before `commit` never sets `committed`
  and never touches the source path), the `backup` stage (copies source into a staging directory —
  actually exercised, not stubbed), and the `detect` stage (checks source exists).
- **Stubbed (no-op, recorded as completed for state-machine testing purposes only):**
  `preview`, `migrate_config`, `migrate_control`, `migrate_clients`, `migrate_policies`,
  `migrate_secrets`, `migrate_analytics`, `generate_runtime_config`, `validate`, `health_check`,
  `commit`. Each of these needs real logic in a later workstream, informed by the storage map in
  `docs/v2/storage-audit.md`.

## Point of no return

`commit` is the last stage and the only one that sets `state.committed = True`. Every stage before
it operates only on a staging copy (`state.staging_dir`) — no stage before `commit` opens
`state.source_path` for writing (enforced by test:
`TestFailureRollback::test_failure_before_commit_leaves_source_untouched`, and
`TestPreviewDoesNotMutateSource`). This keeps the point of no return as late as the roadmap asks
for ("ideally keep that point extremely late") without requiring any stage-specific rollback logic
before it — "rollback" before `commit` is simply "discard the staging directory," which is safe by
construction.

## V1 query-history migration policy recommendation

Per the original workstream brief's three options (convert / archive read-only / discard-with-
aggregates-preserved):

**Recommended: option B, bounded read-only legacy archive, not automatic conversion.**

Rationale: v1's `query_events` rows don't carry the same field set the V2 Parquet schema uses
(no `upstream`/`cache_status` columns in v1 — see `docs/database.md` vs. the fields modeled in
`benchmarks/v2_analytics/generate.py`), so a byte-for-byte "convert to new segments" pass would
either fabricate data V1 never recorded or produce segments with different schemas than
V2-native ones — a subtler problem than it first looks like. Instead:

1. At migration time, export the entirety of v1's `query_events` table to a small number of
   read-only, clearly-labeled legacy Parquet segments (e.g.
   `analytics/queries/legacy-v1-import/*.parquet`, outside the normal `YYYY/MM/DD` layout so
   they're never mistaken for V2-native history and never targeted by V2's normal retention
   sweep).
2. DuckDB can still query them (a `UNION` view over legacy + native segments is possible for a
   later workstream to build, not required for Workstream 1).
3. Give the operator an explicit, bounded transition window (default recommendation: same
   retention period as their configured analytics retention, e.g. 30 days) after which the legacy
   archive is eligible for deletion like any other expired segment — never silently discarded
   immediately, never retained forever by default either.
4. Aggregate history (`analytics_aggregate_buckets`) migrates into the new aggregate SQLite store
   directly — same shape (bucketed counters), no format mismatch, no reason to archive it
   separately.

This satisfies "do not silently discard user history" (it's preserved, just clearly marked legacy
and time-bounded) and "do not import raw query history into control.db" (it goes to the Parquet
directory, never control.db) simultaneously. Not implemented in this workstream — the
`migrate_analytics` stage remains a stub; this is the design recommendation for whoever implements
it.

## Restartability

`resume_state` lets a caller re-invoke `run_migration` with a prior `MigrationState`; stages already
in `completed_stages` are skipped. Verified by
`TestRestartIdempotency::test_resuming_skips_already_completed_stages` — a partial run stopped
before `migrate_clients`, then resumed, only executes the remaining stages and reaches `commit`.
