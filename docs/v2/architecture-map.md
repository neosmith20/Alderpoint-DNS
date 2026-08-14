# V2 Architecture Map — Workstream 1 Summary

**Status:** V2 Workstream 1 output, consolidating `docs/v2/storage-audit.md`,
`docs/v2/failure-domains.md`, and `docs/v2/benchmark-results.md` into the confirmed architecture.

## Storage ownership (confirmed)

| Store | Path | Contents | Status |
|---|---|---|---|
| Config | `/etc/alderpointdns/alderpointdns.yaml` | Operator desired-state: listeners, upstream strategy, analytics policy, feature toggles | Schema + atomic-write implemented (`app/v2/config.py`), not wired to live path |
| Control | `/var/lib/alderpointdns/control.db` | Admins, sessions, audit log, clients/identifiers/groups, policies, job history, replication metadata, migration state | Schema-versioned SQLite WAL prototype implemented (`app/v2/control_db.py`), not wired to live path |
| Raw analytics | `/var/lib/alderpointdns/analytics/queries/YYYY/MM/DD/HH-<segment>.parquet` | Raw per-query history | **Decided: Parquet + Zstd + DuckDB** (see benchmark-results.md) |
| Aggregate analytics | small dedicated SQLite WAL db (path TBD, sibling to control.db, e.g. `/var/lib/alderpointdns/analytics/aggregates.db`) | Minute/hour/day rollup counters | **Decided: dedicated SQLite WAL**, separate file from control.db |
| Secrets | `/etc/alderpointdns/` root-owned dedicated files (existing v1 pattern) | TLS keys, API creds, (new) Argon2id pepper file | Pattern preserved from v1; pepper file path is new, not yet created |

## Confirmed control-db schema boundary

See `app/v2/control_db.py` for the actual DDL. Enforced by test
(`tests/v2/test_control_db.py::TestNoQueryHistoryGuard`): no table whose name contains
`query_event`, `raw_quer`, or `query_log` may exist in control.db. This guard exists specifically
so a future workstream cannot accidentally reintroduce v1's architecture mistake (raw history
sharing the control database) while extending the schema.

## Confirmed config schema

See `app/v2/config.py`. `schema_version` field is mandatory and currently pinned to `1` with no
migrator registered — a real version-2 schema change needs an explicit migrator before
`schema_version: 2` will load. Atomic write is temp-file + `fsync` + `os.replace` + parent-directory
fsync, mode `0640`.

## Argon2id recommendation

Benchmarked on this test server (4 vCPU / 3.8 GiB) via `benchmarks/v2_argon2_bench.py`:

| time_cost | memory_cost | parallelism | hash (ms) | verify (ms) |
|---|---|---|---|---|
| 2 | 19 MiB (library default) | 1 | 27.7 | 27.5 |
| 2 | 64 MiB | 2 | 60.6 | 68.8 |
| 3 | 64 MiB | 2 | 96.3 | 85.3 |
| 3 | 128 MiB | 2 | 170.9 | 174.6 |
| 4 | 128 MiB | 2 | 223.7 | 207.9 |
| 3 | 256 MiB | 4 | 201.6 | 203.0 |
| **4** | **256 MiB** | **2** | **437.4** | **456.0** |
| 5 | 256 MiB | 2 | 573.5 | 536.5 |

**Recommended default (roadmap "normal" 2 vCPU / 2 GiB profile): `time_cost=4, memory_cost=256MiB,
parallelism=2`** — lands at ~440-460ms per login, inside the target 250-500ms interactive-login
window, and is what `app/v2/auth_hash.py`'s `DEFAULT_*` constants use.

**Open risk:** the roadmap also defines a "low-end" 1 vCPU / 512 MiB performance-gate profile.
256MiB Argon2id memory cost alone would consume half that box's RAM per concurrent hash operation,
which is risky if login attempts aren't otherwise rate-limited (v1.1.1 already has a
`login_attempts` table feeding rate-limiting — this needs to be confirmed as bounding *concurrent*
hash operations, not just attempt frequency, before shipping this default unconditionally). This
workstream did not have access to genuinely constrained 1 vCPU / 512 MiB hardware to re-benchmark
directly; a `systemd-run --scope -p CPUQuota=100% -p MemoryMax=512M` approximation was considered
but not run in this session. **Recommendation for Workstream 2 or before release:** either verify
the low-end profile with a lower parameter set (e.g. `time_cost=3, memory_cost=64MiB,
parallelism=1`, ~85-100ms estimated by extrapolation from the table above) selected per-profile at
install time, or confirm login concurrency is bounded tightly enough that 256MiB peak is
acceptable even on the smallest supported hardware.

**Pepper recommendation: yes**, root-only file under `/etc/alderpointdns/argon2-pepper` (0600,
root:root), concatenated with the password before hashing (see `app/v2/auth_hash.py`'s `pepper`
parameter — plumbing exists, wiring into the real admin-login path is a later workstream). Rationale:
theft of `control.db` alone (e.g. from a backup left somewhere, or a partial compromise that reads
the DB but not `/etc/alderpointdns`) becomes insufficient to offline-crack admin passwords without
also obtaining the separate pepper file.

**Backup/recovery implication (must be explicit, not silently accepted):** the pepper file MUST be
included in the encrypted backup path alongside other `/etc/alderpointdns` secrets — a backup that
captures `control.db` but not the pepper makes every admin password permanently unverifiable after
a restore (there is no way to recompute it). This is a real availability risk trade for a real
confidentiality gain, not a free win, and needs to be called out in backup/restore documentation
and in the migration scaffold's `migrate_secrets` stage when it's implemented for real.

## Failure domains

See `docs/v2/failure-domains.md` for the full contract. Summary: DNS answering never depends on a
live control.db/analytics lookup per query (already true in v1.1.1, frozen as an invariant for V2);
analytics ingestion is asynchronous with a bounded queue and explicit oldest-first drop on overflow
(`app/v2/analytics_ingest.py::BoundedQueue`); segment writes use temp-name-then-atomic-rename so a
reader can never observe partial history (`app/v2/analytics_ingest.py::SegmentWriter`,
`ParquetDuckDbBackend.ingest`); host DNS independence is unchanged from v1.1.1.

## Open items / conflicts between docs and implementation evidence

None found that require overriding the roadmap. One clarification worth recording: the roadmap
doesn't specify the aggregate store's exact file path — `architecture-plan.md` §3.5 lists it as "a
small dedicated `analytics.db`" without pinning a path the way it does for `control.db` and the raw
Parquet directory. This document proposes
`/var/lib/alderpointdns/analytics/aggregates.db` as a sibling of the raw-history directory; not
yet implemented, flagged for Workstream 2 to confirm or adjust.
