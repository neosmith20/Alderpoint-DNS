# V1.1.1 Runtime Performance Baseline (Workstream 2, §1)

**Status:** Captured against the live `alderpointdns-1` test appliance, `v1.1.1`, on 2026-08-14.
Method: `benchmarks/v1_baseline/capture_baseline.py` — bounded, local-only (queries `127.0.0.1:53`,
which is dnsdist's own listener), no config/service changes, no writes to
`/etc/alderpointdns`/`/var/lib/alderpointdns` (the one DB read is a read-only `mode=ro` SQLite
connection). Raw JSON: `benchmarks/v1_baseline/baseline-result.json`. Live appliance confirmed
`active` for all 5 units before and after capture; DB file confirmed still being written by the
real service (size/mtime advanced normally during the run).

This is the comparison point Workstream 2 (and later workstreams) must not regress against without
a documented, deliberate tradeoff.

## DNS latency/QPS

| Metric | Uncached (unique subdomains, real recursion) | Cached (`example.com` repeated) |
|---|---|---|
| min | 47.98 ms | 10.59 ms |
| p50 | 63.43 ms | 11.96 ms |
| p95 | 91.22 ms | 13.26 ms |
| p99 | 131.44 ms | 14.17 ms |
| mean | 70.02 ms | 12.03 ms |
| n | 80/80 answered | 80/80 answered |

Uncached latency is dominated by real upstream recursion time to the public internet from this
host (expected — that's genuinely what a cache miss costs here, not an artifact of Alderpoint's
own processing). Cached latency (~12ms mean) is the more relevant number for "how fast is
Alderpoint's own hot path" and is the number Tier A/Tier B recovery and the effective-cache-profile
work should be measured against — cache misses immediately after a cold start should trend from
~70ms toward ~12ms as the working set repopulates.

**QPS (5s bounded raw-UDP synthetic burst, single process, `example.com` repeated):** 1,607.8
sent/s, 1,607.2 received/s (99.98% answered) — this is a single Python process's send-and-wait
throughput ceiling, not a true concurrent-client load test; treat it as a floor, not the
appliance's real ceiling. A proper multi-worker QPS ceiling test is deferred (would need care not
to disrupt the shared test host) — recorded as an open item below.

dnsdist packet-cache / BIND recursive-cache hit/miss counters were not queried directly in this
pass (no safe read-only counter-inspection path was exercised) — the cached-vs-uncached latency
gap above is used as the practical proxy. Direct cache-statistics inspection (e.g. dnsdist's
console/API) is a reasonable Workstream 2+ follow-up if precise hit-rate numbers are needed.

## Resources

| Service | RSS / MemoryCurrent |
|---|---|
| `named`/`bind9` (BIND) | 255,612 KiB RSS / ~252 MB cgroup |
| `alderpointdns-analytics` | 89,464 KiB RSS / ~82 MB cgroup |
| `alderpointdns` (web/API, uvicorn) | 80,716 KiB RSS / ~63 MB cgroup |
| `dnsdist` | 41,616 KiB RSS / ~20 MB cgroup |

Host: `free -b` at capture time — total 4,111,773,696 B (~3.83 GiB), used 1,430,073,344 B
(~1.33 GiB), available 2,681,700,352 B (~2.5 GiB after accounting for reclaimable cache). CPU
utilization (`%CPU` column from `ps`) was low/idle for all four services during capture (0.0-2.2%)
since this was a light synthetic burst, not sustained load — a real CPU-under-load figure needs a
longer sustained-QPS run, not attempted here to avoid disrupting the shared host.

**Takeaway for V2 hardware profiles:** BIND alone (~252 MB) is already a meaningful fraction of the
1 GiB candidate minimum from `docs/v2/architecture-map.md`. Combined V1 footprint (BIND + dnsdist +
web/API + analytics) is roughly 420 MB resident right now, on a host with a 28 MB `query_events`
table — this is a favorable case, not a worst case (large query-log/analytics DB, DuckDB query
execution, and Argon2id under load will all add on top of this). See "Hardware/memory profile
testing" section of `docs/v2/handoff-workstream-2.md` follow-up work for the full-appliance test
this baseline feeds into.

## Analytics / query-log

| Metric | Value |
|---|---|
| `query_events` row count | 23,977 |
| `query_events` COUNT(*) query | 2.01 ms |
| `analytics_events` row count | 1 |
| "recent page" style query (`ORDER BY id DESC LIMIT 50`) | 0.18 ms |

These are trivially fast at 24k rows — expected, since v1.1.1's `query_events` table is small
relative to the scales the Workstream 1 benchmark tested (100k/1M rows). This baseline is the
"today" number; the Workstream 1 benchmark results
(`docs/v2/benchmark-results.md`) are the projection for what happens as this table grows, which is
the actual motivation for moving off SQLite for raw history.

## Storage

| Item | Value |
|---|---|
| `alderpointdns.db` size | 28,676,096 bytes (~27.3 MiB) |
| `/var/lib/alderpointdns` total (`du -sb`) | 12,037,345,645 bytes (~11.2 GiB) — dominated by existing backup archives under `backups/`, not the live DB |
| Host disk free | 11,418,386,432 bytes (~10.6 GiB) of 49,781,313,536 (~46.4 GiB), 76% used |

The disk-free figure is the same constraint noted throughout Workstream 1 — it caps how much
Parquet/benchmark data this workstream can safely generate on this shared host, and is why the
real Parquet writer's own tests use small bounded datasets, not multi-GB scale runs.

## Open items not captured in this pass

- True concurrent multi-client QPS ceiling (this pass measured single-process send-and-wait
  throughput, a floor not a ceiling).
- Sustained CPU utilization under real load (this pass was a short burst, mostly idle CPU).
- Direct dnsdist/BIND cache hit/miss counters (proxied via cached-vs-uncached latency instead).
- Service startup/restart timing (not exercised — restarting a live service, even briefly, was
  judged not worth the risk for a baseline capture; can be captured safely in a maintenance window
  if needed later).
