# V2 Analytics Storage Benchmark — Results

**Status:** V2 Workstream 1 output. Harness: `benchmarks/v2_analytics/`.
**Contenders (per `docs/v2/roadmap-reference/v2-architecture-plan.md` §3.4):** Parquet+Zstd+DuckDB,
dedicated SQLite WAL, compressed JSONL.

## Methodology

- Synthetic records (`benchmarks/v2_analytics/generate.py`) modeled on v1's `query_events` table
  plus roadmap-requested fields (upstream, cache status): Zipfian-skewed domain/client popularity
  (85% of traffic on ~18 popular domains + a Zipf-weighted client pool, 15% long-tail), realistic
  qtype mix (mostly A/AAAA, some HTTPS/PTR/CNAME/TXT/SRV), ~92% NOERROR / 6% NXDOMAIN / rest
  SERVFAIL/REFUSED, ~7% blocked traffic skewed toward a small set of ad/tracker/malware domains,
  gaussian latency (two modes: fast cache-hit-like ~8ms, slower ~45ms), timestamps spread across a
  synthetic 7-day window.
- Each backend (`benchmarks/v2_analytics/backends.py`) implements the same batched-ingest + fixed
  18-query suite + retention-delete + disk-usage interface, so timings are comparable.
- Scales run: **100,000** and **1,000,000** rows (full results below, both completed).
  **3,000,000** was launched but is disk-I/O-bound on this shared host and did not complete within
  this workstream's session — see "3M-row run" below for status and what to do with it.
  This is below the original brief's 10M+ aspiration; see "Known constraint" below.
- Batch sizes: 5,000 (100k), 10,000 (1M). SQLite ingest is wrapped in one explicit transaction per
  batch (autocommit-per-row was measured separately and is ~18x slower — not a realistic comparison
  point, excluded from these results).
- Parquet: `row_group_size=50_000`, Zstd level 9 at the time the 100k/1M runs below were captured
  (level 9 was the harness default for that run; the provisional default was corrected to level 6
  after the fact — see "Zstd default correction" under "Parquet tuning recommendation" below; the
  ingest/query/disk numbers below are not materially affected, since level 6 vs 9 differs by ~0.2%
  compressed size at this scale), one segment file per ingest batch (a real writer would use larger
  segments/time-based rotation — see "Parquet tuning" below for the distinction between this
  benchmark's per-batch segments and the recommended production layout).
- Retention test: delete the oldest ~20% of data (SQLite: `DELETE ... WHERE ts < cutoff` — the
  "no giant DELETE" architectural rule explicitly does *not* apply to SQLite the way it does to
  segment-file backends, which is itself part of the finding; JSONL/Parquet: unlink the oldest ~20%
  of segment files, no VACUUM/rewrite needed).
- Known constraint: this host has **11GB free disk** (76% used of 47GB). 10M+-row runs from the
  original brief were not attempted — projected SQLite WAL size alone at 10M rows (~2GB based on
  the 195MB/1M-row measurement) plus WAL/shm overhead during a live run made it an unnecessary risk
  for a shared test box. 100k/1M are enough to show the trend clearly (see results); the 3M point
  was attempted specifically to get one data point closer to that ceiling.

## Results — 100,000 rows

| Backend | Ingest | Rows/s | Disk | Bytes/row | Peak RSS* |
|---|---|---|---|---|---|
| SQLite WAL | 3.12s | 32,031 | 23.2MB | 243.4 | 22MB |
| JSONL (gzip) | 1.18s | 84,442 | 2.4MB | 25.5 | 186MB |
| Parquet+Zstd+DuckDB | 0.66s | 150,848 | 1.7MB | 17.6 | 186MB |

Query latency (warm, ms) — representative subset:

| Query | SQLite | JSONL | Parquet+DuckDB |
|---|---|---|---|
| `last_24h` (count) | 0.28 | 16.6 | 2.2 |
| `search_exact_domain` | 0.25 | 18.1 | 3.5 |
| `top_domains` | 9.6 | 32.1 | 3.1 |
| `top_blocked_domains` | 81.2 | 15.9 | 6.2 |
| `rcode_distribution` | 39.4 | 29.5 | 2.5 |
| `time_series_counts` | 31.3 | 37.3 | 4.0 |

## Results — 1,000,000 rows

| Backend | Ingest | Rows/s | Disk | Bytes/row | Retention delete |
|---|---|---|---|---|---|
| SQLite WAL | 275.3s | 3,633 | 196.0MB | 205.5 | 9.22s |
| JSONL (gzip) | 11.6s | 86,034 | 24.3MB | 25.5 | 0.0015s |
| Parquet+Zstd+DuckDB | 6.5s | 153,413 | 16.2MB | 16.9 | 0.0014s |

Query latency (warm, ms) — representative subset:

| Query | SQLite | JSONL | Parquet+DuckDB |
|---|---|---|---|
| `last_24h` (count) | 3.6 | 163.9 | 11.6 |
| `search_exact_domain` | 2.4 | 191.4 | 8.6 |
| `top_domains` | 102.0 | 308.8 | 15.4 |
| `top_blocked_domains` | 856.1 | 158.4 | 12.4 |
| `top_clients` | 89.7 | 268.0 | 10.4 |
| `rcode_distribution` | 416.0 | 289.1 | 8.9 |
| `time_series_counts` | 318.0 | 361.2 | 24.2 |

\* Peak RSS for the 100k/1M tables above was measured with the pre-remediation harness, where all
three backends ran sequentially in one process — `resource.getrusage` reports the process's
high-water mark since start, not per-backend, so JSONL's and Parquet's figures both actually
reflected the peak set by JSONL's full-dataset-into-memory query scan (`_load_all()`), not each
backend's independent memory use. **Fixed** (Dex review item): `run_benchmark.py` now runs each
backend in its own subprocess by default (`_run_backend_in_subprocess`), so `peak_rss_mb` is that
backend's own child-process peak. Validated with a representative 50k-row rerun after the fix,
which produced three distinct, plausible per-backend figures instead of two backends sharing an
inflated value: SQLite WAL 22.4MB, JSONL(gzip) 99.4MB, Parquet+DuckDB 122.8MB — Parquet+DuckDB's
own genuine baseline (duckdb+pyarrow import/runtime overhead) is higher than JSONL's at this small
scale, which is a legitimate, backend-specific number now rather than an artifact. The committed
100k/1M tables above were not rerun under the fixed harness (their ingest/disk/query numbers are
unaffected by this fix — only `peak_rss_mb` was ever wrong); treat their `peak_rss_mb` columns as
carrying the pre-fix caveat above, and any future rerun will use the corrected subprocess-isolated
default. A `--in-process` flag preserves the old faster-but-cumulative mode for quick iteration
where memory figures don't matter.

## 3M-row run

Launched with the same harness (`--scale 3000000 --batch 20000`); at time of writing this document
the SQLite WAL phase (which runs first) had not completed after several minutes of disk-I/O-bound
execution, consistent with the non-linear ingest slowdown already visible between the 100k and 1M
points (32k rows/s -> 3.6k rows/s, roughly 9x slower per row at 10x the scale — index B-tree
maintenance cost, not a fluke). This independently supports the same conclusion the 1M data already
shows without needing the 3M number to land the decision. If/when that run finishes, its JSON output
(`benchmarks/v2_analytics/results/scale-3000000.json`) should be appended here as an addendum in a
follow-up commit; it is not blocking the Workstream 1 decision below.

## Interpretation

- **Ingest:** Parquet+Zstd+DuckDB is fastest at both scales (2x JSONL, 40-75x SQLite-with-indexes
  at 1M). SQLite's ingest cost is dominated by maintaining the `idx_qe_domain`/`idx_qe_client`
  indexes needed to keep its *point* queries fast — those are the same indexes that make
  `search_exact_domain`/`by_client` fast on SQLite. This is a real, honest tradeoff: an index-free
  SQLite table would ingest faster but lose exactly the query pattern it currently wins at.
- **Aggregate/GROUP BY queries** (`top_domains`, `top_blocked_domains`, `rcode_distribution`,
  `time_series_counts`) are SQLite's worst case (no covering index helps a full-table GROUP BY) and
  Parquet+DuckDB's best case (columnar scan + vectorized aggregation) — and these are exactly the
  dashboard queries the roadmap cares about (top domains, top blocked, response-code distribution,
  time-series counts).
- **JSONL** is competitive on ingest (no index maintenance) and by far the most disk-efficient
  alongside Parquet, but every query is a full Python-level scan with no query engine underneath —
  it loses on every query type at 1M scale, often by 10-50x versus Parquet+DuckDB, and that gap
  only widens with data size since it has no index or columnar pruning at all.
- **Retention:** SQLite's `DELETE` at 1M rows took 9.2s and — per the architectural rule against
  "million-row DELETE operations" — this cost keeps growing with retained history size and requires
  periodic `VACUUM` to reclaim space (not separately measured here, but is a known SQLite operational
  cost the roadmap explicitly warns against). JSONL/Parquet retention is filesystem `unlink()` on
  closed segments — sub-millisecond regardless of how much history exists, because deleting one file
  never touches the rest of the dataset.
- **Disk:** Parquet is smallest at both scales (17-18 bytes/row vs JSONL's ~25.5 vs SQLite's
  ~205-243), a meaningful difference for a bounded appliance with limited storage.

## Decision

**Raw query history backend: Parquet + Zstandard + DuckDB.** It wins ingest throughput, wins every
query in the fixed suite except two point-lookups where SQLite's indexes have a natural advantage
(and even there Parquet is within single-digit milliseconds, not a usability problem), wins disk
efficiency, and wins retention cost by construction (segment deletion vs. row-level DELETE). This
matches the roadmap's own expectation (§21: "if Parquet+Zstd+DuckDB performs as expected, move
forward with it rather than inventing artificial objections") — the data supports it rather than
requiring it to be assumed.

**Aggregate backend: small dedicated SQLite WAL database**, separate from both `control.db` and the
raw Parquet store. Rationale: aggregate rows (per-minute/hour/day counters) are naturally small,
bounded, and relational (`analytics_aggregate_buckets`-shaped upserts), which is exactly SQLite's
strong case — the 1M-row benchmark's SQLite weaknesses are about *raw event* volume and GROUP BY
over millions of rows, neither of which applies to a bounded counter table with a handful of rows
per time bucket. This avoids adding DuckDB-as-a-second-persistent-store complexity for data that
doesn't need a columnar engine, while still keeping it out of `control.db` per the architectural
rule in `docs/v2/storage-audit.md`.

## Parquet tuning recommendation

- **Partitioning:** `analytics/queries/YYYY/MM/DD/HH-<segment>.parquet` as the roadmap suggests —
  not tested at full partition depth in this benchmark (the harness used flat per-batch segment
  files to isolate storage-format comparison from directory-layout cost), but the atomic
  temp-name-then-rename promotion pattern validated here (`backends.py`
  `ParquetDuckDbBackend.ingest`) applies unchanged to a partitioned layout — DuckDB's
  `read_parquet('.../**/*.parquet')` glob handles nested partitions natively.
- **Rotation:** time-based (hourly) rather than purely batch-count-based, to keep segment count and
  size predictable regardless of query volume; a size-based secondary trigger (e.g. rotate early if
  a segment exceeds ~64MB) avoids pathologically large segments during a traffic spike.
- **Row-group size:** 50,000 rows (provisional default) is a reasonable starting point — large
  enough to keep Zstd compression effective and row-group-level statistics useful for query
  pruning, small enough that a single row group isn't the whole segment. Dex's review noted that
  10k/50k/100k were indistinguishable at the benchmark's tested scale, so this remains an untuned
  provisional default, not a benchmark-proven optimum — real-runtime tuning is deferred to
  Workstream 2 once actual ingest/query profiles are flowing through the system, not guessed
  further here.
- **Zstd level: corrected to 6** (was provisionally 9 in the first Workstream 1 pass). Dex's
  independent review found level 6 compresses to approximately the same size as level 9 at the
  tested scale while writing faster, and level 3 is only modestly larger. This session verified
  that finding directly (100k-row table, `pyarrow.parquet.write_table`, `row_group_size=50_000`):

  | Zstd level | write time | bytes/row |
  |---|---|---|
  | 3 | 0.066s | 16.97 |
  | **6** | **0.080s** | **16.43** |
  | 9 | 0.102s | 16.40 |

  Level 6 gets within 0.03 bytes/row of level 9's compression (a difference of 0.2%) at ~22% less
  write time, and both comfortably beat level 3 on size for negligible extra cost. `app/v2/`'s
  benchmark harness default (`ParquetDuckDbBackend.zstd_level`, `run_benchmark.py --zstd-level`)
  is updated to `6` accordingly. Not an exhaustive level sweep (1-2, 4-5, 7-8, 10+ untested) — if
  Workstream 2's real-runtime CPU profile makes compression cost meaningfully visible, revisit with
  a fuller sweep at production scale rather than this single confirmatory check.
- **Batch size:** 10,000-20,000 records per ingest batch matched the bounded-queue design in
  `app/v2/analytics_ingest.py` reasonably (bounded memory, infrequent enough flushes to keep Zstd
  effective). Exact production default should be tuned against real dnsdist protobuf event rates in
  a later workstream, not guessed further here.
- **Partition pruning (Workstream 2 acceptance gate, not proven here):** this benchmark used flat
  per-batch segment files in one directory, which says nothing about whether a "last hour" query
  against the real `YYYY/MM/DD/HH-<segment>.parquet` layout actually skips scanning historical
  partitions rather than reading every file and filtering in-memory. DuckDB's `read_parquet()` can
  prune by directory-derived Hive partitioning or by row-group statistics, but which one V2 actually
  gets depends on exactly how the reader is written — that reader doesn't exist yet. Workstream 2
  must include a test proving a bounded recent-time-range query touches only the relevant partition
  files, not the full history; see `docs/v2/handoff-workstream-2.md`.
