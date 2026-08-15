# V2 Full Concurrent Resource Test (Workstream 3 final continuation, §34-37)

**Status:** Real, isolated, cgroup-capped evidence at 1 GiB and 2 GiB. 4 GiB was not attempted — see
the concrete measured reason below. This replaces Workstream 2's stated blocker ("could not safely
build a second complete constrained environment") with an actual isolated measurement, made safe by
using `systemd-run --scope -p MemoryMax=<N>` (a real Linux cgroup v2 hard memory ceiling) so the
tested workload can never consume host memory beyond its cap, protecting the live V1 appliance
regardless of total host free memory.

## Method

`benchmarks/v2_hardware/concurrent_workload_test.py` runs, concurrently via threads, inside one
`systemd-run` cgroup scope:

- a real isolated dnsdist instance (real installed binary) answering real DNS queries over a
  30-domain rotating set, sent continuously for the test duration
- a real `ParquetSegmentWriter` + `aggregates_db.record_batch()` ingesting synthetic query-event
  batches every 0.2s
- a real Argon2id hash+verify loop (`time_cost=4, memory_cost=256 MiB, parallelism=2` — the
  existing evidence-backed default from `docs/v2/hardware-memory-profile-results.md`)
- a real effective-policy compile loop (`policy_compiler.compile_effective_policy` +
  `compile_cache_profile`)

Peak memory and swap were polled directly from the cgroup's `memory.peak`/`memory.swap.current`
files during the run (not estimated), and the live v1.1.1 appliance's service status/free memory
were checked before and after each run.

## Host reality check (measured, not assumed)

```
$ free -h
               total        used        free      shared  buff/cache   available
Mem:           3.8Gi       1.5Gi       1.0Gi        53Mi       1.7Gi       2.3Gi
$ nproc
4
```

**This host has 3.8 GiB of total physical RAM.** A 4 GiB cgroup memory cap cannot be meaningfully
created or tested on a host with less than 4 GiB of total RAM — this is a concrete, measured, hard
blocker, not a policy choice: `systemd-run -p MemoryMax=4G` would either be silently capped by the
kernel to something less than 4G of *actual* available memory or would leave essentially zero
headroom for the OS, the live V1 appliance, and everything else on the host simultaneously. The 4
GiB profile therefore remains **reference/aspirational only**, unchanged from Workstream 2 — it was
never testable on this specific host, and this session did not attempt to fabricate a result for it.

## Results

| Profile | Peak RSS (measured) | Swap | DNS p50 | DNS p95 | DNS p99 | Analytics batches (15s) | Argon2 hashes (15s) | Policy compiles (15s) |
|---|---|---|---|---|---|---|---|---|
| 1 GiB cap | **316 MB** | 0 MB | 25.98 ms | 37.52 ms | 46.39 ms | 45 | 16 | 438,265 |
| 2 GiB cap | **316 MB** | 0 MB | 26.60 ms | 41.27 ms | 48.30 ms | 40 | 16 | 425,974 |

Raw results: `benchmarks/v2_hardware/results-concurrent-1gib.json`,
`results-concurrent-2gib.json`.

**Reading this:** the synthetic V2 workload above (dnsdist + real DNS traffic + Parquet/aggregate
writer + Argon2id + policy compiler, all concurrent) used essentially identical peak memory (~316
MB) whether capped at 1 GiB or 2 GiB — it never got anywhere near either ceiling, and never
swapped. DNS latency (uncached, since this test's dnsdist config has no packet cache attached — a
deliberately harder/more realistic worst case) was consistent across both caps, showing no
memory-pressure-induced degradation at either level.

## Combined with prior evidence

- V1 baseline resident footprint (`docs/v2/v1-performance-baseline.md`): ~457 MB (BIND + analytics
  + web/API + dnsdist).
- This session's V2 synthetic concurrent workload: ~316 MB peak.
- Workstream 2's isolated Argon2id-under-cgroup-pressure evidence
  (`docs/v2/hardware-memory-profile-results.md`): default params (256 MiB memory_cost) degrade
  severely below ~512 MB of true headroom.

Naive sum (457 + 316 ≈ 773 MB) plus OS overhead is still comfortably under 1 GiB, which is more
favorable to the 1 GiB profile than Workstream 2's evidence alone suggested — **but this is not a
like-for-like combination**: this session's test used a lightweight synthetic dnsdist instance
without BIND running alongside it in the *same* cgroup (BIND was not included in this concurrent
test — see gaps below), so it does not directly supersede the real BIND+dnsdist+everything-at-once
number.

## What this session did NOT do (explicit gaps for the next pass)

- **BIND was not included in the concurrent cgroup test.** The synthetic workload's dnsdist
  instance forwards to the real public 1.1.1.1 resolver directly, not to an isolated local BIND
  recursive resolver, because standing up a second complete BIND instance (config, zones, root
  hints) inside the same cgroup was judged out of this session's remaining budget on top of
  everything else built this pass — same reasoning as
  `docs/v2/cache-hit-latency-investigation.md`'s stated gap. BIND's own real ~250 MB RSS (from the
  V1 baseline) is not reflected in the 316 MB peak figure above.
- **No concurrent multi-login Argon2id test** — the loop here is single-threaded sequential
  hash/verify, not N simultaneous admin logins each allocating their own 256 MiB working set, which
  Workstream 2 already flagged as untested and remains untested.
- **4 GiB profile** — physically impossible on this host, stated above.
- **Sustained (multi-minute+) run** — each measurement ran 15-20 seconds; a longer soak test could
  reveal slow memory growth this short a window wouldn't show.

## Hardware minimum recommendation (updated, still not final)

This session's evidence does not contradict Workstream 2's 2 GiB recommended-minimum call, and adds
a real (not simulated) data point that the non-BIND V2 component stack alone has comfortable
headroom well below 1 GiB even under concurrent load. Given the explicit gap above (BIND not
included in the concurrent measurement, real concurrent-login Argon2id untested), this session
**keeps 2 GiB as the recommended safe default supported minimum**, with 1 GiB remaining a candidate
pending a BIND-inclusive concurrent test — not because new evidence made 1 GiB look worse, but
because the piece of evidence that would be needed to promote 1 GiB to "supported" (a real BIND
process resident in the same measurement) still doesn't exist. 4 GiB remains recommended/reference,
unchanged, and is untestable on this specific host.
