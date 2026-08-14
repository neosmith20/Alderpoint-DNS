# V2 Hardware/Memory Profile Testing — Workstream 2 (§21-23)

**Status:** Partial, real evidence — not the full-appliance concurrent test the Workstream 2 gate
ultimately requires. Honest scope statement up front: this session could not safely build and run a
second complete constrained-memory V2 appliance (BIND + dnsdist + FastAPI + analytics writer +
DuckDB + Argon2id, all resident and under load simultaneously) on this shared single test host
without either risking contention with the live v1.1.1 service or standing up infrastructure well
beyond this workstream's "foundation, not full implementation" scope. What follows is real,
reproducible, cgroup-constrained evidence for the piece that was previously flagged as completely
untested — Argon2id under actual memory pressure, not just in an unconstrained process — plus the
V1 resident-memory baseline from `docs/v2/v1-performance-baseline.md`, combined into a
reasoned-not-fabricated recommendation. The full concurrent-everything test remains a Workstream 3
prerequisite (see `docs/v2/handoff-workstream-2.md`).

## Method

`systemd-run --scope -p MemoryMax=<N> -- python3 <argon2 probe>` — a real Linux cgroup memory
ceiling (not a simulation), same mechanism systemd would use for a real per-service memory limit.
Each probe hashes and verifies one password with `argon2-cffi`, reporting wall time and peak RSS.
`journalctl` afterward reports the cgroup's actual peak memory and swap usage for that scope.

## Results: Argon2id under constrained memory

| Memory cap | `memory_cost` param | hash time | verify time | peak RSS | swap used |
|---|---|---|---|---|---|
| none (baseline, prior session) | 256 MiB | ~437 ms | ~456 ms | — | — |
| 512 MiB | 256 MiB | 623.6 ms | 571.1 ms | 266.5 MB | not observed |
| 256 MiB | 256 MiB | 3,250.8 ms | 3,680.4 ms | 261.8 MB | 105.3 MB |
| 100 MiB | 256 MiB | did not complete in 15s | — | — | 237.7 MB (still climbing) |
| 256 MiB | 64 MiB | 114.9 ms | 107.1 ms | 74.5 MB | none |
| none (baseline) | 64 MiB | 112.1 ms | 114.3 ms | 74.4 MB | — |

**Reading this table:** the current default (`memory_cost=256 MiB`) is fine as long as the cgroup/
process has meaningfully more than 256 MiB of true headroom — at exactly a 512 MiB cap it's already
~40% slower than baseline (contention with allocator/kernel bookkeeping overhead even before
swapping), and at a 256 MiB cap it collapses to 7.4x slower via 105 MB of swap activity. At a 100
MiB cap it didn't finish in 15 seconds — actively thrashing, not just slow. A lighter parameter set
(`memory_cost=64 MiB`) is essentially unaffected by a 256 MiB cap (114.9ms vs 112.1ms unconstrained)
because it never needs to approach the ceiling.

**Conclusion this evidence directly supports:** the previous "not yet tested under realistic memory
pressure" gap is now closed for the *isolated* Argon2id question — the answer is clearly that
`memory_cost=256 MiB` requires real headroom well above 256 MiB to avoid severe degradation, and
degrades gracefully-then-catastrophically as available memory shrinks toward that value, rather than
failing cleanly.

## V1 resident baseline (from `docs/v2/v1-performance-baseline.md`)

| Service | RSS |
|---|---|
| BIND (`named`) | ~250 MB |
| `alderpointdns-analytics` | ~87 MB |
| `alderpointdns` (web/API) | ~79 MB |
| `dnsdist` | ~41 MB |
| **Total (v1, today, 24k-row query_events table)** | **~457 MB** |

This is v1's footprint with a small (24k-row) query-log table and light synthetic load — not a
worst case. V2 adds DuckDB query execution overhead (not measured standalone here) and Argon2id's
working set on top of this, and a larger production query-log/analytics dataset will grow the
analytics-writer/DuckDB figures further.

## Hardware minimum recommendation (evidence-based, not final)

| Profile | Assessment |
|---|---|
| **512 MiB** | Confirmed unsupported for V2 — the OS + BIND alone (~250 MB) already consumes roughly half of it before dnsdist, the web/API process, analytics, DuckDB, or Argon2id are considered. Retained only as a stress/torture profile per the frozen decision in `docs/v2/architecture-map.md`. |
| **1 GiB** | Still only a *candidate*, not confirmed. V1's baseline footprint (~457 MB) plus OS overhead already uses roughly half; the remainder must cover DuckDB query execution, the analytics writer, Argon2id's working set (256 MiB alone at default parameters), and traffic spikes — this evidence suggests it is tight but not obviously impossible if Argon2id uses a lighter parameter set on this profile specifically (see recommendation below) and DuckDB's `memory_limit` is capped conservatively. Requires the full concurrent-everything test (Workstream 3) before being called supported. |
| **2 GiB** | Recommended as the safe default supported minimum from this evidence: V1 baseline (~457 MB) + default-parameter Argon2id (needs comfortably more than 256 MB free to avoid the degradation shown above) + DuckDB + safety headroom fits with real margin, without requiring a lighter/weaker Argon2id parameter set. |
| **4 GiB** | Recommended/reference profile, ample headroom for all components plus growth (larger query-log tables, more concurrent admin sessions, bigger blocklists). |

## Argon2id parameter recommendation (updated from this evidence, still not final)

**Not switching to a single universal parameter set.** The evidence above supports a
hardware-aware calibrated approach (the second option `docs/v2/handoff-workstream-2.md` gate 5
posed), with a hard security floor:

- **2 GiB and 4 GiB profiles:** keep the existing evidence-base default
  (`time_cost=4, memory_cost=256 MiB, parallelism=2`, ~437-456 ms) — real headroom exists per the
  table above, so no degradation is expected. Still not "final" in the sense of a full concurrent
  test, but no longer unverified as to memory-pressure behavior.
- **1 GiB profile, if it is ever approved as supported:** use a lighter parameter set instead of the
  above — `time_cost=3, memory_cost=64 MiB, parallelism=2` (~112-115 ms, verified unaffected by a
  256 MiB cgroup cap in the table above) is the concrete evidence-backed alternative. This is
  visibly weaker brute-force resistance than the 256 MiB default and that tradeoff must be stated
  explicitly to whoever approves 1 GiB as supported — it is not a free lunch, it is the honest cost
  of fitting Argon2id into a tighter memory budget.
- **512 MiB:** no recommendation — the profile itself is not supported, so no Argon2id parameter
  set is being tuned for it.

This remains **not final** — the full-appliance concurrent test (Workstream 3 prerequisite) is what
actually determines free memory available to Argon2id at each profile once BIND, dnsdist, the web/
API process, the analytics writer, and DuckDB are all resident and active at once, not just V1's
baseline plus an isolated Argon2id probe.

## What this session did NOT do (explicit gaps for Workstream 3)

- Did not run BIND + dnsdist + the V2 analytics/DuckDB stack + Argon2id concurrently under any
  memory cap — only V1 baseline (uncapped, live) and Argon2id (capped, isolated) were measured.
- Did not measure DuckDB's own memory behavior under a tight cap (e.g. `memory_limit` pragma
  effectiveness, query failure behavior when exceeded).
- Did not simulate concurrent Argon2id hashing (multiple simultaneous admin logins) under a cap —
  `parallelism=2` per-hash plus N concurrent logins multiplies the working set, not tested here.
- Did not observe OOM-kill behavior directly (the 100 MiB cap test was stopped by timeout at 15s
  rather than run to an actual OOM kill, to avoid an open-ended hang in this session).
