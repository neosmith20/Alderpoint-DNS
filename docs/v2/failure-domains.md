# V2 Failure-Domain Contract

**Status:** Frozen architectural invariant for V2. Source: `docs/v2/roadmap-reference/v2-architecture-plan.md` §2, §3.

## The invariant

Normal cached/recursive/filtering DNS operation must **never** depend on a live management-plane
database lookup per query. This is already true in v1.1.1 (dnsdist and BIND answer queries without
touching SQLite; the FastAPI app only compiles policy into native dnsdist/BIND structures ahead of
time — see `docs/architecture.md`). V2 keeps this property and makes it an explicit, testable
contract rather than an implicit one, because the V2 storage split (config YAML / control.db /
analytics store) adds more moving parts that could tempt a per-query lookup if not constrained.

## Components that MUST be able to fail without taking DNS down

Per the roadmap, DNS packet handling (dnsdist + BIND) must remain operational if any of the
following fail:

- FastAPI / web UI
- `control.db`
- analytics writer
- analytics reader / query engine (DuckDB or whichever backend wins the benchmark)
- the Parquet directory (or equivalent analytics storage directory)
- aggregate analytics store
- query-log UI
- browser session storage
- audit subsystem

## How this is enforced architecturally (not just by policy)

1. **Compile, don't look up.** Filtering/routing/policy state is compiled into dnsdist Lua config
   and BIND RPZ zones ahead of time by the existing stage → validate → backup → atomically activate
   → health-check → rollback pipeline. V2 extends this pattern to the new unified policy engine
   (out of scope for Workstream 1 to implement, but the interface boundary — "policy compiles to
   native structures, structures are what dnsdist/BIND read" — is frozen now so later workstreams
   don't have to re-architect around it).
2. **Analytics ingestion is asynchronous and bounded.** dnsdist emits protobuf events over the loop-
   back protobuf logger (`127.0.0.1:5301`); a dedicated `alderpointdns-analytics.service` process
   consumes them. This process is already isolated from the DNS data path in v1.1.1 (confirmed via
   `docs/architecture.md` and the v1.1.1 CHANGELOG entries hardening its SQLite connection
   lifecycle/backoff). V2's `app/v2/` prototype ingestion path (§ analytics benchmark harness)
   preserves this: bounded in-memory batch queue, explicit overflow-drop policy, no unbounded
   growth, writer crash does not block or crash dnsdist/BIND.
3. **Storage-layer isolation.** Splitting `query_events` out of the shared SQLite file into its own
   directory (analytics store) and moving control-plane tables into `control.db` means a corrupted
   or full analytics segment cannot corrupt config/control state, and vice versa — they are
   different files/processes/failure surfaces, not just different tables in one file.
4. **Host DNS independence** (§15 of the original workstream brief) is a related but separate
   invariant: the appliance's own apt/GitHub/cert-renewal/recovery networking must not depend on
   Alderpoint's client-facing data plane being healthy. This is already true in v1.1.1 — management
   HTTP traffic and host package management use explicit external resolvers, never loopback/BIND/
   dnsdist (confirmed in `docs/architecture.md`). V2 preserves this unchanged; nothing in this
   workstream touches host resolver configuration.

## What Workstream 1 does and does not implement here

- **Does:** document this contract; design the config/control-db/analytics-store split so the
  boundary exists; prototype the bounded analytics ingestion queue with explicit overflow policy
  (`app/v2/` prototype, tested for "writer failure doesn't propagate").
- **Does not:** wire any of this into the actually-running `alderpointdns.service` /
  `alderpointdns-analytics.service`, or implement the full unified policy engine. Those are later
  workstreams building on this frozen contract.

## Explicit overflow/drop policy (for the analytics prototype)

It is acceptable for V2 to drop analytics records under extreme failure rather than destabilize
DNS. Concretely, for the Workstream 1 ingestion prototype:

- Ingestion queue is a bounded in-memory ring buffer (`app/v2/` prototype default: configurable,
  benchmarked default TBD from harness results in `docs/v2/benchmark-results.md`).
- On overflow, oldest-first drop; a counter tracks `dropped_count` so the condition is observable
  (future workstream: surface as an admin-facing warning/metric, not implemented here).
- Writer-side exceptions (disk full, permission error, backend crash) are caught at the batch-flush
  boundary and logged; they must never propagate into the dnsdist protobuf receiver path.
