# V2 private RC11 — per-client analytics exclusion, real proof after two real defect rounds (roadmap Priority 6)

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~rc11-1`
- Filename: `alderpointdns-v2_2.0.0~rc11-1_all.deb`
- SHA-256: `130254b11fa67d9975cf0c477f6e25017af284c6a3b48f1dabc6b497ca0d57ff`

## What it took to get here

Two real defects found and fixed in sequence through live acceptance
testing, each on its own rebuilt candidate:

1. **RC9** (built, never committed as a numbered artifact):
   `alderpointdns-v2-analytics` crash-looped the instant a real
   per-client `query_log_enabled` exclusion was configured --
   `ProtectSystem=strict`'s narrow `ReadWritePaths=` never anticipated
   this worker needing control.db access at all.
2. First fix attempt (committed, `a208cf6`): a read-only SQLite URI
   connection, hypothesizing reads don't need `ReadWritePaths`. Built
   as RC10, **re-tested live, and it still failed identically** --
   confirmed a real SQLite WAL constraint (a read-only connection to a
   database another process holds open in WAL mode still needs write
   access to that database's `-shm` locking file).
3. Real fix (`608e83b`): widened the service's `ReadWritePaths` to
   match the web/discovery services' existing scope, keeping the
   read-only SQLite connection as real defense in depth at the
   application level.

## Real live proof on RC11

Fresh clean install, 0 failed units. Real client created with
`query_log_enabled=false` via the HTTPS API, a real query from that
exact client IP, a real query from an unexcluded client IP, then two
service restarts (matching the segment-close-on-shutdown Parquet
contract already documented in earlier RCs):

- Aggregate stats correctly show **both** queries and both clients
  (only `query_log_enabled` was disabled, not `statistics_enabled`).
- The real Parquet raw-query-log segment contains the unexcluded
  client's domain **only** -- the excluded client's domain never
  appears in it.
- Zero failed units, zero crash-loop, throughout.

This is the exact scenario that crash-looped RC9 and RC10, now proven
working correctly end to end with real service restarts under real
`ProtectSystem=strict` sandboxing.
