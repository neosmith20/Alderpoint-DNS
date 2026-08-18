# Real defect found and fixed: Tier B prewarm traffic silently polluted real analytics/statistics

Roadmap continuation, discovered while investigating
`cache_status: "prewarm"` (a defined-but-never-set `NormalizedQueryEvent`
enum value) -- tracing through how the Tier B prewarm worker actually
issues its queries.

## What was found

`app/v2/tier_b_worker.py`'s own docstring is explicit that prewarm
"replays through the normal DNS path... never a bypass" -- a
deliberate, correct architecture decision so prewarm can never be
suspected of gating real DNS readiness. The real consequence, never
previously checked: every prewarm resolution is a genuine UDP query
sent from `127.0.0.1` to the live dnsdist listener, indistinguishable
in dnsdist's protobuf log from a real client's traffic on localhost.

**Live-verified impact on a real installed RC14 package:** a real
client query for `example.com` produced `total_queries=1` in the
aggregate database, correctly attributed to client `127.0.0.1`. A
single manual `tier-b-worker --once` tick immediately afterward (which
only re-queries the same, already-popular `example.com` it just
learned about) pushed `total_queries` to `2` -- both attributed
identically to client `127.0.0.1`, with no way to tell the appliance's
own self-generated cache-warming traffic apart from a real client's
activity. Since the production worker runs this every 300 seconds by
default and Tier B's whole purpose is repeatedly re-querying already-
popular names, this would compound over time and, on a quiet
household appliance, likely come to dominate the "top domains"/
per-client dashboard with self-generated noise rather than real usage.

## Fix

`app/v2/tier_b_worker.py`'s `make_udp_resolve_fn` now binds its
UDP socket to a second, dedicated loopback address,
`PREWARM_SOURCE_IP = "127.0.0.2"` (confirmed live: binding and sending
UDP from a non-`.1` address in `127.0.0.0/8` works exactly like
`127.0.0.1` on Linux), instead of leaving the OS to pick the default
`127.0.0.1`. `scripts/v2/alderpointdns_v2_ctl.py`'s
`_query_log_flags_for_client` now recognizes this exact address and
unconditionally excludes it from both the query log and statistics
sinks -- deliberately *not* routed through the normal per-client
policy chain, since this is an architectural invariant (self-generated
traffic is never real client activity), not something an admin's
policy configuration should need to get right.

## Verification

- New regression test:
  `tests/v2/test_ctl_analytics_worker_policy_exclusion.py::test_prewarm_source_ip_is_unconditionally_excluded_from_both_sinks`
  -- proves the exclusion applies with **no** control.db policy state
  seeded for it at all (i.e. it cannot be accidentally left
  permissive by an admin's configuration).
- Existing `tier_b_worker`/`cache_recovery`/`ctl_tier_b_worker_wiring`
  test suites: unaffected, all still passing (127.0.0.2 binding works
  identically in the CI sandbox).
- Full suite: 2073 passed (`tests/`), 881 passed (`tests/v2/`).

## What this does not change

Tier B's own popularity index (`app/v2/tier_b_prewarm.py`'s
`WorkingSetIndex`, tracking which names to prewarm) is unaffected --
it already only records real *client*-driven query popularity via the
analytics pipeline's own separate wiring, not the prewarm worker's own
resolutions. This fix is purely about the *downstream analytics/
statistics* pollution, not a change to what gets prewarmed or why.
