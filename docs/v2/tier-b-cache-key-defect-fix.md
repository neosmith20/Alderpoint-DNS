# Real defect found and fixed: Tier B prewarm's own query shape never matched real clients' dnsdist cache key

Roadmap continuation: re-verifying Tier B cold-start vs prewarm behavior
(`app/v2/tier_b_prewarm.py`/`app/v2/tier_b_worker.py`) against a real
dnsdist instance with a real packet cache -- comparing cold cache vs
prewarmed cache-hit progression using dnsdist's own real `cache-hits`
counter, not inferred from latency.

## What was found

Tier B's entire purpose is: "after restart, the planner replays the
hottest recent names through the normal resolution path... so a real
client's first query after restart is already a cache hit." Testing
this directly -- prewarm a name via the real `resolve_fn`
(`app/v2/tier_b_worker.py`'s `make_udp_resolve_fn`), then send a real
client query (`dig`) for the same name, and check dnsdist's own
`cache-hits`/`cache-misses` counters (`dumpStats()` via the real
console) -- the prewarmed entry was **never** reused. Every single
prewarm-then-real-client-query sequence tested (multiple domains, both
success and NXDOMAIN cases, both loopback source addresses used in
production) counted as two real cache **misses**, never a hit.

Exhaustively narrowed down through live, repeated, controlled
reproduction (packet content, source IP, EDNS presence, DNS Cookie
presence, and header flags were each isolated and tested independently
against dnsdist's real cache-hits counter): dnsdist's real packet
cache key is sensitive to **both** the query's AD (Authenticated Data)
flag and EDNS0 presence. `_build_query()` (`app/v2/tier_b_worker.py`)
always sent `flags=0x0100` (RD only, AD=0) with **no EDNS0 OPT record
at all** -- a query shape essentially no real modern DNS client
actually sends. Confirmed directly: real `dig` (BIND's, the tool used
throughout this entire session) sets `AD=1` and includes EDNS0 by
default (`dig @... +qr` shows `flags: rd ad` plus an OPT pseudosection,
even with `+noedns` alone the AD bit remains set).

**Practical effect**: every prewarmed cache entry was inserted under a
cache key that typical real client traffic could never match, making
Tier B's prewarm mechanism **silently ineffective** for the large
majority of real-world client query shapes -- despite `run_prewarm()`
correctly reporting `succeeded` throughout (the resolves themselves
genuinely succeeded and returned correct answers; they just weren't
reusable by anything afterward). This is exactly the kind of defect
this roadmap's "prove it with a real client, not just that the resolve
succeeded" standard exists to catch.

## What was NOT the cause (ruled out by direct live testing, not assumed)

- **Packet content/correctness**: the hand-built packet was verified
  byte-identical to `dnspython`'s own `make_query()` output (modulo
  the query ID, which dnsdist ignores for cache-key purposes).
- **Prewarm's dedicated source address** (`PREWARM_SOURCE_IP =
  "127.0.0.2"`, RC15's own fix keeping prewarm traffic out of
  analytics): tested explicitly with and without it -- made no
  difference to cache-key compatibility either way.
- **Response truncation**: the real response received was small (well
  under any UDP size limit) with the TC bit clear.
- **DNS Cookies** (RFC 7873, sent by `dig` by default): confirmed
  separately that a cookie-bearing query never reuses cache regardless
  of any other fix -- this is dnsdist behaving *correctly* (a cached
  response cannot correctly echo back a fresh per-query cookie) and
  not something to "fix," and not representative of typical stub-
  resolver client traffic in practice (DNS Cookies are primarily a
  resolver-to-resolver protection mechanism, not commonly sent by
  default by phone/laptop/IoT OS stub resolvers).

## Fix

`_build_query()` now sets `AD=1` (matching the confirmed-working
real-client shape) and includes a minimal EDNS0 OPT record (UDP
payload size 1232, no options -- deliberately no Cookie, for the
reason above). Live-verified, repeatedly, on fresh domains: a real
`dig +nocookie` query (the realistic modern-stub-resolver shape) now
correctly reuses a prewarmed entry, confirmed via dnsdist's own real
`cache-hits` counter incrementing.

## Regression coverage

`tests/v2/test_tier_b_worker.py::TestPrewarmedEntriesAreActuallyReusedByRealClients::test_prewarmed_entry_is_a_real_cache_hit_for_a_realistic_client_query`
-- spins up a real, disposable dnsdist instance with a real packet
cache, prewarms a real domain through the real `resolve_fn`, sends a
real `dig +nocookie` query for the same name, and asserts dnsdist's
own real `cache-hits` counter is at least 1 (not inferred from
latency or from `run_prewarm`'s own self-reported success, which was
never the part that was broken).

Full `tests/v2/test_tier_b_worker.py` + `test_tier_b_prewarm.py`: 28
passed, no regressions.

**A second, independent confirmation surfaced by the fix itself**: the
pre-existing `tests/v2/test_cache_recovery.py` had its own
latency-based cache-hit probe (`_query_is_fast`), which -- before this
fix -- hand-built a query using the *exact same* `flags=0x0100`/no-EDNS
shape the old, broken `_build_query()` used. That symmetry meant the
probe happened to agree with prewarm's cache key by construction, not
because real client traffic would actually see a hit -- a false
positive that had been masking this defect the whole time. Applying
this fix (with the probe still using the old hand-rolled shape)
immediately turned `test_prewarm_before_traffic_gives_immediate_hits`
and `test_recovery_comparison_cold_vs_prewarmed` into real, honest
failures (`assert hits_warm > hits_cold` -> `0 > 0`) -- independent,
unplanned confirmation that the defect was real and that these two
tests had never actually been checking real-client compatibility.
Fixed by having `_query_is_fast()` reuse the real, now-fixed
`_build_query()` instead of a second, independently-drifting
hand-rolled packet (already externally validated as real-client-
representative by the `dig`-based test above, so this isn't
reintroducing the same blind-symmetry problem). All 7 tests in that
file now pass, including both previously-failing ones.

## What this does not cover

This pass focused specifically on proving/fixing real cache-key
compatibility between prewarm and real client traffic -- the actual
gap this investigation surfaced. It did not repeat the full
cold-start-vs-prewarm throughput/CPU/RAM comparison, or the Tier B
state corruption/kill-resilience check (`load()`'s cold-start-on-
corruption fallback), both still open from the original roadmap ask
for this item -- `load()`'s corrupt-state-degrades-safely contract
already has direct unit coverage in `tests/v2/test_tier_b_prewarm.py`
(unaffected by this fix, confirmed via the full-file re-run above),
but a live kill/corrupt-under-real-load demonstration was not repeated
this pass.
