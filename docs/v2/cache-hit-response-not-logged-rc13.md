# Real defect found and fixed: packet-cache hits never produce a response message, mis-logged as NOERROR

Roadmap continuation: investigating the still-open `cache_status`
gap flagged since RC6 (`docs/v2/package-baseline-rc6.md`) and the
"resolved" conclusion in
`docs/v2/analytics-cache-status-investigation.md` (which claimed 3
repeated real queries all produced correct query+response pairs).
Re-tested more rigorously against a real installed RC13 package with
the real per-effective-policy compiler's packet cache actually
attached (`newPacketCache`/`getPool():setCache()`) -- the earlier
"resolved" test had, by luck of the default clean-install config,
never actually exercised a real packet cache at all (no cache profile
is compiled until an admin makes a real policy change; the earlier
test's "no suppression" finding was correct for *that* config, just
not representative of a cache actually being active).

## What was found

With a real packet cache attached and a raw TCP sniffer replacing the
analytics receiver (to see dnsdist's exact wire behavior directly),
three real identical queries for the same qname/qtype through the real
installed package showed:

- Query 1 (cold, real cache miss): full query+response pair logged
  correctly.
- Query 2 and 3 (real cache hits): only the query-side message
  (`RemoteLogAction`) arrived. **No response message ever arrived**,
  confirmed with a real, generous 25-second wait -- `dnsdist` 2.1.1
  does not invoke `RemoteLogResponseAction` for a packet-cache hit,
  the same real behavior already known for terminally-spoofed queries
  (`SpoofAction`/local DNS), just previously not known to also apply
  to cache hits.

**Concrete proof of real impact:** repeated the test with a real
NXDOMAIN-answering name. The real matched response correctly logged
`rcode=NXDOMAIN`. The two subsequent real cache-hit queries for the
exact same name produced only a bare query message -- which the
receiver's existing `_event_from_unmatched_query` fallback
unconditionally treated as a terminally-spoofed answer and logged as
`rcode=NOERROR`. **This is a real, silent analytics-accuracy defect**:
any cached non-NOERROR answer (NXDOMAIN, SERVFAIL, etc.) served from
the packet cache would be mislabeled as a successful NOERROR answer in
every dashboard/statistic that reads this field, and every cache hit
(likely the majority of real-world repeat-domain traffic) was already
being silently counted as `cache_status: "miss"` since the receiver
never had a way to know otherwise.

## Fix

`scripts/v2/alderpointdns_v2_ctl.py`'s `cmd_analytics_protobuf_receiver`
now keeps a small, bounded, best-effort `(qname, qtype) -> (rcode,
insert time)` memory (`_QNAME_RCODE_CACHE_MAX=4096` entries,
`_QNAME_RCODE_CACHE_TTL_SECONDS=3600`), populated every time a real
`RemoteLogResponseAction` message is decoded. `_event_from_unmatched_query`
now checks this memory before falling back to the old NOERROR
assumption: if a real answer for the exact same `(qname, qtype)` was
seen recently, that real rcode is reused and the event is honestly
marked `cache_status: "hit"`. This is not a perfect mirror of dnsdist's
own packet-cache TTL/eviction (no such signal is available over this
protocol), but it is strictly more accurate than the previous
unconditional NOERROR/`"miss"` default, and degrades safely to the
original (still-correct for genuinely first-seen terminally-spoofed
queries) behavior when no prior answer is known.

## Verification

- New real-bytes regression fixtures pinned in
  `tests/v2/test_dnsdist_protobuf.py` (`REAL_NXDOMAIN_QUERY_HEX`,
  `REAL_NXDOMAIN_RESPONSE_HEX`, `REAL_CACHE_HIT_QUERY_ONLY_HEX`) from
  this exact live capture.
- New tests in `tests/v2/test_ctl_analytics_protobuf_receiver.py`:
  `test_cache_hit_query_with_no_response_reuses_real_remembered_rcode`
  (the fix) and
  `test_unmatched_query_for_a_never_before_seen_qname_still_falls_back_to_noerror`
  (no regression on the original correct case).
- Full suite: 2072 passed (`tests/`), 879 passed (`tests/v2/`, 1
  confirmed non-regression flake on the browser UI harness, passes in
  isolation).

## What remains honestly unresolved

This is a heuristic, not a perfect recovery of dnsdist's internal
cache state -- a cache hit for a `(qname, qtype)` never seen answered
in this receiver process's own lifetime (e.g. right after a service
restart, before any cold miss has been observed) still falls back to
the old NOERROR assumption, silently wrong if the real cached answer
is non-NOERROR. Finding the actual PBDNSMessage field (if one exists)
that carries real cache-hit status/rcode directly remains genuinely
unresolved, same as documented since RC6 -- this fix meaningfully
narrows, but does not close, that original gap.
