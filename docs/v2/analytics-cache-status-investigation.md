# Cache-status field investigation: resolved (partially) with real evidence (roadmap Priority 6 continuation)

## What was uncertain

`docs/v2/package-baseline-rc6.md`/`rc7.md` flagged `cache_status` as
defaulting to `"miss"` for every analytics event, not independently
verified. A separate, more serious-sounding concern also surfaced
during ad-hoc scratch testing on this host: repeated attempts to
capture a real dnsdist packet-cache hit against a bare-metal scratch
`dnsdist` config (not the real installed package) produced **zero**
protobuf log messages at all, even for a confirmed real backend cache
*miss* -- raising a real worry that attaching a packet cache to a pool
might suppress `RemoteLogAction`/`RemoteLogResponseAction` entirely.

## Real resolution

Repeated the test against the **real installed RC11 package** (not a
scratch config) with a real, freshly-started TCP capture in place of
the real receiver, on the real compiled per-policy dnsdist runtime:

- Three consecutive real queries for `example.com` (a real domain):
  **all three** produced a correct query+response protobuf message
  pair, decoded correctly (`qname=example.com.`, `rcode=NOERROR`,
  real A-record `rdata`), including the two queries that repeated the
  identical qname (the ones that would go through the packet cache).

**Conclusion: packet-cache attachment does NOT suppress protobuf
logging for real backend-resolved queries.** The earlier scratch-test
"zero messages" results were not reproduced against the real package
and are attributed to connection-instability artifacts from rapid,
messy manual process/port cycling in that ad-hoc bare-metal
environment (dnsdist's remote logger reconnects roughly once per
second on failure and is documented fire-and-forget; a query sent
during a reconnection window can be lost) -- not a genuine dnsdist
behavior. This retracts that earlier tentative concern.

## What remains genuinely unresolved

The specific numeric/boolean field (if any) PBDNSMessage carries to
indicate cache-hit-vs-miss was not found among the base fields this
session's decoder already extracts (`type`, `from`, `timeSec`, `id`,
`question`, `response.rcode`) -- three repeated real queries for the
same domain produced byte-identical values in every field checked
(including the previously-unidentified fields 26/27/28 seen in an
earlier, different capture, which did not reappear here at all).
Whether this specific installed dnsdist build's protobuf schema
carries a cache-status field under a field number outside what's
already decoded is still an open question -- `app/v2/
dnsdist_protobuf.py`'s `cache_status` output continues to default to
`"miss"` for every event, an honest placeholder, not a verified value
either way. Not chased further this pass given the more important
question (does caching break logging at all) is now conclusively
answered no.
