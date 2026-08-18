# RC14 clean-install acceptance + live verification of the cache-hit analytics fix

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc14-1_all.deb`
(sha256 `e67bc0189b18efff8a752b272c14af0aa648dc155ce1a196540f45c4ce0ccfb7`).

## What RC14 fixes over RC13

`docs/v2/cache-hit-response-not-logged-rc13.md`: dnsdist packet-cache
hits never produce a `RemoteLogResponseAction` message at all, so the
analytics receiver's fallback assumption (every unmatched query is a
terminally-spoofed NOERROR answer) silently mislabeled every real
cache-hit's rcode and `cache_status`. Fixed with a bounded
`(qname, qtype) -> real rcode` memory populated from real responses.

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login + a real `/api/local-dns` mutation to
  trigger the real per-effective-policy compiler -- confirmed
  `newPacketCache(...)`/`getPool():setCache(...)` present in the live
  compiled dnsdist config (a real packet cache genuinely attached, not
  the bootstrap-only config).
- Real `dig` for a real NXDOMAIN-answering name, 3 times in a row
  (1 cold miss + 2 real cache hits), through the real installed
  package's full real pipeline (dnsdist -> analytics-protobuf-receiver
  -> inbox -> analytics-worker -> aggregate SQLite).
- Real aggregate query results:
  - `time_buckets`: `total_queries=3, cache_hits=2, cache_misses=1` --
    the 2 cache hits are now correctly counted as hits for the first
    time (previously always counted as misses).
  - `dimension_counts` (dimension=rcode): `NXDOMAIN: 3` -- all three
    queries, including both cache hits, now carry the real rcode
    instead of the two hits being silently miscounted as NOERROR.

## Conclusion

The fix is confirmed live and correct against the real installed
package's real aggregate analytics output, not just at the unit-test
level. Container torn down after verification.
