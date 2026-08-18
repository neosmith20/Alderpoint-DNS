# Alderpoint DNS V2 -- private RC ready for Dex Gate #3 review

Artifact: `alderpointdns-v2_2.0.0~rc16-1_all.deb`
(sha256 `05bb0f7df4eda4603aa0a067d83d0f50b249b7f5826b66a34c32f953a818ecf8`),
branch `v2/architecture-storage-foundation`, still fully private
(no push/tag/publish to any remote; `origin/main` -- the public V1
line -- untouched throughout).

## What RC16 fixes over RC15 (roadmap continuation, "keep going")

1. **`docs/v2/cache-profile-id-not-populated-fix.md`** (real defect
   found and fixed): `cache_profile_id` -- a real filterable/sortable
   query-log column -- was always blank for every real dnsdist-sourced
   analytics event, even though the exact policy compile needed to
   produce it was already happening one function call away. Fixed by
   threading `compile_cache_profile(policy).profile_id` through the
   same per-client policy resolution already used for
   `query_log_enabled`/`statistics_enabled`. Live-verified on RC16
   (`docs/v2/package-baseline-rc16.md`): a real query through the real
   installed package now shows a real, non-blank compiled profile
   digest via the real `GET /api/analytics/query-log` API. Also
   surfaced (not a regression, documented transparently, not fixed
   this pass) that the raw per-query log buffers up to 1 hour before
   flushing to disk by design -- the aggregate statistics dashboard is
   unaffected and updates within seconds.

## What RC15 fixes over RC14

1. **`docs/v2/prewarm-analytics-pollution-fix.md`** (real defect found
   and fixed): Tier B prewarm's self-generated re-queries of
   already-popular domains replayed through the live DNS path from
   client `127.0.0.1`, indistinguishable from real client traffic --
   live-proven on a real installed RC14 package: a single manual
   prewarm tick pushed `total_queries` from 1 to 2 with no way to tell
   the two apart. Fixed by sourcing prewarm traffic from a dedicated
   loopback address and unconditionally excluding it from both
   analytics sinks (not via the normal per-client policy chain, since
   this is an architectural invariant). Live-verified on RC15
   (`docs/v2/package-baseline-rc15.md`): a real prewarm tick now
   leaves `total_queries` unchanged.

## What RC14 fixes over RC13

1. **`docs/v2/ipv6-client-decode-rc13.md`**: closed the last
   "not independently verified" gap from RC6 -- the protobuf decoder's
   IPv6 client-address branch, live-verified against a real
   `dig -6 @::1` query through the real installed package
   (`"client":"::1"` decoded correctly end to end).
2. **`docs/v2/cache-hit-response-not-logged-rc13.md`** (real defect
   found and fixed): dnsdist packet-cache hits never emit a
   `RemoteLogResponseAction` message at all, live-proven with a real,
   repeated NXDOMAIN query -- the receiver's fallback silently
   mislabeled every real cache hit as `NOERROR`/`"miss"`, an accuracy
   defect that would corrupt statistics for the majority of real
   repeat-domain traffic. Fixed with a bounded best-effort
   `(qname, qtype) -> real rcode` memory; live-verified on RC14
   (`docs/v2/package-baseline-rc14.md`): a real 1-miss/2-hit query
   sequence now correctly shows `cache_hits=2, cache_misses=1` and
   `rcode=NXDOMAIN` for all three in the real aggregate database,
   instead of all three being silently counted as NOERROR misses.

## What RC13 fixes over RC12 (this continuation session)

1. **`docs/v2/package-baseline-rc12.md`**: `remote_node_id` on
   `POST /api/replication/issue-peer-cert` hardened with an explicit
   format pattern (defense-in-depth against path-traversal-shaped
   input reaching a real X.509 cert CN); live-verified 422 rejection
   against the real installed package.
2. **`docs/v2/hardware-performance-matrix-rc12.md`**: full 1/2/4 GiB
   hardware matrix re-verified against RC12 with real analytics
   logging active (previously only spot-checked at 2 GiB) -- flat
   ~104k QPS / ~0.9ms across all three tiers, no OOM, zero restarts.
3. **`docs/v2/argon2id-concurrency-defect-and-rc13-fix.md`** (real
   defect found and fixed this session): `/api/login`'s Argon2id
   verify call was structurally unable to engage the appliance's own
   `HashConcurrencyLimiter` (`verify_and_maybe_rehash` had no
   `limiter` parameter at all). Real concurrent-login load against a
   real installed RC12 package measured ~349s per request instead of
   a clean 503 -- the exact DoS shape the limiter exists to prevent,
   open on the one endpoint that most needs it. Fixed in
   `app/v2/auth_hash.py`/`app/v2/webapp.py`, regression-tested at both
   the library and HTTP-endpoint level, and re-verified live on RC13:
   3 concurrent logins now succeed (~3.8s under real contention), the
   rest fast-reject with `503 auth_busy` in ~30ms.
4. **`docs/v2/tierb-and-failure-domain-rc13.md`**: Tier B popularity
   tracking and the analytics-receiver failure-domain independence
   both re-confirmed against the current (post-fix) artifact.

## Cumulative state (this session + prior context)

- Real dnsdist protobuf remote-logging ingestion built, reverse-
  engineered from scratch, and wired into the actual DNS data path
  (previously entirely unpopulated).
- Real cross-node mTLS replication trust (CA-key persistence,
  cross-issuance peer cert enrollment, independent incoming/outgoing
  fingerprint pinning) fixed and live-verified.
- Real V1->V2 migration filter-rule bug (dead-table read) fixed.
- Full local test suite: 2066 passed (offline/`unshare --net` re-run:
  2045 passed / 21 skipped, 1 flake confirmed non-regression on
  isolated retry -- consistent with this session's established
  concurrent-load flakiness pattern, not new).
- RC scrub: no TODO/FIXME/debug leftovers in `app/v2`/`scripts/v2`,
  clean working tree, correct private branch, no secrets committed
  (grep hits on "PRIVATE KEY" are redaction regexes/test fixtures
  with dummy keys, verified by inspection), 25 commits ahead of local
  `main` / 325 ahead of `origin/main`, nothing pushed.

## Conclusion

All roadmap items from this continuation's open list are addressed:
package baseline, full hardware/performance matrix, Argon2id
full-stack validation (found and fixed a real defect), Tier B
re-check, failure-domain re-check, adversarial security re-sweep of
the replication/analytics-receiver attack surfaces (message replay
window, dedupe, size bounds, cert pinning, bounded protobuf parsing),
IPv6 client-decode verification, and three further real analytics-
accuracy defects found and fixed (packet-cache-hit mislabeling,
prewarm-traffic pollution, blank cache_profile_id), CI determinism
(online + offline), and this RC scrub. Full suite: 2074 passed
(`tests/`), 882 passed (`tests/v2/`), all remaining failures
individually confirmed as pre-existing concurrent-load flakes that
pass in isolation, not regressions. The private candidate (RC16) is
ready for Dex Gate #3 review.
