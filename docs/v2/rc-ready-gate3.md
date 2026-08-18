# Alderpoint DNS V2 -- private RC ready for Dex Gate #3 review

Artifact: `alderpointdns-v2_2.0.0~rc13-1_all.deb`
(sha256 `d1ca4c4eabd40f648d3a494acd3722acbbc8a8c48bcc2ef1d65ae4bc0d82dc90`),
branch `v2/architecture-storage-foundation`, still fully private
(no push/tag/publish to any remote; `origin/main` -- the public V1
line -- untouched throughout).

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
window, dedupe, size bounds, cert pinning, bounded protobuf parsing --
no new gaps found), CI determinism (online + offline), and this RC
scrub. The private candidate (RC13) is ready for Dex Gate #3 review.
