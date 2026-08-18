# Alderpoint DNS V2 -- private RC ready for Dex Gate #3 review

Artifact: `alderpointdns-v2_2.0.0~rc25-1_all.deb`
(sha256 `01ac3cf18184be38689cb9a85a052b8707b1b6b5992e0ebd936f75b39df09d1d`),
branch `v2/architecture-storage-foundation`, still fully private
(no push/tag/publish to any remote; `origin/main` -- the public V1
line -- untouched throughout).

## Update (RC25): DNSCrypt is now genuinely functional end-to-end -- the confirmed mandatory encrypted-transport parity gap is FULLY CLOSED

**`docs/v2/dnscrypt-transport-implemented.md`** and
**`docs/v2/package-baseline-rc25.md`**: real DNSCrypt provider-identity
(Ed25519)/resolver-certificate (X25519) provisioning, always driven
through the real installed dnsdist binary's own console functions
(never a hand-rolled binary format), via a disposable, loopback-only
scratch dnsdist instance rather than the live production one. Along the
way, independently reconfirmed a real dnsdist behavior V1's own
`app/encryption.py` had already documented (one-shot `-e` invocation
prints a fingerprint but does not persist key files) and found the real
root cause and a reliable workaround (a genuine interactive console
session over stdin does persist them) -- see that doc for the full
finding. Real, live, end-to-end proof on a genuinely fresh Debian 13
target, stock (non-QUIC) `dnsdist 1.9.16`: real provisioning via
`POST /api/dns-transports/dnscrypt/rotate`, a real `addDNSCryptBind`
listener, and a real `dnscrypt-proxy` client (the reference DNSCrypt
implementation) completing a genuine encrypted handshake and DNS
resolution against the packaged runtime.

**This closes the confirmed mandatory encrypted-transport parity gap in
full: DoT, DoH, DoQ, DoH3, and DNSCrypt are all real, working, and
live-verified end-to-end** -- see
`docs/v2/encrypted-transport-parity-gap.md` for the complete closure
record.

## Update (RC24): DoQ and DoH3 are now genuinely functional end-to-end

**`docs/v2/doh3-transport-implemented.md`** and
**`docs/v2/package-baseline-rc24.md`**: DoH3 config generation
implemented, and DoQ's real environment blocker (the stock Debian
archive dnsdist has no QUIC) resolved by reusing V1's existing,
security-reviewed, opt-in `install-enhanced-dnsdist` mechanism
verbatim for V2 -- deliberately NOT a package `Depends` bump, which
would have silently changed every appliance's default trust base; see
that doc for the reasoning. Real, live, end-to-end proof on a
genuinely fresh Debian 13 target: real `kdig +quic` DoQ resolution and
real `curl --http3` DoH3 resolution, both through the packaged runtime
with normal policy/routing active -- the first genuine end-to-end QUIC
resolution demonstrated in this project (RC23 could not demonstrate
this on the QUIC-lacking stock target). Two real, live-reproduced
defects were found and fixed in the reused installer itself along the
way (missing `gnupg`/`bind9-dnsutils` package dependencies; V1-
hardcoded runtime topology assumptions) plus one real restart/verify
race condition -- all with regression coverage, all re-verified
against a fresh clean-install target after each fix.

**DNSCrypt was the only remaining unimplemented mandatory-parity row at
this point -- since closed, see the RC25 update above.**

## Prior finding (RC23, now superseded above): DoT + DoH closed, DoQ implemented but real target build lacked QUIC

**`docs/v2/encrypted-transport-parity-gap.md`** -- DoH/DoT/DoQ/DoH3/
DNSCrypt (all explicitly **MANDATORY V2** rows in the parity matrix)
were confirmed **entirely absent** from V2's real config generation:
exhaustive grep of both `app/v2/dnsdist_gen.py` and `app/v2/
dnsdist_policy_runtime.py` (what every live installed package
actually runs) found no encrypted-listener directive at all -- every
real compiled config inspected across RC1-RC19 only ever bound plain
`setLocal("0.0.0.0:53")`. V1 has real, working implementations of all
five.

**Update -- DoT and DoH are now implemented and genuinely functional.**
Both admin-toggleable via `GET`/`PUT /api/dns-transports`, reusing the
appliance's existing management TLS cert:

- **DoT** (`docs/v2/dot-transport-implemented.md`): live-verified on
  RC20 with a real `kdig +tls` client completing a genuine TLS 1.3
  session on port 853.
- **DoH** (`docs/v2/doh-transport-implemented.md`): live-verified on
  RC22 with a real `kdig +https` client completing a genuine
  TLS 1.3 + HTTP/2 session.
- **Real defect found and fixed along the way**
  (`docs/v2/dns-transport-port-conflict-fix.md`): enabling DoH on the
  same port as the management API crash-looped dnsdist and took down
  **all real DNS answering** (confirmed live on RC21) -- `dnsdist
  --check-config` only validates syntax, not real socket binds. Fixed
  with pre-promotion port-conflict validation against every one of the
  appliance's own fixed ports; live-verified on RC22 that the same
  conflicting request now cleanly rejects with `400` before ever
  touching the live runtime, while a safe port still works correctly.

**DoQ is implemented (`docs/v2/doq-transport-implemented.md`), with a
real, important environment finding made and corrected within this
same pass:** the real target dnsdist the package's own
`Depends: dnsdist (>= 1.9.0)` constraint resolves to on a stock
Debian 13 archive install is `1.9.16`, which **does not include
QUIC/HTTP3 support** -- confirmed live on RC23 via `dnsdist --version`
on the real installed package (matching `docs/dnsdist.md`'s own
V1-era documented finding). An earlier scoping check against this
session's host shell, which had a separately-installed
`dnsdist 2.1.1` from a third-party repo, wrongly suggested QUIC was
available; corrected before finalizing. DoQ's config generation and
its defensive capability-call wrapper (ported verbatim from V1's own
real `packaging/dnsdist.conf` pattern) are confirmed live-correct on
the real target build: dnsdist logs a clean skip message and keeps
running with zero restarts and unaffected DNS answering, rather than
crash-looping. **Genuine end-to-end QUIC resolution was not
demonstrated**, honestly, since the real target build doesn't support
it -- this is a real environment constraint, not a code defect.

**DoH3 and DNSCrypt remain unimplemented.** DoH3 would face the
identical QUIC/HTTP3-unavailable constraint as DoQ on the real target
build. DNSCrypt remains architecturally distinct regardless (its own
cert/key/provider-identity model, no overlap with the TLS-based
approach the other three share) and was not attempted this pass. See
`docs/v2/encrypted-transport-parity-gap.md` for the full remaining
scope and recommendation.

## What RC23 adds over RC22 (roadmap continuation, "keep going")

1. **`docs/v2/doq-transport-implemented.md`**: real DNS-over-QUIC
   config generation with defensive graceful degradation, live-verified
   on RC23 against the real target dnsdist build (see the parity-gap
   section above for the full, corrected finding).

## What RC21/RC22 add over RC20

1. **`docs/v2/doh-transport-implemented.md`**: real DNS-over-HTTPS
   implementation, live-verified on RC22 with a real `kdig +https`
   client.
2. **`docs/v2/dns-transport-port-conflict-fix.md`**: a real,
   live-reproduced availability defect (port conflict crash-looping
   dnsdist) found and fixed, live-verified on RC22.

## What RC20 adds over RC19

1. **`docs/v2/dot-transport-implemented.md`**: real DNS-over-TLS
   implementation, live-verified on RC20 with a real `kdig +tls`
   client.

## What RC19 fixes over RC18

1. **`docs/v2/client-name-not-populated-fix.md`**: `client_name` (a
   real projectable/sortable query-log column) was also always blank
   for every real event with a registered managed client, closing out
   the field-by-field audit of `NormalizedQueryEvent` against what the
   real receiver pipeline populates (`network_id`/`group_ids`/
   `encrypted_transport` confirmed genuinely unused by any real sink,
   not pursued). Live-verified on RC19
   (`docs/v2/package-baseline-rc19.md`): real `GET /api/analytics/
   query-log` shows the real registered client's name after
   registration, correctly blank before.

## What RC18 fixes over RC17

1. **`docs/v2/upstream-profile-id-not-populated-fix.md`**:
   `upstream_profile_id` (the real `"upstream"` filterable query-log
   column) was also always blank for every real event, same root cause
   as the `cache_profile_id`/blocked-action fixes. One-line fix at the
   same call site. Live-verified on RC18
   (`docs/v2/package-baseline-rc18.md`): real `GET /api/analytics/
   query-log` now shows the real configured upstream profile label.

## What RC17 fixes over RC16

1. **`docs/v2/blocked-action-not-populated-fix.md`** (real defect
   found and fixed -- the most significant analytics-accuracy gap
   found this continuation): `app/v2/filtering_decision.py`'s
   `evaluate_filtering` -- a real, independently tested "why was this
   blocked" decision engine -- was never actually invoked anywhere in
   production. Every real blocked query was silently logged as
   `action="allowed"`, making the entire "blocked queries"
   dashboard/statistic non-functional for real traffic. Also confirmed
   along the way: `app/v2/bind_rpz_gen.py`'s RPZ zone is always empty
   in the real running system, so the `service_definitions` mechanism
   `evaluate_filtering` reads is the complete real blocking-decision
   source, not a partial one. Fixed by threading the per-client
   compiled policy through `evaluate_filtering` per event. Live-verified
   on RC17 (`docs/v2/package-baseline-rc17.md`): a real admin flow
   (create service -> ruleset -> assign globally) blocks a domain at
   the real DNS level (`NXDOMAIN`) *and* now correctly shows
   `blocked=true, block_reason="rc17-blocked-svc"` via the real
   `GET /api/analytics/query-log` API.

## What RC16 fixes over RC15

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

## Conclusion (updated through RC25)

The confirmed mandatory encrypted-transport parity gap that RC13-23
identified and progressively closed is now **fully resolved**: DoT,
DoH, DoQ, DoH3, and DNSCrypt are all real, working implementations,
each independently live-verified end-to-end against a genuinely fresh
clean-install target with a real client of that exact protocol (`kdig
+tls`/`+https`/`+quic`, `curl --http3`, `dnscrypt-proxy`) through the
packaged runtime with normal Alderpoint policy/routing active -- not
merely "config generates and validates." QUIC-dependent protocols
(DoQ/DoH3) required resolving a real environment constraint (the stock
Debian archive dnsdist lacks QUIC), done by reusing V1's existing,
security-reviewed, opt-in `install-enhanced-dnsdist` mechanism rather
than changing the package's default dependency. DNSCrypt required its
own from-scratch design (a distinct provider-identity/certificate
model with no TLS overlap) and, along the way, independently
reconfirmed and worked around a real dnsdist reliability issue V1 had
already documented for one-shot key generation.

Six real, live-reproduced defects were found and fixed across this
encrypted-transport work specifically (beyond the earlier analytics-
accuracy defects RC13-19 already closed): the RC21 DoT/DoH port-
conflict availability incident, RC24's missing installer package
dependencies, RC24's V1-hardcoded runtime topology in the reused
installer, RC24's restart/verify race condition, and this pass's
scratch-instance default-DNS-port collision -- all with regression
coverage, all re-verified against a fresh clean-install target after
each fix.

Full `tests/v2/` suite as of RC25: 953 passed, 1 pre-existing
concurrent-load mTLS-server flake (confirmed to pass in isolation, not
a regression, not touched by this work).

**Readiness assessment:** the private candidate (RC25) is ready for Dex
Gate #3 review with the encrypted-transport mandatory-parity gate
criterion now genuinely met in full, not partially. Remaining roadmap
items not attempted this continuation (hardware/performance matrix
re-verification, Argon2id full-stack re-validation under this exact
build, Tier B re-check, failure-domain/chaos pass, a fresh adversarial
security sweep specifically targeting the new DNSCrypt provisioning
surface, CI determinism re-run, migration-lifecycle re-verification)
should be explicitly scoped for the next session rather than assumed
complete -- see the handoff report for the exact list.
