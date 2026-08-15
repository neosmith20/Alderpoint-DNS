# V2 Workstream 3 — Handoff (deep continuation + final continuation passes)

**Status:** Three passes recorded in this document: an initial slice (policy engine + staged
deployment), a "deep continuation" pass (control.db storage, BIND/RPZ, filtering, upstream/ECS,
analytics pipeline, notification CRUD, Tier B wiring), and a "final continuation" pass covering
the three self-identified review risks plus Priorities 1-6 of a large mandatory-implementation
queue (real migration, secret backup/restore/replication, schedule runtime, dnsdist cache-profile
integration, cache benchmarking, full concurrent hardware test, Argon2 concurrency protection, and
dedicated adversarial/failure-domain passes). Test count: 218 (Workstream 2) → 285 → 431 → **566**
(24 checkpoint commits total across all three passes on this branch).

## What the final continuation pass delivered

**P0 — three self-identified review risks, all fixed:**
- Parental (adult) and malware/phishing (security) protection are now fully independent
  answer-affecting policy dimensions (`parental_policy_id`/`security_policy_id`, both real
  `CachePolicyDimensions` fields, cache-profile schema bumped v1→v2), independent toggles,
  independent diagnostics, proven by dedicated tests that toggling one never affects the other.
- REFUSED blocking mode now returns a real RCODE REFUSED at the dnsdist layer
  (`RCodeAction(DNSRCode.REFUSED)`), verified end-to-end against the real installed binary (a live
  isolated instance actually returns RCODE 5). RPZ's `rpz-drop` substitute is now explicitly
  documented as defense-in-depth only, never claimed equivalent.
- Domain-routing precedence is now enforced by the generator itself (sorted by specificity,
  deterministic regardless of caller input order, conflicting duplicates rejected), not left to
  caller pre-sorting.
- **Real bug found while fixing this:** a pre-existing schema-migration ordering bug in
  `policy_store.py` (gating on a shared version counter instead of actual table existence) meant
  `policy_store.ensure_schema()` could silently skip creating its own tables if
  `notification_store.ensure_schema()` ran first. Fixed, with a dedicated regression test.

**Priority 1 — real V1→V2 migration (the largest item):** every one of the 13 pipeline stages now
does real work against disposable copies (never the live source): real detection, a transactionally
consistent backup (SQLite's own backup API) with checksum+row-count manifest+integrity-check+a real
disposable-restore proof, a real read-only preview report, real conversions for config/admins
(argon2id hashes reused, unrecognized formats flagged for rehash)/clients+identifiers/network
policies/local DNS/filtering rules/upstream resolvers (real DoT backend syntax, a real bug found and
fixed there)/notification providers+secrets, a legacy-analytics-archive registration that never
bulk-copies raw history, real dnsdist+RPZ+local-zone runtime generation validated against the real
binaries, and a real isolated-instance health check that sends an actual DNS query. Crash/restart
proven at every one of the 13 stage boundaries using the real (not stub) stage logic — this required
fixing a second real gap (the durable-state mechanism only tracked stage-completion bookkeeping, not
stage *outputs*, which real stages now depend on; fixed by making dependent stages re-derive their
inputs from what's already durably on disk). A **third** real gap was found and fixed in this same
pass: stage retry idempotency (§21-22) — several stages had no duplicate-object guard for a genuine
mid-stage-crash-then-retry scenario (as opposed to the boundary-only crashes the earlier tests
covered); fixed for every affected stage with dedicated regression tests.

**Priority 2 — secret backup/restore/replication:** encrypted-at-rest backup/restore
(`cryptography.fernet.Fernet`, an existing audited dependency, not home-grown crypto), restore
proven against a completely separate `SecretStore` instance, wrong-key/tampered-ciphertext both
rejected distinctly. A real partial-restore atomicity bug was found and fixed in
`SecretStore.import_all` itself (two-phase validate-then-write). Replication: authenticated +
encrypted + generation-versioned envelope construction and conflict resolution, proven against
isolated primary/secondary fixtures — **explicitly not** wired to the existing V1 replication
subsystem's real mTLS network transport, stated as a concrete scope boundary (a substantial
existing subsystem, not a missing capability in this module's own logic).

**Priority 3 — schedule transition runtime:** a real state machine (`ScheduleTransitionRuntime`)
that recompiles/stages/validates/promotes only when the active schedule set actually changes, never
trusts persisted state as a restart-time decision input (always recomputes from wall clock),
integration-tested against the real policy compiler + cache-profile compiler + `runtime_staging.py`
pipeline, proving a schedule boundary genuinely changes the compiled cache profile and the staged
config. Deliberately not run as an actual background OS process during testing (would itself be an
unauthorized long-running process on the shared host) — every test uses explicit fake-clock
injection instead.

**Priority 4 — real cache hot path:** documented a real architectural finding (current generators
produce one global config, not yet differentiated per effective cache profile at the BIND layer) and
implemented the safe hybrid strategy the brief itself allows: client-scoped blocking at the dnsdist
layer (terminal actions bypass the packet cache entirely, so BIND's recursive cache stays maximally
shared) plus per-pool `PacketCache` partitioning, verified end-to-end (a real bug found and fixed —
`SpoofAction`'s real argument shape). A real isolated packet-cache latency benchmark measured a ~225x
p50 improvement for a dnsdist-layer cache hit vs. V1's real dnsdist→BIND cached baseline. Tier B
prewarm proven end-to-end through a real isolated dnsdist instance (cold cache has zero fast hits;
prewarmed cache has 100%). Power-loss tested with a real SIGKILL, not graceful shutdown.

**Priority 5 — full concurrent hardware test:** real `systemd-run --scope -p MemoryMax` cgroup caps
(kernel-enforced, protects the live V1 appliance regardless of host free memory) at 1 GiB and 2 GiB,
measuring a real concurrent workload (dnsdist+DNS traffic, Parquet/aggregate writers, Argon2id,
policy compiler) — peak 316 MB at both caps, zero swap. 4 GiB explicitly not attempted with a
concrete measured reason (**this host has 3.8 GiB total physical RAM** — a 4 GiB cap is not
physically meaningful here). Added `HashConcurrencyLimiter` (§38) bounding concurrent Argon2id
operations, wired into `auth_hash.py` as an opt-in parameter.

**Priority 6 — dedicated security/failure passes:** a systematic adversarial test file attacking
Lua/SQL injection surfaces, path traversal, malformed CIDRs, and adversarially-named migration
source tables (no new defects found — every attack was already correctly rejected by existing
validation, now proven directly). A live-runtime failure-domain test keeps one real isolated dnsdist
instance answering DNS while control.db, the Parquet directory, aggregates.db, the secret store, and
a Tier B snapshot are destroyed one at a time in sequence.

## Full implementation-queue classification (per §41)

| Item | Status |
|---|---|
| P0-A parental/malware separation | **DONE** |
| P0-B real RCODE REFUSED | **DONE** |
| P0-C domain-routing precedence | **DONE** |
| 1-4 backup/preview/config/control | **DONE** |
| 5 admin/auth metadata | **DONE** (argon2id reuse; unrecognized formats flagged, not migrated blind) |
| 6-9 clients/policy/local DNS/rewrites | **DONE** (rewrites: CNAME records handled via local DNS zone generation; no separate V1 "rewrite" concept beyond CNAME/local-DNS existed in the source schema examined) |
| 10 filtering/allow/block | **DONE** |
| 11 legacy query history | **DONE** (registered, not bulk-copied) |
| 12 aggregate data | **DONE** (rebuild-strategy recorded; Workstream 2's `rebuild_range_from_reader` is the mechanism, not auto-run) |
| 13 generated V2 runtime | **DONE** |
| 14 health test | **DONE** (real query through the generated runtime; local-DNS/rewrite/allow-override/policy-compile live checks through a *second*, separately-configured isolated BIND were judged out of scope this pass — see cache-hit-latency doc's same stated gap) |
| 15 late commit point | **DONE** |
| 16 migration crash/restart | **DONE**, including the idempotent-retry fix |
| 17-19 secret backup/restore/replication | **DONE** (backup/restore); replication logic **DONE**, network transport **BLOCKED** (concrete reason: requires integrating with the existing V1 mTLS replication subsystem, a substantial distinct piece of work) |
| 20 real migration stages | **DONE** |
| 21 migration preview | **DONE** |
| 22 migration rollback/idempotency | **DONE** |
| 23-24 Tier B wiring/ranking | **DONE** (carried from prior pass + this pass's recovery benchmark) |
| 25 dnsdist packet-cache/profile safety | **DONE** (hybrid strategy; full per-profile BIND-layer differentiation remains a stated architecture gap, not solved) |
| 26 BIND cache sharing | **DONE** (by design: policy-sensitive decisions never reach BIND at all under the hybrid strategy) |
| 27 cache hit benchmark | **PARTIAL** — dnsdist packet-cache layer measured for real; isolated BIND-only layer **NOT REACHED** (concrete reason: building a second full isolated BIND instance was out of this session's remaining budget) |
| 28 cache recovery benchmark | **DONE** (cold vs. Tier B, real isolated instance) |
| 29 Tier A | **UNCHANGED**, deferred, no new evidence gathered (per explicit brief instruction not to force it) |
| 30-33 power-loss/prewarm/recovery | **DONE** |
| 34-36 1/2/4 GiB profiles | **DONE** at 1/2 GiB (real cgroup evidence); 4 GiB **BLOCKED** (concrete reason: host has 3.8 GiB total RAM) |
| 37 hardware decision | **UNCHANGED** (2 GiB recommended minimum stands; new evidence is complementary, doesn't supersede since BIND wasn't in the concurrent measurement) |
| 38 Argon2id decision | **DONE** (concurrency protection added); parameter recommendation **UNCHANGED**, still not final |
| 39 adversarial pass | **DONE** |
| 40 failure-domain pass | **DONE** (live running runtime, not just source inspection) |
| 41 test suite | **DONE** — 566 in `tests/v2/`, V1 regression surface expanded to **27 files / 966 tests**, all green |
| 42 optional roadmap (HTTPS/discovery/API/UI) | **NOT REACHED** — correctly deprioritized per the brief's own explicit ordering ("only after the major queue above is substantially completed"); judged that session budget was better spent completing more of Priorities 1-6 than starting these |

## Known open risks / genuine remaining gaps (all with a stated reason, none silently skipped)

- Secret replication's real network mTLS transport (reuse of `app/replication.py`'s existing
  subsystem) is not built.
- A second, fully isolated BIND recursive resolver (for a true isolated BIND-cache-hit latency
  measurement, and for a fuller migration health-check exercising local DNS/rewrites/allow-overrides
  live) was not stood up this session — same stated budget reason in two different docs.
- 4 GiB hardware profile is untestable on this specific host (3.8 GiB total RAM); remains
  reference/aspirational only, unchanged from Workstream 2.
- Per-effective-cache-profile differentiation at the BIND/RPZ layer remains a real architecture gap
  (documented in `app/v2/dnsdist_cache_policy.py`) — the dnsdist-layer hybrid strategy is a safe
  mitigation, not a full solution to "different clients get different BIND-layer filtering."
- Tier A remains deferred by recommendation, unchanged.
- Pepper remains deferred, unchanged.
- The pre-existing V1 combined-test-suite hang is untouched, unchanged, out of scope per repeated
  instruction across all passes.
- HTTPS/client discovery/broader API/UI: not started, correctly lowest-priority per the brief.
