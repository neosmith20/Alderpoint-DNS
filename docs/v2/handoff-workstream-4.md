# V2 Workstream 3 — Handoff (deep continuation pass)

**Status:** Substantially expanded, still not exhaustive against the owner's full 54-section brief.
This document now covers two passes: an initial slice (policy engine + staged deployment
abstraction) and a subsequent "deep continuation" pass explicitly instructed not to stop after one
coherent slice. The continuation pass implemented 9 further independently-committed areas (13
checkpoint commits total across both passes) with 431 tests passing (up from 285 at the end of the
first pass, up from 218 at the end of Workstream 2). What follows is the full delivered/not-delivered
breakdown, current as of this document's last update.

## What this document's two passes delivered

| Area | Module | Status |
|---|---|---|
| Unified policy hierarchy | `app/v2/policy_model.py` | Global/network/group/client, deterministic multi-group conflict resolution (priority + group_id tie-break), field validation. |
| Network-scoped matching | `app/v2/network_match.py` | CIDR, most-specific-wins, IPv4+IPv6, no per-query lookup. |
| Schedule evaluation | `app/v2/schedule_policy.py` | DST-safe wall-clock windows, overnight ranges, multi-window OR semantics. |
| Effective policy compiler | `app/v2/policy_compiler.py` | Deterministic, side-effect-free, full explain trace. |
| Cache-profile integration | same module | Non-answer fields never affect the compiled profile; answer-affecting fields always do. |
| Staged deployment abstraction | `app/v2/runtime_staging.py` | Generic stage->validate->promote->health-check->rollback, backend-agnostic. |
| dnsdist config generation | `app/v2/dnsdist_gen.py` | Listeners/ACL/upstream pools/strategies/domain routing/ECS, validated against the real installed dnsdist 2.1.1 binary. |
| **Control.db policy storage** | `app/v2/policy_store.py` | Real relational tables (schema v2) for every policy dimension, no JSON blobs; round-trip proven identical to in-memory fixtures. |
| **Policy preview/explain service** | `app/v2/policy_service.py` | Control.db-backed `compile_effective_policy_from_store` + secret-free structured explanation. |
| **Real BIND/RPZ generation** | `app/v2/bind_rpz_gen.py`, `app/v2/blocking_response.py` | RPZ zone generation validated against the real installed `named-checkzone` binary; explicit-allow-overrides-block precedence; all four blocking response modes rendered (documented RPZ REFUSED limitation). |
| **Real filtering decision logic** | `app/v2/filtering_decision.py`, `app/v2/safesearch.py` | SafeSearch (4 real providers, honest unsupported-provider rejection), parental + malware/service blocking sharing one curated ruleset mechanism, deterministic precedence, diagnostic reason codes. |
| **Upstream profiles + domain routing** | `app/v2/policy_store.py`, `app/v2/dnsdist_gen.py` | Real storage + compilation into dnsdist pools/`SuffixMatchNodeRule`, 3 of 5 requested strategies mapped to verified native dnsdist policies (`parallel_first_success` explicitly rejected as unsupported by the installed version rather than faked). |
| **ECS privacy controls** | `app/v2/ecs_policy.py` | All 3 modes compiled to real dnsdist directives, verified against the real binary. |
| **Real analytics ingestion pipeline** | `app/v2/query_event.py`, `app/v2/analytics_pipeline.py` | One normalized event feeding Parquet + aggregates + Tier B in one place, bounded queue, per-sink failure isolation, query-log/statistics exclusion semantics proven independent. |
| **Analytics query service** | `app/v2/analytics_service.py` | Bounded named methods over both real backends; partition-pruning re-proven through the service layer. |
| **Notification-provider CRUD** | `app/v2/notification_store.py` | control.db metadata + secret-store-backed credentials; plaintext-absence proven via raw on-disk byte inspection, not just API behavior. |
| **Tier B real worker wiring** | `app/v2/tier_b_worker.py` | Real raw-UDP resolve_fn replayed through an actually-running, fully isolated, disposable dnsdist subprocess — genuine end-to-end resolution, not a mock. |
| **Fallback DNS** | `app/v2/fallback_dns.py` | Pure decision logic with an explicit encrypted-to-plaintext downgrade guard. |
| **Failure-domain proofs (new code)** | `tests/v2/test_workstream3_failure_domains.py` | Structural + behavioral proof the compiler/generators have no control.db/secret/analytics dependency. |

**Test totals:** `tests/v2/` grew from 218 (Workstream 2) -> 285 (first pass) -> **431** (continuation
pass, 146 further new tests). V1 regression surface expanded from 8 files/279 tests to **13
files/619 tests**, all passing. Two real bugs were found and fixed while wiring real external
binaries: dnsdist's `--check-config` silently validating the wrong (live default) file without an
explicit `-C`, and dnsdist detaching/orphaning itself as a subprocess without `--supervised`.

## Implementation queue classification (per the continuation brief's §41 requirement)

Classified against the continuation brief's numbered queue (1-38, skipping the meta-instructions):

| # | Item | Status |
|---|---|---|
| 1 | Real control.db policy storage | **DONE** |
| 2 | Policy preview/explainability service | **DONE** |
| 3 | Real BIND/RPZ generation | **DONE** (generation+validation; no reload/rndc wiring, by design — never promotes over live V1) |
| 4A | SafeSearch | **DONE** (4 real providers; honestly narrow, not exhaustive) |
| 4B | Parental/adult blocking | **DONE** (via shared curated-ruleset mechanism) |
| 4C | Malware/phishing | **DONE** (same mechanism, `category="security"` — see `filtering_decision.py` docstring for why this design choice was made instead of a new cache-profile dimension) |
| 4D | Service blocking | **DONE** |
| 5 | Schedule transition runtime | **NOT REACHED** — schedule *evaluation* (Workstream 3 pass 1) and *storage* (this pass) both exist; the recompile-on-transition scheduler itself (detecting "next_transition passed, recompile+restage+revalidate now") was not built this session. Reason: needs a real always-running process/timer loop to drive it, which doesn't fit this session's "isolated test artifacts, no persistent isolated service" scope — building one safely (without it becoming an unauthorized long-running V2 process on the shared host) needs an explicit decision about where that process would live. |
| 6 | Blocking response modes | **DONE** |
| 7 | Upstream profile storage + runtime | **DONE** |
| 8 | Policy-scoped upstream routing | **DONE** (storage + compiler resolve to a profile id; end-to-end EffectivePolicy -> dnsdist pool wiring for network/group/client scoping specifically was proven at the storage/compiler level, not re-demonstrated as a fourth dnsdist-generation integration test — reasonable to treat as covered by items 1+7+9's tests together) |
| 9 | Domain-specific upstream routing | **DONE** |
| 10 | Fallback DNS | **DONE** (pure decision logic + privacy-downgrade guard; not wired to a real health-check signal source, since none exists yet) |
| 11 | Upstream strategies | **PARTIAL** — 3 of 5 requested (ordered/failover/load_balanced) mapped to verified real dnsdist policies; `fastest` and true `parallel_first_success` have no native stock-dnsdist equivalent in 2.1.1 and are explicitly rejected rather than faked. **BLOCKED** for those two specifically: would require custom Lua fan-out logic this session did not have time to write and validate against the real binary. |
| 12 | ECS privacy controls | **DONE** |
| 13 | Real analytics ingestion | **DONE** (pipeline is real and tested; not fed by any live/test DNS traffic source, since none exists yet — same gap as Workstream 2) |
| 14 | Normalized query event | **DONE** |
| 15 | Analytics query service | **DONE** |
| 16 | Query-log/statistics exclusion | **DONE** |
| 17 | Secret store -> notification providers | **DONE** |
| 18 | Secret backup/restore | **NOT REACHED** — Workstream 2's `secret_store.py` already has `export_all`/`import_all` hooks; a *protected* (encrypted-at-rest-in-the-backup-artifact) wrapper around them plus integrity/checksum and atomic-restore-with-rollback was not built this session. Reason: ran out of session budget after 13 checkpoints; this is a self-contained, boundable next task, not architecturally blocked. |
| 19 | Secret replication | **NOT REACHED** — needs the existing V1 replication/mTLS protocol studied and extended, which is a substantial standalone investigation this session didn't reach. Not architecturally blocked, just not started. |
| 20-22 | Real migration stages, preview, failure injection | **NOT REACHED** — each of the ~18 real per-stage migrations listed in §20 is independently substantial (real data conversion against realistic V1 fixtures, not stubs); attempting a shallow pass across all of them was judged worse than not touching migration this session, consistent with "do not replace depth with shallow placeholder scaffolding." Durable state machine (Workstream 2) is unaffected and still correct. |
| 23 | Tier B real worker wiring | **DONE** (via a real isolated dnsdist subprocess — genuine end-to-end proof) |
| 24 | Tier B working-set ranking | **DONE** (Workstream 2's half-life decay scoring; not revisited this session, no new evidence gathered) |
| 25 | dnsdist packet-cache profile-safety | **NOT REACHED** — investigated conceptually in Workstream 2's docs but no prototype built or tested against the real binary this session. |
| 26 | BIND cache reuse | **NOT REACHED** — no BIND recursive-cache instance was stood up this session to test against. |
| 27 | Cache latency layer investigation | **NOT REACHED** — requires a live isolated multi-service (dnsdist+BIND) stack instrumented layer-by-layer; out of this session's budget after the above. |
| 28 | Cache recovery benchmark | **BLOCKED**, unchanged from Workstream 2 — no real DNS cache implementation exists yet to benchmark against. |
| 29 | Tier A decision | **UNCHANGED** — still deferred per Workstream 2's evidence-based recommendation; no new evidence gathered this session (correctly, per the continuation brief's own "do not burn a large fraction of the session forcing Tier A to exist" instruction). |
| 30 | Full concurrent hardware test | **BLOCKED**, unchanged from Workstream 2 — building a second complete constrained-memory V2+V1-equivalent stack (BIND+dnsdist+web/API+analytics+DuckDB+Argon2id all resident under a memory cap) safely isolated from the live shared host is infrastructure-scale work, not a boundable task within this session; doing it against the live host risks resource contention with the real v1.1.1 service, which the continuation brief itself forbids. |
| 31 | V2 memory minimum decision | **UNCHANGED** — 2 GiB evidence-based-not-final recommendation stands; item 30 is its prerequisite. |
| 32 | Argon2id profile | **UNCHANGED** — same reasoning as 31. |
| 33 | Dedicated adversarial security pass | **PARTIAL** — every new module's own test suite includes rejection tests for its specific attack surface (SQL metacharacters via bound params, path traversal in secret/service IDs, symlink rejection, CIDR/schedule edge cases, cache-profile leakage across policies). A *separate, systematic* cross-cutting adversarial pass (the specific checklist in §33) was not run as its own exercise. |
| 34 | Failure-domain pass | **PARTIAL** — `tests/v2/test_workstream3_failure_domains.py` proves the compiler/generators have no control.db/secret/analytics dependency; the fuller checklist (inject failure of each of 8 listed components against a *running* compiled DNS runtime) needs a running runtime, which doesn't exist yet. |
| 35 | Test volume | **DONE** — all `tests/v2/` (431) run and green; V1 regression surface expanded from 8 to 13 files (619 tests, up from 279), all green. |
| 36-38 | HTTPS/client discovery/API/UI | **NOT REACHED** — explicitly lowest priority per the brief's own ordering ("only after the major queue above is substantially completed"); judged that session budget was better spent finishing more of the DNS/policy/analytics/secrets queue above than starting these. |

## Why the session stopped here

Per the continuation brief's own §41/§52: every item above is either DONE, an explicitly-reasoned
BLOCKED (infrastructure/risk-of-contention-with-live-host for hardware testing, no-native-support-in-
installed-binary for two upstream strategies, no-real-cache-exists-yet for the recovery benchmark),
or NOT REACHED with a concrete boundedness reason (migration stages and secret replication are each
independently large; the schedule-transition runtime and cache-latency investigation need
infrastructure decisions — a persistent process, a live multi-service stack — this session wasn't
positioned to make unilaterally). Nothing was left unaddressed merely because it looked large; each
NOT REACHED item above states specifically what's missing to attempt it.

## Recommended next-session priority order

1. Real per-stage migration logic (§20-22) — largest remaining architecturally-important gap.
2. Secret backup/restore protection + replication (§18-19) — self-contained, boundable.
3. Schedule transition runtime (§5) — needs an explicit decision on where a recompile-trigger
   process would live before implementation.
4. Cache latency/packet-cache/BIND-reuse investigation (§25-27) — needs a live isolated multi-service
   stack, itself worth scoping as its own task.
5. Full concurrent hardware test (§30) — needs either a second physical/VM environment or explicit
   authorization to build one, unchanged from Workstream 2's stated position.
6. Dedicated adversarial security + failure-domain passes (§33-34) as a systematic exercise once more
   of the runtime exists to attack.
7. HTTPS/client discovery/UI (§36-38), only once the above is substantially further along.

## Known open risks carried forward unchanged

- 2 GiB hardware minimum recommendation still evidence-based, not final.
- Migration stage logic still entirely stub.
- Tier A still deferred by recommendation.
- Pepper still deferred.
- Test-suite shared-state hang still pre-existing V1 debt, untouched.
- `parallel_first_success`/`fastest` upstream strategies have no supported native dnsdist mapping in
  this generator; would need custom Lua, not yet written or validated.
