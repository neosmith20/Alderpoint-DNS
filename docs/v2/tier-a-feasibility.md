# Tier A (Safe Direct Cache Restore) — Feasibility Assessment (Workstream 2, §26-27)

**Status:** Recommendation: **defer Tier A, ship Tier B only for V2's initial release.**
Correctness logic is proven feasible as a pure function (`app/v2/tier_a_feasibility.py`, 16 passing
adversarial tests) — the *mechanism* works. The recommendation to defer is about measured benefit
vs. complexity/risk, not about whether it can be built correctly.

## What was proven

`evaluate_restore()` implements the full validity-decision contract from
`docs/v2/architecture-map.md`'s "DNS cache architecture" section as a pure function with no I/O:

- **TTL never resets on reboot** — proven structurally, not just by a runtime check:
  `CachedAnswerRecord` has no `ttl`/`original_ttl` field at all, only `absolute_expiration_ts`.
  Remaining TTL is always `absolute_expiration_ts - now`. Test: an entry cached with 300s TTL,
  restored 260s later, gets exactly ~40s remaining, not 300s. Exactly-at-expiration is rejected
  outright rather than restored with a 0s or negative TTL.
- **DNSSEC validity gates restoration** — `secure`/`insecure` (both are provably-checked outcomes)
  are trustworthy; `bogus`/`unknown` are rejected. Uncertainty fails closed.
- **Every context dimension is checked independently** — effective cache profile, resolver/upstream
  profile, domain-routing context, and ECS context each have their own rejection reason, so a
  mismatch in any one of them alone is enough to refuse restoration, and a caller/log can see
  exactly which one failed rather than a single opaque "invalid" result.
- **Negative caching (NXDOMAIN/NODATA) follows the same rules** — no special-cased shortcut that
  would let a negative entry bypass validity checks a positive entry has to pass.
- **Every rejection path returns no TTL** — a rejected decision can never be accidentally treated as
  "restorable but with 0 seconds left" by a careless caller.

## Why the recommendation is "defer," not "reject" or "ship it"

**Not "reject":** nothing found here shows Tier A is *unsafe* to build — the correctness contract is
implementable and testable, and the validity-decision function above is small, pure, and easy to
review/audit (roughly 100 lines, no external dependencies).

**Not "ship it" for V2's initial release**, for reasons the brief itself anticipated (§27):

1. **Measured benefit is unknown.** The cache-recovery benchmark gate (§29,
   `docs/v2/architecture-map.md` "Cache recovery benchmark gate") — comparing pure cold cache vs.
   Tier B vs. Tier A+B hybrid on real time-to-recovery numbers — was not run this session (it
   requires a working DNS cache implementation to benchmark against, which doesn't exist yet; this
   workstream built the storage/policy/state foundations, not the runtime cache itself). Without
   that number, there's no evidence Tier A meaningfully beats Tier B alone on recovery speed.
2. **Complexity is real, not hypothetical, once wired to actual BIND/dnsdist state.** The pure
   function proven here assumes a caller can already accurately produce
   `dnssec_state`/`resolver_upstream_profile_id`/`domain_routing_context_id`/`ecs_context` for every
   cached entry, captured at cache-write time, and reliably persisted alongside the answer. That's
   additional per-entry metadata the DNS hot path would need to capture and persist synchronously
   enough to be trustworthy at restart, which works against the "no synchronous disk dependency on
   the hot path" invariant unless done carefully (batched/async, same as Tier B's own persistence) —
   solvable, but it's real added surface area, not a rounding error.
2a. Getting DNSSEC validity classification *exactly* right at persist-time (not re-derived at
   restore-time, since re-deriving would defeat the point of "direct" restore) is the single
   highest-risk piece: a classification bug here means silently serving a stale/invalid signed
   answer, which is a worse failure mode than Tier B's "slightly slower cold start."
3. **Tier B alone already satisfies the mandatory baseline requirement** and has none of the above
   risk — it always re-resolves through the normal path, so it can never serve a stale or
   incorrectly-validated answer by construction. The only cost of Tier B-only is a slightly slower
   walk back to full cache effectiveness after a restart, which is bounded and rate-limited by
   design (`app/v2/tier_b_prewarm.py`).

## Recommendation

Ship **Tier B only** for V2's initial release. Keep the `app/v2/tier_a_feasibility.py` module as
proven-but-unused groundwork — if a future workstream runs the cache-recovery benchmark gate and
finds Tier B's cold-start cost is a real operational problem (not just theoretically slower), the
validity-decision logic to build Tier A on top of is already written and tested; wiring it to real
BIND/dnsdist cache-write/restore hooks would be the remaining work, not re-deriving the correctness
rules. This is the explicitly acceptable outcome §27 anticipated: "If Tier A cannot be proven safe
and worthwhile: recommend shipping Tier B only. That is an acceptable V2 architecture outcome."

## What would change this recommendation

- A Workstream 3+ cache-recovery benchmark showing Tier B's cold-start walk-back time is materially
  worse than acceptable for real deployments (e.g. minutes rather than seconds to reach 90% working
  set effectiveness).
- A concrete, reviewed design for capturing DNSSEC state and context metadata at cache-write time
  without adding synchronous hot-path cost.
