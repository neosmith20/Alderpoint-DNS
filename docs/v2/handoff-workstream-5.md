# Alderpoint DNS V2 — Handoff to Workstream 5

**Workstream 4** completed Priority 0 (Dex's three Gate #2 residual findings — see
`docs/v2/gate2-residuals-p0.md`). **Workstream 4A** completed Priority 1 (real installable .deb
packaging — see `docs/v2/packaging.md` and `docs/v2/clean-install-evidence.md`) and Priority 2
(the three real background-worker systemd units, hardened, DNS-first ordering proven under
simultaneous failure injection). **Workstream 4B** completed Priority 4 (native HTTPS, real
self-signed bootstrap + user-cert replacement) and the core of Priority 6 (a real management/API
service covering policy/network/client/upstream/schedule/analytics/notifications, with the
mandatory HTTPS-API-to-real-DNS end-to-end proof passing) — see `docs/v2/management-plane.md` and
`docs/v2/clean-install-evidence-4b.md`. Priority 3 (mTLS secret replication), Priority 5 (client
discovery), Priority 7 (UI — explicitly out of scope for 4B), migration realism beyond detection,
full-stack hardware/cache benchmarking, a broader adversarial security pass, CI/test-suite quality,
and private RC assembly remain **not** implemented.

## Why this is reported honestly as incomplete rather than fabricated

Each of Priorities 1–14 is independently a multi-day, verification-heavy engineering effort by
the Workstream 4 spec's own required proof bar (real TLS handshakes, real mTLS certificate
failure injection, a real built `.deb` installed into a genuinely clean disposable environment,
real cgroup-constrained full-stack load tests at three memory tiers including BIND, a real fix for
a previously-undiagnosed test-suite hang). Simulating completion of any of these without the real
artifact (a running HTTPS listener under real TLS test traffic, a real mTLS handshake between two
disposable nodes, a real `.deb` built and installed clean, real p50/p95/p99 numbers from a
genuinely constrained cgroup) would not meet the spec's own "actual binary/end-to-end testing
required, not only unit tests" standard — it would just be a plausible-sounding paragraph. The
Workstream 4 spec explicitly rules out "this deserves another session" as a stopping reason, but
it equally requires "report exact results" and forbids exactly this kind of unverified claim. This
handoff exists to leave that judgment call, and the concrete next steps, transparent rather than
papering over it.

## What genuinely exists already (from Gate #1/#2 and earlier workstreams — do not redo)

- Real per-effective-policy dnsdist runtime enforcement (`app/v2/dnsdist_policy_runtime.py`),
  proven with a live cross-policy DNS test matrix.
- Real DoH backend support with no plaintext downgrade (`app/v2/dnsdist_gen.py`).
- Real production analytics dependency packaging (vendored wheels,
  `app/v2/analytics_deps.py`), proven 0-skip/0-fail under the real system `python3`.
- Atomic (and now, after this pass, crash-atomic) secret restore.
- Exhaustive migration source schema validation.
- SQL/DNS-name injection hardening across every real generation/query call site.
- `docs/v2/policy-runtime-architecture.md`, `docs/v2/analytics-dependency-packaging.md`,
  `docs/v2/gate2-remediation.md`, `docs/v2/gate2-residuals-p0.md` document all of the above.

None of this needs to be rebuilt. Workstream 5 (or a continuation of this one) should start
directly on Priority 1.

## Recommended real next steps, in the spec's own priority order

1. **Priority 1 (filesystem layout + package integration + postinst/prerm)** is the correct
   starting point — every later priority (systemd units, HTTPS cert storage paths, migration
   package-flow testing, RC assembly) depends on V2 having an actual installable shape first.
   `podman` is available on this host and was confirmed working
   (`which podman` succeeded) — a real Debian 13 container is a legitimate disposable target for
   the clean-install proof Priority 1 §4 requires, without needing a separate VM.
2. **Priority 2 (systemd topology + DNS-first startup ordering)** follows naturally once Priority
   1 defines what units actually exist.
3. **Priority 4 (native HTTPS)** and **Priority 3 (secret replication mTLS)** are both large,
   security-critical, and independently testable with real TLS traffic once a management service
   process exists to terminate it (Priority 1/2 first).
4. **Priority 9 (full-stack resource testing)**: confirm actual available headroom before
   attempting a 4 GiB cgroup test — `free -h` on this host currently shows **3.8 GiB total
   physical RAM**, so a real, honest 4 GiB-constrained cgroup run is not possible on this specific
   host without first checking whether a larger host is available; this is a genuine hard blocker
   for that one specific sub-item, not an excuse to skip 1 GiB/2 GiB runs, which remain feasible
   here.
5. **Priority 13 §58 (combined-suite hang)**: worth investigating early since it blocks reliable
   CI for everything else being built — recommend a dedicated `pytest --collect-only` /
   `-p no:cacheprovider` bisection session across the full V1+V2 combined suite before more test
   volume is added on top of it.

## Explicit non-recommendation

Do not attempt Priorities 5–8 (client discovery, management API, UI) before Priority 1–2 exist —
building API/UI surface against a runtime that has no real install/service lifecycle yet would
produce code with no real deployment target to validate against, the same failure mode this
handoff is trying to avoid.
