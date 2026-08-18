# Confirmed real gap: DoH/DoQ/DoH3/DNSCrypt (mandatory parity rows) not implemented in V2 -- ALL FIVE now closed

**Update: this gap is fully closed.** DoT, DoH, DoQ, DoH3, and DNSCrypt
are all implemented -- see `docs/v2/dot-transport-implemented.md`,
`docs/v2/doh-transport-implemented.md`,
`docs/v2/doq-transport-implemented.md`,
`docs/v2/doh3-transport-implemented.md`, and
`docs/v2/dnscrypt-transport-implemented.md`. DoH3's doc also resolves
DoQ's real-target-build QUIC blocker via V1's existing, security-
reviewed opt-in `install-enhanced-dnsdist` mechanism, reused verbatim
for V2. DNSCrypt's own doc covers its distinct provider-identity/
certificate design and a real dnsdist behavior (unreliable one-shot
`-e` key persistence) found and worked around along the way. This doc's
original findings below are retained as the historical record of the
gap as originally found.

**This is the most consequential finding of this continuation session
-- surfaced prominently for Dex's Gate #3 review, not buried among the
smaller analytics fixes.** Found while auditing the mandatory
feature/parity matrix
(`docs/v2/roadmap-reference/v2-adguard-parity-matrix.md`) row by row
against the current V2 codebase.

## What was found

The parity matrix lists both of these as **MANDATORY V2**:

| Capability | V1 Status | V2 Requirement |
|---|---|---|
| DoH / DoT / DoQ / DoH3 | Present where dnsdist supports | Preserve |
| DNSCrypt | Best-effort/current plumbing | Audit, preserve supported behavior |

Confirmed, concrete, exhaustive evidence this is currently a real gap
across **all five** encrypted-transport protocols, not a partial one:

- **V2's real config generators only ever emit one plain listener.**
  Exhaustive grep of `app/v2/dnsdist_gen.py` (bootstrap generator) and
  `app/v2/dnsdist_policy_runtime.py` (the real per-effective-policy
  compiler -- what every live installed package actually runs) for
  every real dnsdist Lua directive that would configure an encrypted
  listener (`addDOHLocal`, `addTLSLocal`, `addDOQLocal`,
  `addDOH3Local`, `addDNSCryptBind`, or any DoH/DoT/DoQ/DNSCrypt
  enabled-flag) returns **zero matches**. The only listener directive
  either module ever emits is `setLocal("{listen_address}")` --
  confirmed as `setLocal("0.0.0.0:53")` in every single real compiled
  config inspected throughout this entire session's live testing
  (RC1 through RC19), with no exceptions.
- **V1 has real, working implementations of all of these.** V1's
  `app/encryption.py`/`app/webapp.py` expose real admin-facing
  enabled/port/cert configuration for DoH, DoT, DoQ, and DNSCrypt
  (confirmed: `doh_enabled`, `dot_enabled`, `doq_enabled`,
  `dnscrypt_enabled` and their associated port/provider settings all
  exist and are wired into V1's real dnsdist startup). V2 dropping all
  of them is a genuine, confirmed feature regression against the
  explicitly mandatory parity requirement, not a documentation gap.
- **The real installed dnsdist 2.1.1 binary supports all five.**
  Confirmed live (`dnsdist --version`):
  `Enabled features: ... dns-over-quic dns-over-http3
  dns-over-tls(gnutls openssl) dns-over-https(nghttp2) dnscrypt ...` --
  this is not blocked by the packaged dnsdist build; the binary is
  fully capable, V2's config generation simply never configures any of
  it.
- **V2's own migration code is aware of the gap.** `app/v2/
  migration_convert.py` records that a V1 install *had* one or more of
  these enabled (for the migration report), but does not configure
  anything equivalent in the migrated V2 install -- an admin migrating
  from a V1 appliance that was actually using DoH/DoT/DNSCrypt would
  silently lose that functionality post-migration with only a report
  line noting it, not a working replacement.

## Why this was not implemented in this pass

This is genuinely new feature surface -- not a small, well-scoped fix
to already-existing, already-designed machinery like every other real
defect found this continuation (analytics field population, Argon2id
concurrency, input validation). Implementing it correctly requires
real design decisions this session has no prior grounding for:

- Real TLS/cert material for DoH/DoT/DoQ listeners: reuse the existing
  management-API server cert, or provision independent certs (likely
  the latter, given DNS-facing and admin-facing trust boundaries
  probably shouldn't share key material) -- not yet decided.
- Whether encrypted-listener configuration is global-only or
  participates in the per-effective-policy compile chain the rest of
  V2's answer-affecting fields go through (likely global/network-level
  only, since a listening port isn't a per-client concept, but this
  needs real design review, not an assumption).
- The real dnsdist 2.1.1 Lua directive names/behavior/required
  parameters for each protocol, verified against this exact version --
  none of this has been empirically confirmed yet the way this
  session's protobuf/replication work was.
- DNSCrypt specifically needs real provider/resolver key generation
  and lifecycle (cert rotation/expiry), a new design surface with no
  V2 precedent to extend (V1's approach used a different integration
  shape -- systemd environment variables to a separate startup helper
  -- not directly portable to V2's generated-Lua-file model).
- Real live verification would need genuine DoH/DoT/DoQ/DNSCrypt
  clients to prove end-to-end resolution over each protocol, not just
  "the config validates" -- a real, nontrivial verification undertaking
  in its own right, matching the rigor every other fix in this session
  received.

Attempting this blind, without that design groundwork, risked landing
an incomplete or unverified feature in a release candidate that is
otherwise being hardened toward Gate #3 review, or consuming the bulk
of remaining session capacity on new feature-building at the expense
of the verification/hardening work this continuation was primarily
asked to prioritize. This is a real engineering judgment call, and is
surfaced explicitly and prominently here rather than silently omitted,
buried, or rushed.

## Recommendation

This should be treated as the top-priority item for the next dedicated
V2 workstream -- a genuine, confirmed, mandatory-parity-matrix gate
criterion currently unmet, larger in scope and impact than any other
finding from this continuation. Recommend: design the
key-storage/policy-integration decisions first (matching the rigor
already applied to native HTTPS admin/replication mTLS in prior
workstreams), implement each protocol incrementally, and live-verify
each with a real client of that protocol against the real installed
package -- the same evidence-based pattern this continuation used for
every other fix.
