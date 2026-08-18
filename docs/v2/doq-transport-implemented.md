# DNS-over-QUIC (DoQ) implemented and live-verified, closing a third part of the encrypted-transport parity gap

Follow-up to `docs/v2/doh-transport-implemented.md`, same continuation
of `docs/v2/encrypted-transport-parity-gap.md`. Confirmed this exact
real installed dnsdist build has QUIC support compiled in
(`dnsdist --version` lists `dns-over-quic`) and `kdig` supports
`+quic`, making DoQ tractable within this same continuation rather
than deferred with DoH3/DNSCrypt.

## Design

- **`dns_transport_settings` extended**: `doq_enabled`, `doq_port`
  (default 853 -- deliberately the same numeric default as DoT: real,
  standard DNS practice per RFC 9250, since DoQ (UDP) and DoT (TCP)
  occupy separate transport namespaces and do not actually collide).
- **New Lua directive** (`app/v2/dnsdist_policy_runtime.py`):
  `DoqConfig` + `_doq_bind_lines`, emitting `addDOQLocal(...)`.
  Unlike `addTLSLocal`/`addDOHLocal`, dnsdist's real `addDOQLocal`
  takes plain cert/key path strings, not single-element tables --
  verified against V1's own real `packaging/dnsdist.conf` syntax, not
  guessed.
- **Defensive capability wrapper**: unlike DoT/DoH (supported since
  early dnsdist releases), QUIC is a newer, optional build feature --
  not present in every distro's packaged dnsdist (V1's own real,
  hands-on finding: the stock Debian archive build lacks it). Ported
  V1's exact `alderpointdnsSafeCapabilityCall` pcall-wrapper pattern
  verbatim (as `alderpointdnsv2SafeCapabilityCall`) so a build without
  QUIC support prints a skip message and validates cleanly instead of
  crashing config startup.
- **Port-conflict validation refined**: `app/v2/webapp.py`'s
  `_validate_dns_transport_ports` now distinguishes TCP-bound
  listeners (DoT, DoH -- checked pairwise against each other for a
  literal same-port conflict) from DoQ's UDP binding (only checked
  against this appliance's own reserved ports and the plain DNS
  listener, never against DoT/DoH -- since a real TCP/UDP collision on
  the same port number never actually happens).

## Verification

- Real `dnsdist --check-config` validation (including all three of
  DoT+DoH+DoQ enabled simultaneously) in
  `tests/v2/test_dnsdist_policy_runtime.py`.
- Real HTTP-endpoint tests in `tests/v2/test_webapp.py`: enable-emits-
  listener, DoT+DoQ sharing port 853 (must NOT be rejected -- the real
  standard convention), DoQ-vs-reserved-port conflict rejected.
- Full suite: 2106 passed (`tests/`), 914 passed (`tests/v2/`), no
  flakes this pass.
- **Real live verification on RC23** (`docs/v2/package-baseline-rc23.md`):
  a real installed package, real admin API call to enable DoQ, and a
  real `kdig +quic` client resolving over a genuine QUIC session --
  see that doc for the exact command and result.

## What remains open

DoH3 and DNSCrypt remain unimplemented. DoH3 would very likely follow
the same low-risk pattern as DoQ (same QUIC-transport capability
already confirmed present, same cert reuse, V1's own proven
`addDOH3Local` syntax already known) but was not attempted this pass
purely due to session-time budgeting, not because it's architecturally
harder than DoQ. DNSCrypt remains the one genuinely different case --
its own cert/key format and provider-identity model has no overlap
with the TLS-based approach DoT/DoH/DoQ all share. See
`docs/v2/encrypted-transport-parity-gap.md` for the full remaining
scope and recommendation.
