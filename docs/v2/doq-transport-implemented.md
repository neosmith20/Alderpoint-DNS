# DNS-over-QUIC (DoQ) implemented, with real live-verified graceful degradation on the real target dnsdist build

Follow-up to `docs/v2/doh-transport-implemented.md`, same continuation
of `docs/v2/encrypted-transport-parity-gap.md`.

**Important correction made during this same pass, before finalizing:**
initial scoping checked `dnsdist --version` on this session's host
shell and found QUIC support present (`dnsdist 2.1.1`, from a
PowerDNS-maintained third-party repo installed earlier in this
session for ad-hoc testing convenience) and proceeded on that basis.
Live verification against a *real clean-install target* (RC23, a
fresh `apt-get install` resolving the package's real
`Depends: dnsdist (>= 1.9.0)` constraint against the stock Debian 13
archive) found the real target build is **`dnsdist 1.9.16`, without
QUIC** -- exactly what `docs/dnsdist.md` already documented from V1's
own real-world experience ("installs cleanly from Debian 13's own
archive... does not include DNS-over-QUIC or DNS-over-HTTP/3"). The
host's separately-installed 2.1.1 was never representative of what
this package actually ships to a real user. This is corrected here
rather than left as an inaccurate claim.

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
  a real installed package (the real target build, `dnsdist 1.9.16`,
  confirmed via `dnsdist --version` to genuinely lack QUIC), real
  admin API call to enable DoQ -- and the real, intended graceful-
  degradation path fired exactly as designed: dnsdist's own journal
  logged `"DoQ (addDOQLocal) failed on this dnsdist build (... DNS
  over QUIC support is not present!); skipping."`, zero restarts, DNS
  answering completely unaffected. A real `kdig +quic` client
  correctly failed to connect (no QUIC listener bound, as expected --
  not a crash, not a hang). **Genuine end-to-end QUIC resolution was
  NOT demonstrated** in this pass, since the real target dnsdist build
  doesn't support it; what's verified is that DoQ config generation
  never crash-loops or degrades the appliance when the target build
  lacks the capability, on precisely the real target build this
  package actually ships to.

## What remains open

DoH3 and DNSCrypt remain unimplemented. DoH3 would follow the same
code-shape pattern as DoQ (same cert reuse, V1's own proven
`addDOH3Local` syntax, the same defensive capability wrapper) but --
per the correction above -- the real target dnsdist build (Debian
13's own archive, `1.9.16`) lacks QUIC/HTTP3 entirely, same as it
lacks DoQ, so DoH3 would face an identical "implements cleanly,
degrades gracefully, but doesn't actually work end-to-end on the real
target build" outcome without a genuinely QUIC-capable dnsdist build
to test against. DNSCrypt remains the one genuinely different case
regardless of that constraint -- its own cert/key format and
provider-identity model has no overlap with the TLS-based approach
DoT/DoH/DoQ all share. See `docs/v2/encrypted-transport-parity-gap.md`
for the full remaining
scope and recommendation.
