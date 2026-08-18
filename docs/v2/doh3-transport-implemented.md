# DNS-over-HTTP/3 (DoH3) implemented, plus a real, safe, maintainable path to genuine QUIC functionality for DoQ+DoH3 alike

Follow-up to `docs/v2/doq-transport-implemented.md`, same continuation
of `docs/v2/encrypted-transport-parity-gap.md`. This closes the last
QUIC-dependent row of the confirmed mandatory-parity gap (DoH3), and
separately resolves DoQ's real-target-build blocker that
`docs/v2/doq-transport-implemented.md` left open.

## Part 1: DoH3 config generation

Same code shape as DoQ, deliberately -- no new design decisions needed:

- **`dns_transport_settings` extended**: `doh3_enabled`, `doh3_port`
  (default 443 -- same numeric default as DoH, since DoH3 is the HTTP/3
  transport of the same protocol and real clients discover it via the
  DoH listener's own Alt-Svc header, below).
- **New Lua directive** (`app/v2/dnsdist_policy_runtime.py`):
  `Doh3Config` + `_doh3_bind_lines`, emitting `addDOH3Local(address,
  certPath, keyPath)` -- plain path strings like `addDOQLocal`, not
  single-element tables like `addTLSLocal`/`addDOHLocal` (verified
  against V1's own real `packaging/dnsdist.conf` syntax).
- **Same defensive capability wrapper as DoQ**: DoH3 shares QUIC's
  build-dependency, so it reuses the identical
  `alderpointdnsv2SafeCapabilityCall` pcall wrapper -- a build without
  QUIC prints a skip message and validates cleanly instead of crashing.
- **Alt-Svc advertisement, ported verbatim from V1**: when DoH3 is
  enabled alongside plain DoH, the DoH listener's own response now
  carries `customResponseHeaders={["alt-svc"]='h3=":<port>"; ma=86400'}`
  (RFC 7838) so real HTTP/1.1 or HTTP/2 DoH clients can discover and
  upgrade to HTTP/3 -- exactly V1's real, production-proven
  `packaging/dnsdist.conf` "doh-altsvc" managed block, not reinvented.
  Confirmed absent when DoH3 is disabled (would otherwise advertise a
  UDP port nothing is listening on).
- **Port-conflict validation extended**: DoH3 is QUIC/UDP-transported
  like DoQ (despite the "HTTPS" name) -- checked only against this
  appliance's own reserved ports and the plain DNS listener, never
  against DoT/DoH's TCP-only pairwise conflict set, and may legitimately
  share a numeric port with DoQ.
- **Real capability reporting added to `GET /api/dns-transports`**:
  `dnsdist_version`, `doq_supported`, `doh3_supported`,
  `dnscrypt_supported` -- reuses `app.dnsdist_upgrade
  .dnsdist_capabilities()` (the same `dnsdist --version` feature-list
  parser V1's own `install-enhanced-dnsdist` command already uses)
  rather than a second implementation, so the admin UI can show *why* a
  toggled-on protocol isn't actually answering queries on a build that
  lacks it, independent of whether the toggle itself is accepted.

## Part 2: DoQ's real environment blocker, resolved

`docs/v2/doq-transport-implemented.md` left DoQ real-functionally
blocked: the package's `Depends: dnsdist (>= 1.9.0)` constraint
resolves to the stock Debian 13 archive build (`1.9.16`), which has no
QUIC support at all -- confirmed live on RC23. This session evaluated
the safe, maintainable paths to a genuinely QUIC-capable dnsdist without
weakening the appliance's supply chain, and found **V1 had already
solved this exact problem**, deliberately and with real security review
(`app/dnsdist_upgrade.py`'s own module docstring): an **opt-in,
root-only `install-enhanced-dnsdist` command** that adds the official
PowerDNS project's own `trixie-dnsdist-21` apt repository (not a random
third party), pinned to a specific, independently-verified signing-key
fingerprint (`EXPECTED_KEY_FINGERPRINT`), with APT pinning
(`Pin-Priority: 600`) so `dnsdist*` packages specifically prefer that
repo while everything else stays on the Debian archive. Deliberately
**never invoked automatically** -- not from postinst, not from the
unprivileged web process (which has no APT/sudo access at all) -- only
through the explicit CLI command, so no appliance's trust base changes
without an administrator's explicit action.

**This is reused verbatim for V2, not reimplemented**: `app/
dnsdist_upgrade.py` has no V1 app/web-code dependency (confirmed by
inspection -- its own imports are all stdlib) and is shipped as the one
deliberate exception to V2's "only `app/v2/` ships" packaging rule (see
`docs/v2/packaging.md`, `scripts/build-v2-deb.sh`). V2 gets its own
entry points:

- `alderpointdns-v2-ctl install-enhanced-dnsdist` -- same real,
  fail-closed installer (network-failure/wrong-key/apt-candidate
  checks, idempotent re-run, individually-reversible steps) as V1's CLI
  command of the same name, just re-parented under V2's own control
  script.
- `alderpointdns-v2-ctl dnsdist-capabilities` -- reports the installed
  dnsdist version, origin, and per-protocol support, matching V1's own
  command output shape.
- `GET /api/dns-transports`'s new `doq_supported`/`doh3_supported`/
  `dnscrypt_supported`/`dnsdist_version` fields (Part 1, above).

**Why this, and not a package `Depends` bump.** Changing V2's own
`Depends:` to require the PowerDNS-repo build directly was considered
and rejected: it would silently change every V2 appliance's default
trust base (patch/CVE cadence moving from Debian security's team to
PowerDNS's own release schedule and signing key) with no admin action
required, which is exactly the blast-radius V1's own deliberate
opt-in design was built to avoid. The opt-in path gets every appliance
the exact same real, working QUIC capability on request, with the
decision left where it belongs -- explicit administrator action, not a
default baked into the package.

## Verification

- Real `dnsdist --check-config` validation (DoH3 alone, DoH3+DoQ+DoT+DoH
  all four simultaneously, and the Alt-Svc header present/absent
  correctly) in `tests/v2/test_dnsdist_policy_runtime.py` -- run against
  this session's real dnsdist build.
- Real HTTP-endpoint tests in `tests/v2/test_webapp.py`: enable-emits-
  listener, DoH3+DoQ sharing a port (must NOT be rejected), DoH3-vs-
  reserved-port conflict rejected, Alt-Svc header appears in the
  compiled config exactly when both DoH and DoH3 are enabled, real
  capability fields present on `GET /api/dns-transports`.
- **Real, live capability confirmation**: this session's dev/build host
  already has the official PowerDNS `trixie-dnsdist-21` repository
  configured and `dnsdist 2.1.1` installed (pre-existing, not added by
  this pass) -- `alderpointdns-v2-ctl dnsdist-capabilities` against it
  reports genuine `DoH/DoT/DoQ/DoH3/DNSCrypt: supported` across the
  board, live-run and captured verbatim:

  ```
  dnsdist version: dnsdist 2.1.1 (Lua 5.1.4 [LuaJIT 2.1.1737090214])
  source/origin:   500 http://repo.powerdns.com/debian trixie-dnsdist-21/main amd64 Packages
  DoH      : supported
  DoT      : supported
  DoQ      : supported
  DoH3     : supported
  DNSCrypt : supported
  ```

- **Update -- the full clean-install proof is now done**, see
  `docs/v2/package-baseline-rc24.md`: a genuinely fresh Debian 13
  target (stock `dnsdist 1.9.16`, no QUIC), real `install-enhanced-
  dnsdist` run against it (not a pre-configured host), real `kdig
  +quic` DoQ resolution (`QUIC session (QUICv1)-(TLS1.3)-...`, real
  `NOERROR` answer) and real `curl --http3` DoH3 resolution (`HTTP/3
  200`, real `application/dns-message` answer bytes) through the
  packaged runtime with normal Alderpoint policy/runtime active, plus
  real Alt-Svc discovery. Two real, live-reproduced defects were found
  and fixed along the way in the reused installer itself (missing
  `gnupg`/`bind9-dnsutils` package deps; V1-hardcoded runtime topology)
  and one real restart/verify race condition -- see that doc for full
  detail and regression coverage.

## What remains open

DNSCrypt remains the one genuinely different case: its own cert/key
format and provider-identity model has no overlap with the TLS/QUIC-
based approach DoT/DoH/DoQ/DoH3 all share, and was not attempted this
pass. See `docs/v2/encrypted-transport-parity-gap.md` for the full
remaining scope.
