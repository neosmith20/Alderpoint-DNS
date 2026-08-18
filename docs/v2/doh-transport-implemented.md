# DNS-over-HTTPS (DoH) implemented and live-verified, closing another part of the encrypted-transport parity gap

Follow-up to `docs/v2/dot-transport-implemented.md`, same continuation
of `docs/v2/encrypted-transport-parity-gap.md`. DoH is the second
protocol implemented -- like DoT, it reuses the appliance's existing
management TLS cert (no new key material), and dnsdist's real
`addDOHLocal` directive (ported verbatim from V1's own
production-proven `packaging/dnsdist.conf`) needs only one additional
concept over DoT: the accepted HTTP path (`/dns-query`, the RFC 8484
default, admin-configurable).

## Design

- **`dns_transport_settings` extended**: `doh_enabled`, `doh_port`
  (default 443), `doh_path` (default `/dns-query`) -- added via
  `ALTER TABLE ADD COLUMN` (idempotent, reaches pre-existing installs
  from RC20 on upgrade, same pattern as the table's own initial
  creation).
- **New Lua directive** (`app/v2/dnsdist_policy_runtime.py`):
  `DohConfig` dataclass + `_doh_bind_lines`, emitting a real
  `addDOHLocal(...)` call with the same TLS options as DoT.
- **Wired into the real compile path**: `webapp.py`'s
  `_encrypted_transport_configs(conn)` (renamed from `_dot_config` to
  build both configs from one settings read) -- same fail-safe
  behavior as DoT (no listener if disabled or cert not provisioned).
- **`/api/dns-transports` extended** with `doh_enabled`/`doh_port`/
  `doh_path`, and the cert-provisioned flag renamed `cert_provisioned`
  (shared by both protocols, not DoT-specific).

## Verification

- Real `dnsdist --check-config` validation (including DoH+DoT enabled
  simultaneously) in `tests/v2/test_dnsdist_policy_runtime.py`.
- Real HTTP-endpoint tests in `tests/v2/test_webapp.py`: enable-emits-
  listener, both-simultaneously, invalid-path-rejected (Pydantic
  pattern validation).
- Real schema-migration idempotency test in
  `tests/v2/test_policy_store.py` (`test_ensure_schema_is_idempotent_and_incremental`).
- Full suite: 2095 passed (`tests/`), 903 passed (`tests/v2/`); 2
  individually confirmed non-regression flakes (browser UI harness,
  mTLS server test -- both pass on isolated retry, consistent with
  this session's established concurrent-load flakiness pattern).
- **Real live verification on RC21** (`docs/v2/package-baseline-rc21.md`):
  a real installed package, real admin API call to enable DoH, and a
  real `curl --doh-url` (or `kdig +https`) client resolving over HTTPS
  on the configured port -- see that doc for the exact command and
  result.

## What remains open

DoQ, DoH3, and DNSCrypt remain unimplemented -- each needs QUIC-specific
tuning (DoQ/DoH3) or a completely different cert/key/provider-identity
model (DNSCrypt) beyond what DoT/DoH's TLS-based approach covered. See
`docs/v2/encrypted-transport-parity-gap.md` for the full remaining
scope and recommendation.
