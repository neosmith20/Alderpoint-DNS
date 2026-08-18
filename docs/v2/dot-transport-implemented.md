# DNS-over-TLS (DoT) implemented and live-verified, closing part of the encrypted-transport parity gap

Follow-up to `docs/v2/encrypted-transport-parity-gap.md`. DoT was
chosen first among the five missing protocols (DoH/DoT/DoQ/DoH3/
DNSCrypt) because it needed no new key material (reuses the
appliance's existing management TLS cert, exactly like V1's own real,
production-proven `packaging/dnsdist.conf` does) and no HTTP/QUIC
protocol surface -- the lowest-risk of the five to add safely within
this continuation.

## Design

- **New settings table** (`app/v2/policy_store.py`):
  `dns_transport_settings`, a singleton row (`dot_enabled`, `dot_port`,
  default port 853) -- deliberately *not* folded into `policy_layers`,
  since a listening port is an appliance-wide concept, not a
  per-client/per-network answer-affecting policy dimension. Created via
  a new `_ensure_dns_transport_settings_table` helper that runs
  unconditionally on every `ensure_schema` call (not gated on the
  existing one-shot `_MIGRATION_V2` check), so it reaches pre-existing
  installs on upgrade, not only fresh ones -- same incremental-migration
  pattern `app/v2/replication_v2.py`'s `ensure_schema` already
  established for the same reason.
- **New Lua directive** (`app/v2/dnsdist_policy_runtime.py`):
  `DotConfig` dataclass + `_dot_bind_lines`, emitting a real
  `addTLSLocal(...)` call with `minTLSVersion="tls1.2"`/
  `ciphers="HIGH:!aNULL:!MD5:!RC4"` -- V1's own real, already-deployed
  values verbatim, ported from `packaging/dnsdist.conf`'s
  production-proven syntax, not new choices made here.
- **Wired into the real compile path**
  (`app/v2/runtime_compile.py`/`app/v2/webapp.py`): `_dot_config(conn)`
  builds the config from the real admin setting + the appliance's
  existing `ACTIVE_CERT_PATH`/`ACTIVE_KEY_PATH`, returning `None`
  (no listener emitted, fails safe) when disabled or when the cert
  isn't provisioned yet.
- **New admin API**: `GET`/`PUT /api/dns-transports`
  (`dot_enabled`, `dot_port`, and a read-only `dot_cert_provisioned`
  flag).

## Verification

- Real `dnsdist --check-config` validation with a real self-signed
  cert in `tests/v2/test_dnsdist_policy_runtime.py`.
- Real HTTP-endpoint tests in `tests/v2/test_webapp.py`
  (`TestDnsTransports`): defaults, fails-safe-without-cert,
  enable-emits-listener, disable-removes-listener, auth-required.
- Full suite: 2085 passed (`tests/`), 893 passed (`tests/v2/`), no
  flakes.
- **Real live verification on RC20** (`docs/v2/package-baseline-rc20.md`):
  a real installed package, real admin API call to enable DoT, and a
  real `kdig +tls` client resolving `example.com` over a genuine
  **TLS 1.3** session on port 853 -- `NOERROR`, both real A records
  returned, ~24ms. Confirmed disabling removes the listener
  (`ss -tlnp` no longer shows port 853 bound) with plain UDP/TCP DNS
  unaffected throughout.

## What remains open

DoH, DoQ, DoH3, and DNSCrypt remain unimplemented -- each needs
real, protocol-specific design work (HTTP path config for DoH, QUIC
congestion-control tuning for DoQ, a completely different cert/key
format and provider-identity model for DNSCrypt) beyond what DoT's
straightforward TLS-wrap-of-plain-DNS needed. See
`docs/v2/encrypted-transport-parity-gap.md` for the full remaining
scope and recommendation.
