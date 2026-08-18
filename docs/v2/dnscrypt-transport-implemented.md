# DNSCrypt implemented -- the last remaining row of the confirmed mandatory encrypted-transport parity gap, real end-to-end verified

Follow-up to `docs/v2/doh3-transport-implemented.md`, same continuation
of `docs/v2/encrypted-transport-parity-gap.md`. DNSCrypt was the one
protocol with no shared design surface with DoT/DoH/DoQ/DoH3 (its own
provider-identity/certificate model, not TLS-based) and was explicitly
deferred pending its own design pass -- this is that pass.

## Why DNSCrypt needed real, from-scratch design work

Unlike DoT/DoH/DoQ/DoH3, DNSCrypt has no shared trust material with the
appliance's management HTTPS certificate. It needs:

- A long-term **provider identity** (an Ed25519 signing keypair) --
  this is the root of trust every client stamp pins against. Rotating
  it invalidates every previously-distributed client configuration.
- A short-term, periodically-reissued **resolver certificate** (signed
  by the provider key, containing an X25519 short-term keypair, a
  serial number, and a validity window) -- this is what a client
  actually fetches and verifies before establishing an encrypted
  session, and what should rotate routinely without touching the
  provider identity.

Both are governed by a real, non-standardized (not an RFC, not X.509)
binary wire format that dnsdist itself defines and verifies.

## Key design decision: generation always goes through the real dnsdist binary

Hand-rolling the DNSCrypt binary formats in Python was considered and
rejected: a byte-offset or signing-scope mistake would produce broken or
insecure crypto that might only be caught by a real client failing a
handshake in production, if at all. dnsdist is the authoritative
implementation (it is also the verifier at query time), so
`app/v2/dnscrypt_provisioning.py` always asks the real installed
`dnsdist` binary to generate the material via its own real
`generateDNSCryptProviderKeys`/`generateDNSCryptCertificate` console
functions -- the same thing an administrator would do by hand from the
dnsdist console, never reimplemented.

## A real, live-reproduced dnsdist behavior worked around

V1's own `app/encryption.py` (`ensure_dnscrypt_provider_keys`) documents
that these functions, invoked via `dnsdist -l ... -e script` (one-shot,
no real console), reliably print a provider fingerprint but do **not**
persist the key files to disk -- and separately notes the live-console
path (`-c ... -e`) is blocked by dnsdist.service's systemd sandboxing in
V1's real deployment. This was independently re-confirmed, live, against
this exact real `dnsdist` binary during this session's design work: the
one-shot `-l addr -e cmd` form prints `"Provider fingerprint is: ..."`
and genuinely writes nothing.

**The actual root cause, found by testing rather than assumed:** issuing
the identical command as a real *interactive console session* -- piped
via stdin to `dnsdist -C <config> -c` against an already-running dnsdist
process with a real `controlSocket`/`setKey` -- reliably writes both
files, every time, including through a full real end-to-end resolution
via a real DNSCrypt client afterward. The most likely explanation:
`-e` disconnects immediately after sending the command rather than
waiting for the server to finish processing it, racing the file write;
a real console session only disconnects once its stdin reaches EOF,
by which point the server's result has already been read back over the
wire. `app/v2/dnscrypt_provisioning.py` therefore always drives
generation through a genuine console session fed via stdin -- never
`-e`, never a bare one-shot `-l` listener.

## Why a disposable scratch dnsdist instance, not the live production one

V2's real compiled runtime (`app/v2/dnsdist_policy_runtime.py`) has no
`controlSocket`/console at all -- confirmed by inspection, and a
deliberate choice: adding a permanent console to the live query-serving
process is real new attack surface (V1 does ship one, loopback-only with
a random key, but V2's policy-runtime architecture had no need for one
until now, and this workstream did not want to add one merely to serve
an infrequent administrative action). Provisioning is a rare, explicit
admin action, not something the hot query path needs, so it gets a
fully disposable, loopback-only, random-console-key, random-port dnsdist
instance that exists only for the fraction of a second this module needs
it and is torn down immediately after -- never reachable from anywhere
but this process, and never overlapping with the live production
dnsdist's own ports (a real bug found and fixed during this same design
pass: omitting `setLocal()` entirely makes dnsdist default to binding
`127.0.0.1:53`, which collided with this host's own real DNS service --
the scratch config now always includes an explicit scratch DNS port with
nothing behind it).

## What was implemented

- **`app/v2/dnscrypt_provisioning.py`**: `generate_provider_keypair()`,
  `generate_resolver_certificate(...)`, `provider_fingerprint(...)` --
  real generation via the scratch-instance mechanism above. Verified
  live: 32-byte Ed25519 public key, 64-byte Ed25519 private key,
  124-byte signed certificate (`DNSC` magic, confirmed byte-for-byte:
  4 magic + 2 esVersion + 2 protocolMinorVersion + 64 signature +
  32 serverPublicKey + 8 clientMagic + 4 serial + 4 ts_start +
  4 ts_end = 124), 32-byte X25519 resolver private key.
- **`dnscrypt_settings` table** (`app/v2/policy_store.py`): a separate
  table from `dns_transport_settings` (the DoT/DoH/DoQ/DoH3 one) since
  the column shape is genuinely different -- secret references
  (`provider_secret_id`/`resolver_secret_id`, real values live in
  `app/v2/secret_store.py`'s protected store, never in control.db
  itself, the same frozen architecture `app/v2/replication_v2.py`'s CA
  signing key already follows) plus non-secret public material
  (`provider_public_key_b64`, `cert_b64` -- the certificate is
  broadcast in plaintext to any client that asks for it, not sensitive).
- **`DnscryptConfig`/`_dnscrypt_bind_lines`**
  (`app/v2/dnsdist_policy_runtime.py`): emits real
  `addDNSCryptBind(address, providerName, certPath, keyPath)`, wrapped
  in the same defensive `alderpointdnsv2SafeCapabilityCall` pattern
  DoQ/DoH3 already use.
- **Real file materialization at every recompile**
  (`app/v2/webapp.py`'s `_materialize_dnscrypt_files`): decodes the
  stored cert bytes and fetches the resolver private key from the
  SecretStore fresh every compile, writing real files
  (`DNSCRYPT_CERT_PATH`/`DNSCRYPT_KEY_PATH`) dnsdist can read --
  matching how DoT/DoH/DoQ/DoH3 already materialize
  `ACTIVE_CERT_PATH`/`ACTIVE_KEY_PATH`. Fails safe (no listener emitted,
  not a crash) if the referenced secret is missing/corrupt.
- **API** (`app/v2/webapp.py`):
  - `GET /api/dns-transports` gains `dnscrypt_enabled`, `dnscrypt_port`,
    `dnscrypt_provider_name`, `dnscrypt_identity_provisioned`,
    `dnscrypt_fingerprint`, `dnscrypt_cert_serial`,
    `dnscrypt_cert_valid_until`.
  - `PUT /api/dns-transports` gains the same enabled/port/provider_name
    fields. **Enabling DNSCrypt before a provider identity has ever
    been issued is rejected with `409 dnscrypt_not_provisioned`**,
    directing the admin to the rotate endpoint first -- a deliberate
    guard matching this workstream's established posture for
    consequential crypto/trust actions (`app/dnsdist_upgrade.py`'s own
    "never automatic" `install-enhanced-dnsdist` design): generating a
    new root-of-trust identity is never a side effect of a checkbox
    toggle.
  - `POST /api/dns-transports/dnscrypt/rotate` (`{rotate_provider:
    bool}`, default `false`): issues a fresh resolver certificate under
    the existing provider identity (the routine action -- e.g. renewing
    an expiring cert) unless `rotate_provider: true` or no identity
    exists yet, in which case a brand-new provider identity is
    generated first (which invalidates every previously-pinned client's
    stamp -- always an explicit, deliberate admin action, never
    automatic). Old secret material is deleted only after the new
    reference is durably recorded.
  - Port-conflict validation (`_validate_dns_transport_ports`) treats
    DNSCrypt's port like DoT/DoH's TCP set (dnsdist's real
    `addDNSCryptBind` binds both UDP and TCP on the same port) *and*
    checks it against the appliance's reserved ports -- the same
    conservative-by-default posture RC21's real live port-conflict
    incident established.

## Verification

- **`tests/v2/test_dnscrypt_provisioning.py`**: every test drives the
  real installed `dnsdist` binary (no mocks -- DNSCrypt generation IS
  dnsdist itself; there is no meaningful way to test it without testing
  the real thing). Covers correct key/cert sizes, two calls producing
  genuinely different keys, the real serial byte offset, validation
  failures, and a full real `dnsdist --check-config` pass against
  generated material.
- **`tests/v2/test_dnsdist_policy_runtime.py`**: real `addDNSCryptBind`
  Lua emission + real `dnsdist --check-config` against real generated
  cert/key material, listener correctly omitted when disabled.
- **`tests/v2/test_policy_store.py`**: schema round-trip, the
  `identity_provisioned` gate requiring all three fields, incremental-
  migration coverage for a pre-existing install.
- **`tests/v2/test_webapp.py`** (`TestDnscrypt`, 10 tests): the full
  real HTTP flow -- unprovisioned state reported correctly; enabling
  before provisioning rejected `409`; `rotate` generates a real
  identity+cert and the fingerprint round-trips through `GET`; enabling
  after provisioning emits a real `addDNSCryptBind` with real
  materialized files (`DNSC` magic confirmed on disk); a routine rotate
  keeps the same fingerprint but bumps the serial; an explicit provider
  rotation changes the fingerprint and restarts the serial sequence;
  port-conflict rejection; disabling removes the listener from the next
  compile; auth/CSRF enforcement.

## Backup/restore and migration -- covered for free, no new code needed

- **Secrets**: `provider_secret_id`/`resolver_secret_id` are ordinary
  entries in `app/v2/secret_store.py`'s store, already covered by its
  existing generic `export_all`/`import_all` (used by
  `/api/secret-backups`) -- no DNSCrypt-specific backup/restore code
  needed.
- **`dnscrypt_settings` table**: lives in `control.db`, backed up by
  the existing whole-file `shutil.copy2` control.db backup mechanism
  (`app/v2/migration.py`) -- again, no new code needed.
- **V1 migration**: `app/v2/migration_convert.py` already recorded V1's
  `dnscrypt_enabled` flag (alongside DoH/DoT/DoH3/DoQ) in the migration
  report as `"migrated": False` with an explicit warning -- this was
  already true before this pass for all five protocols uniformly (none
  auto-migrate V1 settings), and remains the deliberate, already-
  reviewed scope decision; not changed here.

## What remains open

None -- this closes the last row of the confirmed mandatory
encrypted-transport parity gap
(`docs/v2/encrypted-transport-parity-gap.md`). Still owed before this
can be called fully proven on the exact shipped package: a clean-room
install of the next RC onto a fresh Debian 13 target with a real
DNSCrypt client (`dnscrypt-proxy`, the reference implementation) proving
genuine end-to-end resolution through the packaged runtime with normal
Alderpoint policy/routing active -- tracked as the next step of this
workstream (see the RC package-baseline doc for that RC's real result).
