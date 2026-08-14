# Clients & Access

Persistent named clients, strong ClientIDs, and DNS-level allow/deny policy,
enforced at dnsdist before a query ever reaches BIND.

## Persistent clients

A client is a stable, named record (`Living Room TV`) that can own several
identifiers instead of needing a separate client per device/protocol:

- exact IPv4 or IPv6 address
- IPv4 or IPv6 CIDR (normalized via Python's `ipaddress`; `192.168.32.1/24`
  canonicalizes to `192.168.32.0/24`, matching what other identical networks
  normalize to)
- a strong ClientID (see below)

Clients can be enabled/disabled; a disabled client's identifiers and any
access rule that references it stop applying (they don't get deleted).

## ClientIDs: strength, generation, and DNS-safe encoding

Alderpoint accepts exactly two ClientID strengths, generated with
`secrets.token_hex()` (a CSPRNG, backed by `os.urandom`) -- never `random`,
UUIDs, timestamps, counters, or hashes of predictable state:

| Strength | Hex length | Bytes | Generator |
|---|---|---|---|
| 192-bit (minimum) | 48 | 24 | `secrets.token_hex(24)` |
| 256-bit (recommended) | 64 | 32 | `secrets.token_hex(32)` |

**Nothing under 48 hex characters is ever accepted**, including 32-hex/
128-bit values -- manual entry is validated identically to generated values,
and a ClientID is never silently truncated, shortened, or downgraded.

A DNS label is limited to 63 characters. A 192-bit ClientID (48 hex) already
fits, so it's used as-is on every transport. A 256-bit ClientID (64 hex)
does not fit a label, so hostname-based transports (DoT/DoQ, which carry the
ClientID via TLS SNI) use a lossless re-encoding instead: lowercase
[RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) Base32 without padding,
which turns 32 random bytes into a 52-character label. This is the *same*
256 bits, not a weaker or different identity -- both `app.clients.
clientid_dns_label()`/`clientid_from_dns_label()` and the UI make that
explicit. DoH carries the ClientID in the request path, which has no
63-character limit, so DoH always uses the full canonical 64-hex value.

**A ClientID identifies, it does not authenticate.** 256 bits of entropy
makes it extremely hard to *guess*, but there is no certificate, signature,
or proof-of-possession involved -- anyone who *learns* a ClientID (e.g. by
observing an unencrypted network segment carrying it, or extracting it from
a misconfigured client) can present it too. Treat it the way you'd treat a
long shared secret, not a client certificate. The design is deliberately
crypto-agile so a stronger, authenticated mechanism could be layered on
later without changing the identifier model.

## ClientID transport support (this dnsdist build)

Verified against the actual installed `dnsdist 2.1.1` build on this system
(`Enabled features: ... dns-over-quic dns-over-http3 dns-over-tls ...
dns-over-https ...`):

| Transport | Mechanism | Status |
|---|---|---|
| DoT | TLS SNI, exact match (`SNIRule`) | Works |
| DoQ | TLS SNI, exact match (`SNIRule`) | Works |
| DoH | HTTP request path, exact match (`HTTPPathRule`) | Works, with a caveat below |
| DoH3 | Same DoH path mechanism (dnsdist routes DoH3 through the same path-matching layer) | Works |
| Plain UDP/TCP | No transport-level identifier exists for plain DNS | Not applicable -- use IP/CIDR identification instead |

**DoH caveat, and how Alderpoint handles it:** dnsdist's DoH frontend only
routes a request whose path is in the fixed list passed to `addDOHLocal()`
at startup -- a request to a path outside that list (like a ClientID-
suffixed one) gets a bare HTTP 404 from dnsdist's own HTTP layer before any
policy rule is ever evaluated. Alderpoint works around this by writing every
currently-configured ClientID's DoH path to
`/var/lib/alderpointdns/compiled/dnsdist/access-doh-clientid-paths.txt` and
having `packaging/dnsdist.conf`'s DoH block read it at dnsdist startup to
build the frontend's path list dynamically (see
`app.clients.render_doh_clientid_paths()`). This means **adding or removing
a ClientID requires a dnsdist restart to take effect on DoH** -- which
`deploy_access_layer()` already performs whenever anything changes, so this
is transparent in normal use, but is worth knowing if you're troubleshooting
a ClientID that "isn't showing up yet."

## Access policy

**Default policy** is Allow or Deny. **Explicit rules** (Allow or Deny) can
reference a raw IPv4/IPv6/CIDR value, a ClientID, or a persistent client
(which expands to all of that client's identifiers while it's enabled).

**Precedence, always:**

1. An explicit **Deny** match -> denied.
2. Otherwise an explicit **Allow** match -> allowed.
3. Otherwise the **default policy**.

```
Allowed:  192.168.32.0/24
Denied:   192.168.32.200

192.168.32.100 -> ALLOWED  (matches the allow CIDR, no deny matches)
192.168.32.200 -> DENIED   (deny always wins, even though it's inside an allowed range)
```

IPv6 behaves identically. A denied response is `REFUSED`
(`RCodeAction(DNSRCode.REFUSED)`), not a silent drop, and is identical
across every protocol (UDP, TCP, DoT, DoH, DoQ, DoH3) a denied client tries.

**Loopback exemption:** `127.0.0.1` and `::1` are always exempt from the
*default*-deny gate specifically (not from explicit deny rules -- an admin
who deliberately denies loopback still gets that honored, since deny rules
run first, unconditionally). This is automatic and undocumented-until-now
behavior would have been a real foot-gun: without it, switching to Default
Deny would lock out Alderpoint's own internal health checks and acceptance
tests, which query dnsdist from loopback. The web UI's Default Deny switch
also requires an explicit confirmation checkbox before it takes effect.

## Enforcement: how it's compiled into dnsdist

Policy is compiled into native dnsdist objects at deploy time, never
evaluated with a per-query Python/SQLite lookup:

- IPv4/IPv6/CIDR rules -> `NetmaskGroupRule` over a `newNMG()` netmask
  group (dnsdist's native, efficient network-matching structure).
- ClientID rules -> one `SNIRule`/`HTTPPathRule` per configured ClientID
  (also static, compiled at deploy time from the current database state).
- Deny rules are evaluated first and are terminal (`RCodeAction(REFUSED)`).
  Under Default Deny, a single `NotRule(OrRule(...))` gate follows; under
  Default Allow, no gate is added at all -- the pre-existing catch-all
  bind-pool routing is untouched, so Default Allow costs nothing extra on
  the hot path.

Deployment mirrors `app/custom_rules.py`'s pattern exactly: render to a
staging directory, validate with a real `dnsdist --check-config` against a
composite config, atomically install with a `.last-good.<timestamp>` backup
of whatever was previously live, restart dnsdist, and restore + restart on
any failure. **A failed validation never replaces the active,
last-known-good configuration** -- verified both in automated tests and
live (`tests/test_clients.py`'s `DeployRollbackTest`, and a live simulated
validation failure during development that left dnsdist serving the
previous policy throughout).

## Analytics

When Statistics privacy mode is `full` (i.e. the client address in
analytics has not been anonymized/truncated), the Dashboard/Clients pages
resolve it to a persistent client's name via most-specific-network match
(an exact IP beats a broader CIDR). **This resolution never runs on an
already-anonymized value** -- doing so would defeat the point of
anonymizing it -- see `app.clients.resolve_client_name()`'s callers in
`app/analytics.py` and the regression test that pins this.

## AdGuard Home migration

AdGuard persistent clients (name + every `ids` entry) map to a new
Alderpoint persistent client with the same identifiers: IPv4/CIDR/IPv6/CIDR
map directly, and any `ids` entry that's already at or above Alderpoint's
192-bit ClientID minimum imports as an active ClientID. An AdGuard ClientID
*below* that minimum is preserved in the migration preview and report,
clearly marked as below Alderpoint's minimum, and is **never activated** --
generate a new strong ClientID for that client afterward if encrypted-DNS
identification is needed. `allowed_clients`/`disallowed_clients` map to
Alderpoint Allow/Deny rules of the matching kind, preserving the source
range exactly (never broadened). Remaining AdGuard client-scoped settings
with no Alderpoint equivalent (SafeSearch, per-client filtering,
per-client upstreams, blocked-service bundles) are preserved as explicit,
clearly-labeled inactive findings, never silently discarded.

## Export/import, backup, and replication

- **Native export** (`app.importer.export_alderpointdns_native()`) is
  version 2: it now includes `clients` (full identifier lists, canonical
  ClientIDs at full strength) and `access_policy` (default policy + rules)
  alongside every v1 field, which are kept for backward compatibility.
- **Backup/restore** covers the new tables (`clients`, `client_identifiers`,
  `access_settings`, `access_rules`) under the existing `client_aliases`
  backup component -- the same category of data, just the newer schema.
- **Replication** replicates clients/identifiers/access rules using a
  name-keyed representation rather than the generic flat-column mechanism
  other tables use: `client_identifiers.client_id` and
  `access_rules.client_id` are surrogate autoincrement foreign keys that
  would silently point at the wrong (or a nonexistent) row once copied onto
  a replica with its own independent autoincrement sequence, so the
  primary re-keys by client *name* and the replica resolves that name back
  to its own local id on apply.

## Migrating existing `client_aliases`

Existing `client_aliases` rows (Local DNS's pre-existing display-only
client labels) are copied into the new model idempotently at schema
migration time -- the legacy table itself is left intact (Local DNS and
other existing code still read it), and a given identifier is only ever
migrated into a client once, thanks to a uniqueness constraint on
`(kind, value)`. Tested against a fresh database, a copied v1.0.2-era
database, and repeated/idempotent runs.
