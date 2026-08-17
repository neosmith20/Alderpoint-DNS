# Real two-node replication acceptance (roadmap Priority 12)

## Real finding: no shipped workflow establishes trust between two independent installs

Each real install's `init-replication-cert` (postinst) generates its
own private CA entirely in memory, uses it once to sign that node's own
self-signed server certificate, and **discards the CA private key
immediately** -- only the CA's public cert (`trust-ca.pem`) is ever
written to disk. This is a deliberate, reasonable security property (a
stolen node can never mint new trusted certs), but it also means no
tool on the appliance -- CLI or API -- can ever issue an *additional*
certificate signed by that node's own CA after install. Grepped
`scripts/v2/alderpointdns_v2_ctl.py` for every subcommand: only
`init-replication-cert` (create-if-absent, never re-signs) and
`replication-server` exist; no `issue-peer-cert`/enrollment command.
Grepped `webapp.py`: `/api/tls/replace` exists for the *management*
HTTPS certificate only -- there is no equivalent endpoint for the
*replication* mTLS certificate. `ReplicationPeerUpsert`'s
`client_cert_pem`/`client_key_pem` fields expect an administrator to
already have valid cert material in hand, with no in-band way to
produce it for two genuinely independent appliances.

**Net effect: as currently packaged, a real administrator with two real
V2 appliances has no way to establish replication trust between them.**
The protocol itself (below) is solid; only the enrollment step is
missing. This is a real, actionable gap for a future session -- likely
either (a) a `alderpointdns-v2-ctl issue-peer-cert <remote-node-id>`
command that persists the CA key (weighed against the security property
above) or re-derives trust some other way, or (b) formally documenting
an external-CA workflow (an administrator runs their own PKI tooling
external to the appliance and imports certs via a new
`/api/replication/cert/replace`-style endpoint, mirroring the existing
`/api/tls/replace` pattern for the management cert).

## Real protocol proof (acting as that missing enrollment step manually)

To still prove the actual replication data plane over two real,
independently `apt`-installed RC3 appliances (rather than only the
existing single-process unit tests), generated one shared CA + a real
cert per node's real node identity using `replication_v2`'s own
production functions (the same "administrator's external PKI" role a
real enrollment tool would fill), installed each node's cert as its
live replication server cert, and registered peers through the real
`PUT /api/replication/peers/{id}` HTTPS API on both sides -- not a
test-only shortcut for the sync itself, only for how trust material was
produced.

Two fresh Debian 13 containers (`10.88.0.80`/`10.88.0.81`), real
`apt-get install` of RC3 on both, real bootstrap/login on both.

- **Real push**: created a real client (`repl-canary-client`) on node A
  through its real HTTPS API, called `POST
  /api/replication/peers/{peer}/sync` -- real mTLS HTTPS connection to
  node B's real `9443` listener, real fingerprint-verified TLS handshake,
  real signed JSON payload.
- **Result on node B**: the client is present in node B's real
  `control.db` and served by node B's own real `/api/clients` -- a real
  cross-appliance replication round trip, not an in-process call.
- **Health reporting**: `GET /api/replication/health` on node A
  correctly shows `last_success_at` populated, `last_error` empty,
  `remote_known_generation` advancing.
- **Scope note (not a bug, a real early miss in this test)**: first
  attempted this proof with a local DNS record, which silently didn't
  replicate -- `local_dns_records` is genuinely not in
  `replication_v2.REPLICATED_TABLES` (clients, policy layers/networks/
  groups/schedules, upstream profiles, domain routing, service
  definitions/rulesets, and notification providers are). Re-tested with
  a client record, which is in scope, and it worked correctly. Whether
  local DNS records and custom filter rules *should* eventually be
  in-scope for replication is a product-scope question for the roadmap,
  not something fixed here.

Both containers removed after verification, not retained as running
services.
