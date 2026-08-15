# Alderpoint DNS V2 Workstream 4C — Replication and Client Discovery

## Package

- Version: `alderpointdns-v2 2.0.0~private3-1`
- Artifact: `/tmp/alderpointdns-v2-4c/alderpointdns-v2_2.0.0~private3-1_all.deb`
- Size: `69700460` bytes
- SHA-256: `c869fa9b2615d7adcbdce050513b405b345a075015c5ef4334768573ed8b0f96`

## Node Identity

`app/v2/node_identity.py` stores one cryptographically random UUID in `control.db`
table `node_identity`. Hostname is never used as the security identity. Display
name is separate and mutable.

Backup/restore retains the node id. A simultaneously active clone must explicitly
regenerate identity before adding replication trust; regeneration updates the id
and clears the trust relationship in the management workflow.

## Replication

`app/v2/replication_v2.py` implements protocol version `1` over HTTPS with mutual
TLS. TLS uses CA validation, server certificate validation, client certificate
validation, and explicit peer authorization in `replication_peers`.

Authorization binds:

- peer node id
- peer certificate SHA-256 fingerprint
- certificate CN node identity
- trusted CA
- peer URL

Unknown, unauthorized, CA-invalid, fingerprint-mismatched, or node-id-mismatched
peers fail closed. There is no plaintext fallback.

Replicated control tables are bounded snapshots of:

- clients and identifiers
- client groups and memberships
- policy layers, networks, groups, schedules
- upstream profiles and endpoints
- domain routing
- service definitions/rulesets
- notification provider metadata

Not replicated through control snapshots:

- raw Parquet query history
- aggregate analytics rows
- transient query logs
- sessions
- machine-local jobs
- generated runtime files

Actual secret values replicate through the same authorized mTLS message but are
applied only to the dedicated `SecretStore`; control.db receives only metadata and
secret references.

## Protocol Bounds and Semantics

Messages include `protocol_version`, `message_id`, `sender_node_id`, `category`,
`operation`, `generation`, `content_hash`, `created_at`, and `payload`.

Bounds:

- request body: `1,000,000` bytes
- object rows per table/message: `2,000`
- secret value: `64 KiB`
- replay seen-message store per peer: `4,096`
- replay timestamp window: `10 minutes`

Generation rule:

- greater generation applies
- lower generation is stale
- same generation and same hash is duplicate/no-op
- same generation and different hash is conflict

Apply path is transactional for control.db and uses runtime compile/stage/validate/promote before success. Secret import is crash-atomic through `SecretStore.import_all`; if runtime promotion fails after secret import, the previous secret snapshot is restored.

## Client Discovery

`app/v2/observed_clients.py` stores aggregate observed-client state in
`observed_clients`. This is not raw query history: one row per source address is
updated/coalesced.

Tracked fields:

- source IP and address family
- first/last seen
- query count
- sanitized hostname candidate and source
- managed client association
- dismissed flag
- confidence/source

Defaults:

- max entries: `4096`
- inactivity expiry: `30` days
- eviction: oldest unmanaged observations first

Hostname candidates are untrusted and sanitized before storage. Discovery never
creates managed clients automatically. Promotion is an explicit admin action and
is idempotent for an already-associated observed address.

The packaged `alderpointdns-v2-discovery.service` drains JSONL observations from
`/var/lib/alderpointdns-v2/discovery/inbox`. Queue/backlog failures update stats
and do not block DNS.

## Management API

New HTTPS API endpoints:

- `GET /api/node-identity`
- `PUT /api/node-identity/display-name`
- `GET /api/replication/peers`
- `PUT /api/replication/peers/{peer_node_id}`
- `DELETE /api/replication/peers/{peer_node_id}`
- `GET /api/replication/health`
- `POST /api/replication/peers/{peer_node_id}/sync`
- `GET /api/discovery/observed-clients`
- `GET /api/discovery/observed-clients/{source_ip}`
- `DELETE /api/discovery/observed-clients/{source_ip}`
- `GET /api/discovery/status`
- `PUT /api/discovery/settings`
- `POST /api/discovery/observed-clients/{source_ip}/promote`

State-changing endpoints require authenticated sessions and CSRF.

## Installed E2E Evidence

Evidence directory: `/tmp/alderpointdns-v2-4c-e2e`.

Two brand-new Debian 13 Podman systemd nodes installed the exact rebuilt `.deb`.
All services were active:

- `alderpointdns-v2-web`
- `alderpointdns-v2-analytics`
- `alderpointdns-v2-tierb`
- `alderpointdns-v2-schedule`
- `alderpointdns-v2-discovery`
- `alderpointdns-v2-replication`

Node ids:

- node A: `09d35bbf-f453-4229-ae3a-3f57f12cceff`
- node B: `0558605e-6052-4204-8ec1-0b4c4f475c76`

Replication proof:

- node A to node B sync returned `applied=true`, generation `1`
- node B API listed replicated network `lan-a 10.40.0.0/24`
- node B API listed replicated notification provider `canary` with `has_secret=true`
- node B control.db metadata had only `canary|<secret_ref>`
- node B secret canary appeared only in `/var/lib/alderpointdns-v2/secrets/<secret_ref>`

Discovery proof:

- observed source `192.0.2.77`
- hostile hostname `<script>bad</script>.Lan` stored as `scriptbad-script.lan`
- explicit promotion created managed client `1`
- policy explain returned the promoted client and effective cache profile

Reinstall proof:

- reinstalling the exact package on node A preserved node id
  `09d35bbf-f453-4229-ae3a-3f57f12cceff`

Failure isolation proof:

- stopping node A replication service left node B management health `status=ok`
- restarting node A replication service returned `active`

Defects found and fixed during E2E:

- replication CA bootstrap CN exceeded X.509 CN length; fixed by shortening CA CN
- `push_to_peer` shadowed the imported `http` module; fixed and covered by regression test
- E2E test CA lacked keyUsage; fixed in the E2E fixture

## Test Results

- Focused 4C tests: `12 passed, 1 skipped`
- Adjacent V2 regression subset: `117 passed`
- Broad V2 run excluding known-hanging `tests/v2/test_webapp.py`: `705 passed, 25 skipped, 15 failed`

The 15 broad-run failures were environmental on this host: sandbox denied
`socket()` or `chown()` operations under `/tmp`, and migration health checks could
not start dnsdist in the sandbox. The installed-package Podman E2E exercises those
capabilities outside the sandbox.
