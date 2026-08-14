# V2 Storage Ownership Map — v1.1.1 Table Audit

**Status:** V2 Workstream 1 output. Private engineering document.
**Source of truth for classification rules:** `docs/v2/roadmap-reference/v2-architecture-plan.md` §3.
**Audit method:** live schema pulled read-only from the running appliance
(`sqlite3 "file:/var/lib/alderpointdns/alderpointdns.db?mode=ro" -readonly ".schema"`), cross-checked
against `docs/database.md`. No write access was used. 52 tables enumerated.

This is a classification map, **not a migration**. Nothing described here has been executed against
the live database. See `docs/v2/migration-scaffold.md` for the (stubbed) execution path.

## Classification legend

- **CONFIG** — operator-facing desired state → V2 target: `/etc/alderpointdns/alderpointdns.yaml`
- **CONTROL** — bounded transactional/relational state → V2 target: `/var/lib/alderpointdns/control.db`
- **ANALYTICS-RAW** — unbounded raw event history → V2 target: `/var/lib/alderpointdns/analytics/queries/...` (Parquet, pending benchmark confirmation)
- **ANALYTICS-AGG** — bounded aggregate counters → V2 target: separate small aggregate store (pending benchmark confirmation), never control.db
- **SECRET** — must never live in YAML or in analytics; root-only dedicated storage
- **GENERATED** — runtime-compiled output, not source-of-truth state, not migrated at all (regenerated fresh on V2)

## Table-by-table map

| Table | v1 role | V2 class | Notes |
|---|---|---|---|
| `sources` | blocklist source config + last-run stats | CONFIG (desired list) + CONTROL (run stats) | Split: which sources are enabled = config; `last_attempt`/`parsed_rules`/etc. run-state = control |
| `custom_rules` | legacy custom allow/block rules | CONTROL | Superseded by `custom_filter_rules`; already has a `migrated_to_v2` flag from a prior *internal* schema migration (unrelated to this V2 effort) — needs one-time reconciliation, not carried forward as two tables |
| `custom_filter_rules` | current custom filter rule engine | CONTROL | Policy data, not raw history |
| `deployments` | compiler/deploy run history | CONTROL | Bounded job history, same shape as software_update_jobs |
| `admins` | admin accounts + password hash | CONTROL (SECRET-adjacent) | `password_hash` column becomes Argon2id-encoded string (see `app/v2/auth_hash.py`); never exported to YAML/backups in plaintext |
| `login_attempts` | auth rate-limit history | CONTROL | Bounded by retention, audit-adjacent |
| `categories`, `policy_profiles`, `network_policies`, `profile_categories` | filtering policy taxonomy | CONTROL (policy tables) | These are exactly the kind of table the V2 unified policy engine (roadmap §4) will restructure; kept as CONTROL-class placeholders for now, not redesigned in Workstream 1 |
| `analytics_settings` | analytics config (retention, enable) | CONFIG | Operator-facing toggles → YAML |
| `analytics_aggregate_buckets` | per-minute/hour rollups | ANALYTICS-AGG | Not control.db — bounded but high-churn, roadmap explicitly separates this |
| `analytics_counter_state` | monotonic counter checkpoints | ANALYTICS-AGG | Small KV, could live in the aggregate store |
| `query_events` | **raw per-query log** | ANALYTICS-RAW | This is the table the whole benchmark (Parquet/Zstd/DuckDB vs SQLite WAL vs JSONL) is about. Must leave control.db entirely in V2. |
| `analytics_events` | analytics subsystem's own operational log (errors/warnings) | CONTROL (small, operational) | Not query history; this is "the analytics pipeline logging about itself" — bounded, low-volume, fits control.db |
| `local_dns_settings`, `local_dns_records`, `client_aliases`, `local_dns_deployments` | Local DNS zone config + deploy history | CONFIG (records/settings) + CONTROL (deploy history) | Records are desired state; `local_dns_deployments` is run history |
| `dns_cache_settings`, `dns_cache_deployments`, `dns_cache_flushes` | cache tuning + operational actions | CONFIG (settings) + CONTROL (deployments/flushes) | |
| `encryption_settings`, `encryption_deployments` | DoH/DoT/DoQ config + deploy history | CONFIG + CONTROL | TLS material itself is SECRET (see below), not this table |
| `import_jobs` | AdGuard/Pi-hole import job bookkeeping | CONTROL | Bounded job history w/ embedded JSON blobs; fits control.db as-is |
| `backup_settings`, `backup_history`, `restore_history`, `backup_requests` | backup/restore config + job history | CONFIG (settings) + CONTROL (history/requests) | |
| `replication_settings`, `replication_enrollments`, `replication_replicas`, `replication_generations`, `replication_sync_history` | replication config + peer state + sync history | CONFIG (settings) + CONTROL (everything else) | `token_hash`/`cert_fingerprint` are hashes, not raw secrets — control.db is fine; the actual enrollment tokens/keys in transit are SECRET but not stored raw here already |
| `upstream_resolvers`, `upstream_deployments` | resolver config + deploy history | CONFIG + CONTROL | |
| `upstream_resolver_aggregate_buckets`, `upstream_resolver_counter_state` | per-resolver rollups | ANALYTICS-AGG | Same reasoning as `analytics_aggregate_buckets` — high-churn rollup, not control.db |
| `filter_update_settings` | blocklist auto-update schedule config | CONFIG | |
| `sessions` | active admin web sessions | CONTROL | Ephemeral but relational; per roadmap §3.2 explicitly listed as control.db content |
| `admin_audit_log` | admin action audit trail | CONTROL | Roadmap explicitly allows "audit history" in control.db (bounded by retention policy, not the raw-query firehose) |
| `notification_settings`, `notification_providers`, `notification_subscriptions`, `notification_rate_state`, `notification_history`, `notification_check_state` | notification config + provider secrets + delivery history | CONFIG (settings/subscriptions) + CONTROL (history/state) + SECRET (`notification_providers.secret`) | `notification_providers.secret` (webhook tokens etc.) must not sit as a plain column readable alongside everything else in V2 — needs the same secret-separation treatment as admin credentials, flagged as an open item, not solved in Workstream 1 |
| `software_update_settings`, `software_update_jobs`, `software_update_events` | update-check config + job history + step log | CONFIG + CONTROL | |
| `source_parse_cache` | blocklist parse cache (derived, disposable) | GENERATED | Not migrated; V2 regenerates on first compile |
| `clients`, `client_identifiers`, `access_settings`, `access_rules` | named clients + identifiers + access policy | CONTROL | Directly maps to roadmap §3.2 "persistent clients / client identifiers / groups/tags / policy assignments" — this is also where V2's client-groups/tags feature (out of scope for Workstream 1) will attach |

## What's explicitly NOT in this table

- **Generated runtime config**: dnsdist.conf, named.conf, RPZ zone files, compiled blocklist artifacts under `/var/lib/alderpointdns/compiled/` — these are outputs of the compiler, not source-of-truth storage, and are out of scope for this audit (V2 keeps compiling into native dnsdist/BIND structures per the frozen failure-domain contract, see `docs/v2/failure-domains.md`).
- **TLS/cert material** (`/etc/alderpointdns/certs/`, `dnsdist-api.key`, `dnsdist-web.creds`, `secrets.env`) — already root-owned dedicated paths outside the SQLite DB in v1; V2 preserves this pattern rather than pulling secrets into YAML or control.db.

## Summary counts

- CONFIG-only or CONFIG+CONTROL split: ~24 tables
- CONTROL-only: ~20 tables
- ANALYTICS-RAW: 1 table (`query_events`) — small in table count, dominant in row count and the entire point of the Workstream 1 benchmark
- ANALYTICS-AGG: 4 tables
- GENERATED (not migrated): 1 table
- Flagged secret-separation gap (not resolved in this workstream): `notification_providers.secret`
