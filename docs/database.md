# Database

Alderpoint DNS stores configuration, compiler state, and analytics in
`/var/lib/alderpointdns/alderpointdns.db` using SQLite WAL mode.

Analytics tables:

- `analytics_settings`: collection, privacy, retention, and size-limit options.
- `analytics_aggregate_buckets`: normalized one-minute counters for dashboard
  charts and summary cards.
- `analytics_counter_state`: last dnsdist counter values, used to handle
  restarts and counter resets without negative deltas.
- `query_events`: recent detailed query rows when detailed logging is enabled.
- `analytics_events`: local warnings such as database-size pruning.

The collector batches detailed query inserts and updates aggregate buckets in
the same local database. In aggregate-only privacy mode, individual query rows
are not retained.

Local DNS tables:

- `local_dns_settings`: internal domain, default TTL, and server identity
  defaults. The default internal domain is `home.arpa`; `.local` is rejected to
  avoid multicast DNS conflicts.
- `local_dns_records`: A, AAAA, PTR, and CNAME records with TTL, comments,
  enabled state, and automatic PTR linkage.
- `client_aliases`: analytics display names for client IPs or CIDRs.
- `local_dns_deployments`: validation, serial, zone count, and deployment
  result for the last Local DNS zone generation.

Local DNS records are stored separately from RPZ filtering data. Host records
are never written into the RPZ zone.

Custom filtering rule tables:

- `custom_filter_rules`: first-class custom rules (see `docs/filtering.md`):
  original rule text, normalized form, rule type
  (`block`/`allow`/`rewrite`/`regex_block`/`regex_allow`/`comment`/
  `unsupported`), match domain and exact-vs-subdomain flag, regex pattern,
  rewrite address and family, priority (`$important`), enabled state,
  validation state (`valid`/`unsupported`/`invalid`) with the exact reason,
  source system (`manual`/`adguard`/`pihole`/`legacy`/`import`), and an
  optional `import_jobs` reference.
- `custom_rules` (legacy): the original allow/block table. Kept intact for
  backup and replication compatibility; rows are copied once into
  `custom_filter_rules` (tracked by a `migrated_to_v2` column) and the
  compile path and UI read only the new table afterwards.

BIND cache tables:

- `dns_cache_settings`: key/value cache tuning (max size, positive/negative
  min/max TTL, recursive clients, prefetch, serve-stale), same shape as
  `local_dns_settings`.
- `dns_cache_deployments`: staged/validated/backed-up/atomically-activated/
  health-checked/rolled-back deployment history for generated cache options.
- `dns_cache_flushes`: pending and completed cache flush requests (entire
  cache, one name, or one subtree), applied by the privileged
  `cache-flush` compiler command.

Upstream resolver tables:

- `upstream_resolvers`: friendly name, protocol (`plain`/`dot`/`doh`),
  resolver address or DoH host, port, DoH path, TLS hostname, bootstrap IPs,
  enabled state, ordering, and last health/latency result.
- `upstream_deployments`: staged/validated/health-checked/rolled-back
  deployment history for the generated BIND forwarder include and dnsdist
  upstream-forwarder include.
- `upstream_resolver_aggregate_buckets`: one-minute per-resolver analytics
  snapshots from dnsdist's `alderpointdns_upstreams` backend counters, including
  resolver name/protocol/endpoint snapshots, enabled and health state, queries
  attempted, successful responses, failures, timeouts, latency aggregates, and
  last success/failure timestamps. Historical rows intentionally do not depend
  on a live `upstream_resolvers` row.
- `upstream_resolver_counter_state`: last-seen dnsdist per-server counters,
  keyed by generated backend name, used to calculate monotonic deltas after
  polling and after dnsdist restarts.

Encryption tables:

- `encryption_settings`: key/value protocol toggles/ports, hostname,
  bootstrap IP, certificate mode/paths, and a `pending_cert_action` flag used
  to hand a certificate-generation request from the unprivileged web process
  to the privileged deploy step.
- `encryption_deployments`: staged/validated/backed-up/atomically-activated/
  health-checked/rolled-back deployment history, including the per-protocol
  functional test results for the most recent deployment.

Import table:

- `import_jobs`: one row per row-oriented upload (CSV/XLSX/hosts/BIND-zone/
  Alderpoint DNS CSV), storing raw parsed rows, the sanitized staged source path,
  the column mapping, preview counts, the list of inserted `local_dns_records`
  IDs (used by rollback), a downloadable JSON report, and status
  (`uploaded`/`previewed`/`applied`/`rolled_back`/`failed`). Migration-style
  imports such as AdGuard Home, Pi-hole, and Alderpoint DNS-native JSON are
  previewed as structured translations before apply; their original upload is
  staged under `/var/lib/alderpointdns/imports` for troubleshooting.

Backup tables:

- `backup_settings`: key/value schedule settings (`schedule_enabled`,
  `schedule_interval_hours`, `retention_count`) and the default component
  selection used by scheduled/manual-CLI backups.
- `backup_history`: one row per created archive — path, size, components,
  manifest JSON, status, message.
- `restore_history`: one row per restore attempt — source path, requested
  components, staged/validated/applied outcome, the pre-restore safety
  backup's path, validation output, and status
  (`deployed`/`rolled_back`/`rollback_failed`/`failed`).
- `backup_requests`: the unprivileged-web-process-writes /
  privileged-compiler-process-reads handoff queue for
  create/restore/preview requests (mirrors `dns_cache_flushes`).

Replication tables:

- `replication_settings`: node role, stable node ID, listener/poll settings,
  primary address, pause flag, last applied generation/hash, and drift state.
- `replication_enrollments`: one-time enrollment token hashes, intended node
  identity/name, expiry, status, and consumption timestamp.
- `replication_replicas`: enrolled replica identities, certificate
  fingerprints/serials, active/paused/revoked status, last seen time, last
  ACKed generation/hash, and last result.
- `replication_generations`: primary-produced generation number, source node,
  schema version, replicated section list, content hash, and canonical JSON
  payload.
- `replication_sync_history`: replica-side sync attempt history including
  generation, result, timestamp, and message.
