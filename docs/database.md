# Database

BindGuard stores configuration, compiler state, and analytics in
`/var/lib/bindguard/bindguard.db` using SQLite WAL mode.

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
