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
