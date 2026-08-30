-- Statistics settings, matching V1.1.1's real analytics_settings row
-- (webapp.py statistics_settings.html) as far as this architecture
-- honestly has an equivalent -- see internal/dnsanalytics/settings.go's
-- doc comment for exactly which V1 fields map onto the new single-tier
-- dnstap event-stream design and which two (aggregate_retention_days,
-- collection_interval) do not exist here because there is no separate
-- poll-and-aggregate tier to configure.
CREATE TABLE analytics_settings (
    id                              INTEGER PRIMARY KEY CHECK (id = 1),
    analytics_enabled               INTEGER NOT NULL DEFAULT 1,
    detailed_query_logging_enabled  INTEGER NOT NULL DEFAULT 1,
    privacy_mode                    TEXT NOT NULL DEFAULT 'full' CHECK (privacy_mode IN ('full', 'anonymized_clients', 'aggregate_only')),
    client_anonymization            TEXT NOT NULL DEFAULT 'truncate' CHECK (client_anonymization IN ('truncate', 'hash')),
    detailed_retention_days         INTEGER NOT NULL DEFAULT 7,
    db_size_limit_bytes             INTEGER NOT NULL DEFAULT 268435456,
    recent_query_limit              INTEGER NOT NULL DEFAULT 100
);
INSERT INTO analytics_settings (id) VALUES (1);
