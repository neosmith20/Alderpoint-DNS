-- 0005_policy_layers: native Go schema for the shared policy-layer system
-- (global/network/group/client/schedule), matching app/v2/policy_store.py's
-- policy_layers + policy_networks tables field-for-field. This is the
-- shared infrastructure the Clients & Access, Filters, and DNS Settings
-- pages all read/write -- built once here, not duplicated per page.
CREATE TABLE policy_layers (
    id                          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope                       TEXT NOT NULL CHECK(scope IN ('global','network','group','client','schedule')),
    scope_ref                   TEXT NOT NULL,
    filtering_profile_id        TEXT,
    safesearch_mode             TEXT,
    parental_policy_id          TEXT,
    security_policy_id          TEXT,
    service_blocking_ruleset_id TEXT,
    blocking_response_mode      TEXT,
    custom_ipv4                 TEXT,
    custom_ipv6                 TEXT,
    upstream_profile_id         TEXT,
    fallback_strategy           TEXT,
    fallback_upstream_profile_id TEXT,
    ecs_mode                    TEXT,
    domain_routing_ruleset_id   TEXT,
    query_log_enabled           INTEGER,
    statistics_enabled          INTEGER,
    created_at                  TEXT NOT NULL,
    updated_at                  TEXT NOT NULL,
    UNIQUE(scope, scope_ref)
);

CREATE TABLE policy_networks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    network_id TEXT NOT NULL UNIQUE,
    cidr       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);
