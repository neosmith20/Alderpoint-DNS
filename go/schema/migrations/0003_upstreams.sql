-- 0003_upstreams: native Go schema for DNS Settings / Upstreams, matching
-- app/v2/policy_store.py's upstream_profiles/upstream_endpoints tables
-- field-for-field (see internal/upstreams's doc comment for exactly what
-- was preserved and what's deliberately deferred).
CREATE TABLE upstream_profiles (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    upstream_profile_id TEXT NOT NULL UNIQUE,
    name                TEXT NOT NULL,
    transport           TEXT NOT NULL,
    strategy            TEXT NOT NULL DEFAULT 'ordered',
    enabled             INTEGER NOT NULL DEFAULT 1,
    sort_order          INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL
);

CREATE TABLE upstream_endpoints (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    upstream_profile_row_id INTEGER NOT NULL REFERENCES upstream_profiles(id) ON DELETE CASCADE,
    address                  TEXT NOT NULL,
    tls_hostname             TEXT,
    priority                 INTEGER NOT NULL DEFAULT 0,
    weight                   INTEGER NOT NULL DEFAULT 1,
    doh_path                 TEXT
);

CREATE INDEX idx_upstream_endpoints_profile ON upstream_endpoints(upstream_profile_row_id);
