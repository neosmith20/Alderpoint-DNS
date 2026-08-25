-- 0001_init: Milestone 1 control-plane schema.
--
-- Column names deliberately mirror app/v2/policy_store.py's real
-- blocklist_subscriptions / local_dns_records columns and
-- app/v2/webapp.py's sessions/admins/login_attempts shape (see
-- docs/v2/architecture-decision-go-svelte.md §"Python behavior contracts
-- preserved") so a future state-migration from the live Python control.db
-- is a column-for-column copy wherever both sides have the column, not a
-- redesign.

CREATE TABLE schema_migrations (
    version     INTEGER PRIMARY KEY,
    applied_at  TEXT NOT NULL
);

CREATE TABLE admins (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    created_at     TEXT NOT NULL
);

CREATE TABLE sessions (
    id            TEXT PRIMARY KEY,
    admin_id      INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    ip            TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    csrf          TEXT NOT NULL
);
CREATE INDEX idx_sessions_admin ON sessions(admin_id);

-- Bounded (see dbmigrate/prune in auth package): rows older than the
-- failure window are deleted on every write, same as the Python original.
CREATE TABLE login_attempts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    attempted_at  TEXT NOT NULL,
    success       INTEGER NOT NULL
);
CREATE INDEX idx_login_attempts_ip ON login_attempts(ip, attempted_at);

CREATE TABLE blocklist_settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

CREATE TABLE blocklist_subscriptions (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    subscription_id          TEXT NOT NULL UNIQUE,
    name                     TEXT NOT NULL,
    url                      TEXT NOT NULL,
    category                 TEXT NOT NULL DEFAULT '',
    enabled                  INTEGER NOT NULL DEFAULT 1,
    created_at               TEXT NOT NULL,
    last_refresh_at          TEXT,
    last_status              TEXT,
    last_error               TEXT,
    rule_count               INTEGER,
    last_success_at          TEXT,
    next_update_at           TEXT,
    update_duration_ms       INTEGER,
    -- NULL = use the global default_interval_seconds setting;
    -- 0 = "Manual Only" (never scheduled, only Update Now/All).
    update_interval_seconds  INTEGER,
    failure_count            INTEGER NOT NULL DEFAULT 0,
    first_failure_at         TEXT,
    update_in_progress       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE blocklist_jobs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    kind              TEXT NOT NULL,        -- 'single' | 'all'
    subscription_ids  TEXT NOT NULL,        -- JSON array of subscription_id
    state             TEXT NOT NULL,        -- queued|running|succeeded|failed
    results           TEXT,                 -- JSON: per-subscription outcome
    started_at        TEXT NOT NULL,
    finished_at       TEXT
);

CREATE TABLE local_dns_records (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    record_type  TEXT NOT NULL CHECK(record_type IN ('A','AAAA','CNAME','PTR')),
    value        TEXT NOT NULL,
    ttl          INTEGER NOT NULL DEFAULT 300,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    UNIQUE(name, record_type, value)
);
