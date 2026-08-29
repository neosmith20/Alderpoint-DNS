-- 0015_notification_dispatch: the event-driven dispatch engine
-- (app/notifications.py's EVENT_CATEGORIES/subscriptions/dispatch/
-- history/cooldown logic, read directly) -- internal/notifications
-- already had real provider CRUD + secret storage + test-send; this
-- closes the "nothing decides WHEN to notify" gap that package's own
-- doc comment disclosed.
CREATE TABLE notification_subscriptions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id      TEXT NOT NULL REFERENCES notification_providers(provider_id) ON DELETE CASCADE,
    event_category   TEXT NOT NULL,
    min_severity     TEXT NOT NULL DEFAULT 'warning' CHECK(min_severity IN ('info','warning','critical')),
    enabled          INTEGER NOT NULL DEFAULT 1,
    cooldown_minutes INTEGER NULL, -- NULL = use the global default
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE(provider_id, event_category)
);

-- One row per (event_category, provider_id) pair actually dispatched to
-- -- tracks cooldown/dedup state so a repeat of the same real condition
-- doesn't re-notify every time it's merely still true.
CREATE TABLE notification_rate_state (
    event_category   TEXT NOT NULL,
    provider_id      TEXT NOT NULL,
    last_fingerprint TEXT NOT NULL DEFAULT '',
    last_sent_at     TEXT NULL,
    suppressed_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(event_category, provider_id)
);

CREATE TABLE notification_history (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    at             TEXT NOT NULL,
    event_category TEXT NOT NULL,
    severity       TEXT NOT NULL,
    component      TEXT NOT NULL,
    message        TEXT NOT NULL,
    began_at       TEXT NOT NULL,
    recovered      INTEGER NOT NULL DEFAULT 0,
    provider_id    TEXT NOT NULL,
    provider_name  TEXT NOT NULL,
    status         TEXT NOT NULL, -- 'sent' | 'suppressed' | 'failed'
    error          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_notification_history_at ON notification_history(at DESC);
