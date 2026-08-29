-- 0018_replication: real Go-native replacement for the dead
-- Python-control.db-reading Replication feature (see PARITY_MATRIX.md's
-- 2026-08-29 correction). Rebuilt against V1.1.1's actual owner-facing
-- workflow (app/replication.py, read directly): one-way primary-to-
-- replica configuration sync over mutual TLS, token-based enrollment,
-- numbered content-hashed generations, and replica-side drift detection
-- -- field-matched for the parts that carry over, adapted where the
-- Go-native schema genuinely differs (see internal/replication's own
-- doc comment for the full replicable-table allowlist).
CREATE TABLE replication_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE replication_enrollments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     TEXT NOT NULL UNIQUE,
    node_name   TEXT NOT NULL,
    token_hash  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','consumed','revoked','expired')),
    consumed_at TEXT,
    reserved_at TEXT
);

CREATE TABLE replication_replicas (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id               TEXT NOT NULL UNIQUE,
    display_name          TEXT NOT NULL,
    cert_fingerprint      TEXT NOT NULL,
    cert_serial           TEXT NOT NULL DEFAULT '',
    enrolled_at           TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','paused','revoked')),
    last_generation_acked INTEGER NOT NULL DEFAULT 0,
    last_ack_hash         TEXT NOT NULL DEFAULT '',
    last_seen_at          TEXT,
    last_result           TEXT NOT NULL DEFAULT ''
);

CREATE TABLE replication_generations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    generation_number  INTEGER NOT NULL UNIQUE,
    created_at         TEXT NOT NULL,
    source_node_id     TEXT NOT NULL,
    schema_version     INTEGER NOT NULL,
    section_keys       TEXT NOT NULL, -- canonical JSON array of section names present, for a quick preview without parsing the full payload
    content_hash       TEXT NOT NULL,
    payload            TEXT NOT NULL  -- canonical JSON of the full replicable-table sections
);

CREATE TABLE replication_sync_history (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    attempted_at      TEXT NOT NULL,
    generation_number INTEGER,
    result            TEXT NOT NULL,
    message           TEXT NOT NULL DEFAULT ''
);
