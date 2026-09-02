-- Owner-configurable Observed Clients retention/cleanup -- previously
-- Observed Clients (derived from the analytics query_events table's own
-- "client" dimension, up to a 31-day lookback window) had no way to
-- forget a client that stopped being seen, short of the appliance-wide
-- "Clear statistics" button nuking all query history. This is a
-- targeted per-client prune instead: a client is only ever removed once
-- its OWN most recent query is older than retention_days, and a
-- recently-seen client's history is never touched, no matter how old
-- its earliest rows are. Scheduled by a bounded in-process goroutine
-- (internal/observedretention's own RunScheduler), matching internal/
-- backup's/internal/blocklists' own established scheduling pattern
-- rather than introducing a new one. Singleton row (id always 1),
-- matching backup_schedule_settings/replication_settings' own
-- established singleton-table convention in this schema.
--
-- schedule: 'manual' | 'daily' | 'weekly' | 'monthly'. Defaults to
-- 'manual' (auto-clean off) -- the safest possible default: an
-- upgrading appliance never starts silently deleting observed-client
-- history it wasn't already deleting, until an owner explicitly opts
-- into a schedule. retention_days defaults to 90, comfortably beyond
-- any routine "haven't seen this device in a while" case.
CREATE TABLE observed_client_retention_settings (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    retention_days         INTEGER NOT NULL DEFAULT 90,
    schedule               TEXT NOT NULL DEFAULT 'manual' CHECK (schedule IN ('manual', 'daily', 'weekly', 'monthly')),
    last_run_at            TEXT,
    last_status            TEXT,
    last_error             TEXT,
    last_removed_clients   INTEGER NOT NULL DEFAULT 0
);
INSERT INTO observed_client_retention_settings (id) VALUES (1);
