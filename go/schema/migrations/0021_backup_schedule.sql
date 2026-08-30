-- Owner-configurable scheduled appliance backups. Field-matched against
-- V1.1.1's own real settings (app/backup.py's settings(): schedule_enabled,
-- schedule_interval_hours default 24, retention_count default 7 -- read
-- directly, not guessed), but scheduled here by a bounded in-process
-- goroutine (internal/backup's own RunScheduler, matching internal/
-- blocklists' established pattern) rather than V1.1.1's systemd timer
-- unit -- this appliance's own process model doesn't depend on systemd
-- being present or reachable for any of its other scheduled work either.
-- Singleton row (id always 1), matching replication_settings/notification
-- settings' own established singleton-table convention in this schema.
CREATE TABLE backup_schedule_settings (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    enabled          INTEGER NOT NULL DEFAULT 0,
    interval_hours   INTEGER NOT NULL DEFAULT 24,
    retention_count  INTEGER NOT NULL DEFAULT 7,
    last_run_at      TEXT,
    last_status      TEXT,
    last_error       TEXT
);
INSERT INTO backup_schedule_settings (id, enabled, interval_hours, retention_count) VALUES (1, 0, 24, 7);
