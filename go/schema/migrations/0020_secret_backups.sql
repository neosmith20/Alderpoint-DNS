-- 0020_secret_backups: real Secret Backups job history, matching
-- app/v2/webapp.py's real backup_jobs/restore_jobs tracking for the
-- SAME feature (field-matched, not the main config-backup's own
-- restore_jobs table -- this one is scoped to internal/secretbackup).
CREATE TABLE secret_backup_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL CHECK(kind IN ('create', 'restore')),
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL CHECK(status IN ('running', 'succeeded', 'failed')),
    filename     TEXT NOT NULL DEFAULT '',
    secret_count INTEGER NOT NULL DEFAULT 0,
    detail       TEXT NOT NULL DEFAULT ''
);
