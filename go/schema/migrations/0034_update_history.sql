-- Software Updates: real persistent history of every apply attempt --
-- previously only the current version and the most recently staged
-- candidate were tracked, with no record of past attempts at all.
CREATE TABLE update_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    at            TEXT NOT NULL,
    from_version  TEXT NOT NULL,
    to_version    TEXT NOT NULL,
    source        TEXT NOT NULL DEFAULT 'manual', -- 'manual' (uploaded binary) | 'channel' (downloaded from update channel)
    result        TEXT NOT NULL,                  -- 'success' | 'failed'
    backup_ref    TEXT NOT NULL DEFAULT '',        -- the pre-update safety backup's own filename, when one was taken
    error         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_update_history_at ON update_history(id DESC);
