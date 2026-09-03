-- DNS Runtime: real deployment history + rollback. One row per real,
-- non-dry-run Apply attempt (manual click or an auto-apply-on-save) --
-- see internal/dnsruntime's own doc comment for the real, disclosed
-- scope this enables: dnsdist_conf is only ever populated on a
-- successfully PROMOTED row (a real, replayable snapshot of exactly
-- what was live), never on a failed/rolled-back attempt, which keeps
-- only its own diagnostic fields. BIND's own on-disk state (zone/RPZ
-- files) is NOT snapshotted here -- it's continuously derived from the
-- live DB (blocklists/local DNS/policy), governed by Backup & Restore,
-- not by this table.
CREATE TABLE dns_runtime_generations (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    generation_number INTEGER NOT NULL,
    created_at        TEXT NOT NULL,
    trigger_source    TEXT NOT NULL DEFAULT 'manual', -- 'manual' | 'auto' | 'rollback'
    promoted          INTEGER NOT NULL DEFAULT 0,
    rolled_back       INTEGER NOT NULL DEFAULT 0,
    stage             TEXT NOT NULL DEFAULT '',
    detail            TEXT NOT NULL DEFAULT '',
    error             TEXT NOT NULL DEFAULT '',
    dnsdist_conf      TEXT,       -- only set when promoted=1 -- see this file's own doc comment
    content_hash      TEXT NOT NULL DEFAULT '',
    build_ms          INTEGER NOT NULL DEFAULT 0,
    compile_ms        INTEGER NOT NULL DEFAULT 0,
    rpc_ms            INTEGER NOT NULL DEFAULT 0,
    total_ms          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_dns_runtime_generations_number ON dns_runtime_generations(generation_number DESC);
