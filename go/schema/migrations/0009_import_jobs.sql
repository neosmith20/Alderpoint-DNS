-- 0009_import_jobs: native Go schema for the Import page's real
-- preview -> apply workflow (was previously a one-shot apply with no
-- staged preview/selection/report at all), matching the SHAPE of
-- Python's own app/v2/import_migration.py's job model (read directly):
-- a job is created from a real parse of the uploaded source, the plan
-- (what would be imported, row by row, with a conflict flag for
-- anything already present) is stored and returned for the operator to
-- review and select rows to skip, and only actually written on a
-- separate, explicit apply call.
CREATE TABLE import_jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type  TEXT NOT NULL,
    source_name  TEXT NOT NULL,
    plan_json    TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','applied')),
    result_json  TEXT,
    snapshot_filename TEXT,
    created_at   TEXT NOT NULL,
    applied_at   TEXT
);
