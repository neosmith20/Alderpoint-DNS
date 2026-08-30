-- Recent Administrative Activity, matching V1.1.1's own real
-- admin_audit_log table (webapp.py audit_log()/administration_context())
-- field-for-field.
CREATE TABLE admin_audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        TEXT NOT NULL,
    admin_id  INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    username  TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL,
    success   INTEGER NOT NULL DEFAULT 1,
    ip        TEXT NOT NULL DEFAULT '',
    detail    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_admin_audit_log_admin ON admin_audit_log(admin_id, id DESC);
