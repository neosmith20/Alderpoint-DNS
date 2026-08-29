-- 0019_notification_check_state: real edge-detection state for the
-- periodic health-condition checkers (internal/notifications/
-- healthchecks.go), matching app/notify_check.py's own
-- notification_check_state table and _fire_edge() design: each
-- (event_category, component) pair's last-known state is stored so a
-- check only dispatches on a state TRANSITION (ok->bad fires the
-- failure notice, bad->ok fires a recovery notice) rather than once
-- per poll for an ongoing problem.
CREATE TABLE notification_check_state (
    event_category TEXT NOT NULL,
    component      TEXT NOT NULL,
    state          TEXT NOT NULL CHECK(state IN ('ok', 'bad')),
    updated_at     TEXT NOT NULL,
    PRIMARY KEY (event_category, component)
);
