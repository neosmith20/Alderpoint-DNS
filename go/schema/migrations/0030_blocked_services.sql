-- Blocked Services (Standard > Filters > Blocked Services): which
-- catalog service ids (internal/blockedservices.Catalog, a static Go
-- list -- not stored here, services aren't owner-defined) are currently
-- toggled on, plus an optional schedule window. A single row, same
-- pattern as every other *_settings table in this schema. Real
-- enforcement compiles through a dedicated, reserved
-- service_blocking_rulesets row (id 'standard-blocked-services',
-- created/maintained by this package, not hand-edited) assigned to the
-- GLOBAL policy layer -- see internal/dnsruntime's own doc comment on
-- the fix that made a global service_blocking_ruleset_id actually
-- compile into live DNS behavior.
CREATE TABLE blocked_services_settings (
    id                 INTEGER PRIMARY KEY CHECK (id = 1),
    enabled_service_ids TEXT NOT NULL DEFAULT '[]', -- JSON array of catalog ids
    schedule_enabled   INTEGER NOT NULL DEFAULT 0,
    schedule_days      TEXT NOT NULL DEFAULT '[]',  -- JSON array, e.g. ["mon","tue",...]
    schedule_start     TEXT NOT NULL DEFAULT '00:00', -- "HH:MM", appliance-local time
    schedule_end       TEXT NOT NULL DEFAULT '23:59',
    schedule_all_day   INTEGER NOT NULL DEFAULT 0,
    updated_at         TEXT NOT NULL DEFAULT ''
);
INSERT INTO blocked_services_settings (id, updated_at) VALUES (1, '');
