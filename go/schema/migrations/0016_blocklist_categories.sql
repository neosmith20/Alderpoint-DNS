-- 0016_blocklist_categories: real Custom Category create/rename/delete
-- for Blocklists (directive: "Custom category create; category rename;
-- category delete") -- blocklist_subscriptions.category was previously
-- just a free-text column with three hardcoded UI options (standard/
-- privacy/aggressive), with no real category entity to manage.
CREATE TABLE blocklist_categories (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Seed the three categories every existing subscription already uses,
-- so this migration never orphans a subscription's own category value.
INSERT INTO blocklist_categories (name, created_at, updated_at)
SELECT DISTINCT category, datetime('now'), datetime('now')
FROM blocklist_subscriptions
WHERE category IS NOT NULL AND category != '';

INSERT INTO blocklist_categories (name, created_at, updated_at)
SELECT 'standard', datetime('now'), datetime('now')
WHERE NOT EXISTS (SELECT 1 FROM blocklist_categories WHERE name = 'standard');
INSERT INTO blocklist_categories (name, created_at, updated_at)
SELECT 'privacy', datetime('now'), datetime('now')
WHERE NOT EXISTS (SELECT 1 FROM blocklist_categories WHERE name = 'privacy');
INSERT INTO blocklist_categories (name, created_at, updated_at)
SELECT 'aggressive', datetime('now'), datetime('now')
WHERE NOT EXISTS (SELECT 1 FROM blocklist_categories WHERE name = 'aggressive');
