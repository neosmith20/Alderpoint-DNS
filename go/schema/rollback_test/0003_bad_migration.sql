-- 0003_bad_migration: DELIBERATELY INVALID, kept out of schema/migrations/
-- so it never runs during normal startup. Used only by the migration
-- rollback acceptance test (tests/acceptance.py): SQLite rejects a NOT
-- NULL column add with no DEFAULT on a non-empty table, so applying this
-- inside a transaction must fail and roll back cleanly, leaving
-- schema_migrations at version 2 and the table unchanged.
ALTER TABLE blocklist_subscriptions ADD COLUMN required_field TEXT NOT NULL;
