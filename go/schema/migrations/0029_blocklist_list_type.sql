-- Allowlists (Standard > Filters > Allowlists): the exact same fetch/
-- parse/schedule/category pipeline blocklist_subscriptions already has,
-- distinguished only by list_type -- an allowlist subscription's own
-- compiled domains feed into the orchestrator's allowedSet instead of
-- blockedSet (see internal/dnsruntime/orchestrator.go), which already
-- always wins over a same-named block entry. Existing rows default to
-- 'block', a real no-op for every subscription that predates this
-- column.
ALTER TABLE blocklist_subscriptions ADD COLUMN list_type TEXT NOT NULL DEFAULT 'block';
