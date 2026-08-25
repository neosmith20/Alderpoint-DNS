-- 0002_scheduler_index: the interval-scheduler goroutine polls for due
-- subscriptions on every tick; index the columns it filters on.
CREATE INDEX idx_blocklist_subscriptions_scheduling
    ON blocklist_subscriptions(enabled, update_in_progress, next_update_at);
