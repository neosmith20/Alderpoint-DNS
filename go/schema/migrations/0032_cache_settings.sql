-- Cache (Advanced) real BIND resolver-cache tuning: max/negative TTL,
-- prefetch, serve-stale. Distinct from dnsdist's own packet-cache size/
-- TTL (dnscompile.Input.CacheMaxEntries/CacheMaxTTLSeconds, already
-- real, dnsdist-side) -- this table governs BIND's own options{} block,
-- which is what the Cache page's real hit/miss counters actually
-- measure (rndc/stats-channel), so this is the cache these settings
-- should actually affect.
CREATE TABLE cache_settings (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    max_cache_ttl_seconds     INTEGER NOT NULL DEFAULT 604800, -- BIND default: 1 week
    max_negative_ttl_seconds  INTEGER NOT NULL DEFAULT 10800,  -- BIND default: 3 hours
    prefetch_enabled          INTEGER NOT NULL DEFAULT 1,      -- BIND default: on
    serve_stale_enabled       INTEGER NOT NULL DEFAULT 0,
    max_stale_ttl_seconds     INTEGER NOT NULL DEFAULT 86400,  -- only used when serve_stale_enabled
    updated_at                TEXT NOT NULL DEFAULT ''
);
INSERT INTO cache_settings (id, updated_at) VALUES (1, '');
