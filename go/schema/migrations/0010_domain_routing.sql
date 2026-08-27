-- 0010_domain_routing: native Go schema for domain-specific upstream
-- routing, matching app/v2/policy_store.py's domain_routing_rules table
-- field-for-field, narrowed to one implicit global ruleset -- see
-- internal/domainrouting's own doc comment for exactly what was
-- preserved (match_kind/domain/upstream_profile_id, uniqueness,
-- validation) and what's deliberately deferred (Python's own
-- ruleset_id concept, since internal/dnscompile has no per-network
-- resolution engine to select a different ruleset by yet -- there is
-- exactly one compiled scope today, matching every other policy row's
-- own "global scope only" narrowing).
--
-- The REFERENCES/ON DELETE CASCADE clause below is advisory
-- documentation of the relationship only, same as upstream_endpoints's
-- own pre-existing FK to upstream_profiles: this codebase's SQLite
-- connections never set PRAGMA foreign_keys=ON, so it is not actually
-- enforced or cascaded by SQLite itself -- internal/domainrouting.Create
-- checks the referenced profile's existence explicitly in application
-- code instead.
CREATE TABLE domain_routing_rules (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    match_kind          TEXT NOT NULL CHECK(match_kind IN ('exact', 'suffix')),
    domain              TEXT NOT NULL,
    upstream_profile_id TEXT NOT NULL REFERENCES upstream_profiles(upstream_profile_id) ON DELETE CASCADE,
    created_at          TEXT NOT NULL,
    UNIQUE(match_kind, domain)
);
