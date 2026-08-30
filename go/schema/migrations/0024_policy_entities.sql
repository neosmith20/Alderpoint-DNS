-- 0024_policy_entities: real, ownable entities for the four
-- policy_layers ID-reference fields that previously pointed at nothing
-- (filtering_profile_id, parental_policy_id, security_policy_id,
-- service_blocking_ruleset_id -- confirmed absent from V1.1.1 entirely
-- and never backed by any Go storage; see internal/policycompile's own
-- doc comment for the full V1 evidence), plus ruleset grouping for
-- domain_routing_rules so domain routing can differ per scope
-- (0010_domain_routing's own comment disclosed this as deferred --
-- closed here).
--
-- Filtering Profile / Parental Policy / Security Policy are
-- deliberately three separate tables with the identical
-- (id, name, description, ...) + a category-membership join table
-- shape, not one shared table with a "kind" column: each is its own
-- real, independently-managed owner-facing entity (own CRUD, own API,
-- own UI section), matching the owner's explicit choice to keep them
-- distinct rather than consolidated into one generic "profile" concept.
CREATE TABLE filtering_profiles (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE filtering_profile_categories (
    profile_id TEXT NOT NULL REFERENCES filtering_profiles(id) ON DELETE CASCADE,
    category   TEXT NOT NULL,
    PRIMARY KEY(profile_id, category)
);

CREATE TABLE parental_policies (
    id             TEXT PRIMARY KEY,
    name           TEXT NOT NULL UNIQUE,
    description    TEXT NOT NULL DEFAULT '',
    safesearch_mode TEXT NOT NULL DEFAULT 'off' CHECK(safesearch_mode IN ('off','moderate','strict')),
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);
CREATE TABLE parental_policy_categories (
    policy_id TEXT NOT NULL REFERENCES parental_policies(id) ON DELETE CASCADE,
    category  TEXT NOT NULL,
    PRIMARY KEY(policy_id, category)
);

CREATE TABLE security_policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE security_policy_categories (
    policy_id TEXT NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    category  TEXT NOT NULL,
    PRIMARY KEY(policy_id, category)
);

-- Service Blocking Ruleset is domain-based, not category-based -- it
-- blocks specific named services (e.g. a social-media app) by their
-- own known domains, orthogonal to the blocklist-subscription/category
-- system the three tables above draw from.
CREATE TABLE service_blocking_rulesets (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE service_blocking_ruleset_domains (
    ruleset_id TEXT NOT NULL REFERENCES service_blocking_rulesets(id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    PRIMARY KEY(ruleset_id, domain)
);

CREATE TABLE domain_routing_rulesets (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
-- Nullable, additive: existing rows (ruleset_id IS NULL) keep exactly
-- today's behavior (apply globally, in every compiled scope) -- see
-- internal/domainrouting's own updated doc comment. SQLite's
-- ALTER TABLE ADD COLUMN with no NOT NULL/DEFAULT-less constraint is
-- safe on an existing table (every prior row gets NULL), matching this
-- schema's own established migration-adds-a-column convention (see
-- 0022/0023's own _ensure-column-free straight ADD COLUMNs).
ALTER TABLE domain_routing_rules ADD COLUMN ruleset_id TEXT REFERENCES domain_routing_rulesets(id) ON DELETE CASCADE;

CREATE INDEX idx_domain_routing_rules_ruleset ON domain_routing_rules(ruleset_id);
