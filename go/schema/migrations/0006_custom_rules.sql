-- 0006_custom_rules: native Go schema for Custom Filtering Rules. Per
-- docs/v2/v2-roadmap.md's locked "Custom Rules" decision, this is new
-- functionality (Python V2 has no custom-rules API at all yet -- only
-- V1's app/custom_rules.py, a free-text AdGuard-syntax parser). A
-- structured "modern rule builder" is explicitly permitted as an
-- addition; see internal/customrules's doc comment for what's
-- deliberately not carried over from V1 (free-text syntax parsing/import).
CREATE TABLE custom_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type      TEXT NOT NULL CHECK(rule_type IN ('block','allow','regex_block','regex_allow','rewrite')),
    pattern        TEXT NOT NULL,
    rewrite_target TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1,
    priority       INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL
);

CREATE INDEX idx_custom_rules_priority ON custom_rules(priority);
