// Package domainrouting is a native Go implementation of domain-specific
// upstream routing -- the last remaining real feature gap in the DNS
// Settings / Upstreams P0 workflow-parity row (see PARITY_MATRIX.md).
// Field shapes and validation are matched against
// app/v2/policy_store.py's domain_routing_rules table (match_kind
// exact/suffix, domain, upstream_profile_id, uniqueness on
// (match_kind, domain)), following the same "native Go schema + CRUD,
// not a compatibility boundary" pattern already proven by
// internal/upstreams (see that package's own doc comment for why).
//
// Ruleset grouping (0024_policy_entities.sql's ruleset_id column,
// domain_routing_rulesets table): a rule with RulesetID == "" (NULL in
// storage) applies globally, in every compiled scope -- exactly the
// prior "one implicit global ruleset" behavior, unchanged, so every
// pre-existing rule keeps working with no migration of its own data.
// A rule with a real RulesetID only applies to a scope whose own
// resolved domain_routing_ruleset_id names that ruleset (see
// internal/policycompile), letting a network/group/client override
// which named set of domain routes applies to it -- closing the gap
// this file's prior version disclosed.
//
// Not wired into internal/pymigrate: that importer's own doc comment
// scopes itself to "the five tables internal/dnscompile actually
// consumes" (local_dns_records, upstream_profiles+upstream_endpoints,
// dns_transport_settings, policy_layers global scope, and
// blocklist_subscriptions) as of when it was written -- domain routing
// now also meets that bar but was added after that importer, and a
// real migration needs its own cross-reference of Python's vs. Go's
// upstream_profile_id spaces plus its own tests, not a quiet one-line
// addition. Disclosed here rather than silently left out.
package domainrouting

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotFound   = errors.New("domain routing rule not found")
	ErrValidation = errors.New("domain routing rule validation failed")
)

type Rule struct {
	ID                int64  `json:"id"`
	MatchKind         string `json:"match_kind"` // "exact" | "suffix"
	Domain            string `json:"domain"`
	UpstreamProfileID string `json:"upstream_profile_id"`
	RulesetID         string `json:"ruleset_id,omitempty"` // "" = applies globally in every scope
	CreatedAt         string `json:"created_at"`
}

// Ruleset is a named group of Rules a policy scope can select via its
// own domain_routing_ruleset_id.
type Ruleset struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type Service struct {
	DB *sql.DB
}

// normalizeDomain mirrors internal/dnscompile's own normalizeDomain
// (lowercase, trailing-dot-stripped) -- rules are stored normalized so
// a later lookup/uniqueness check can never be fooled by case or a
// trailing dot that dnscompile would have normalized away anyway.
func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

func validate(matchKind, domain, upstreamProfileID string) (string, error) {
	if matchKind != "exact" && matchKind != "suffix" {
		return "", fmt.Errorf("%w: match_kind must be \"exact\" or \"suffix\", got %q", ErrValidation, matchKind)
	}
	domain = normalizeDomain(domain)
	if domain == "" {
		return "", fmt.Errorf("%w: domain is required", ErrValidation)
	}
	if upstreamProfileID == "" {
		return "", fmt.Errorf("%w: upstream_profile_id is required", ErrValidation)
	}
	return domain, nil
}

func (s *Service) List(ctx context.Context) ([]Rule, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, match_kind, domain, upstream_profile_id, COALESCE(ruleset_id, ''), created_at
		 FROM domain_routing_rules ORDER BY domain ASC, match_kind ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.MatchKind, &r.Domain, &r.UpstreamProfileID, &r.RulesetID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListForRuleset returns every rule belonging to rulesetID (used by
// internal/policycompile to compile a scope whose resolved
// domain_routing_ruleset_id names this ruleset). rulesetID == ""
// returns the global rules (RulesetID == ""), i.e. the same set every
// scope with no ruleset override already gets today.
func (s *Service) ListForRuleset(ctx context.Context, rulesetID string) ([]Rule, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(all))
	for _, r := range all {
		if r.RulesetID == rulesetID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Service) ListRulesets(ctx context.Context) ([]Ruleset, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, name, description, created_at, updated_at FROM domain_routing_rulesets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Ruleset{}
	for rows.Next() {
		var r Ruleset
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Service) CreateRuleset(ctx context.Context, id, name, description string) (Ruleset, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return Ruleset{}, fmt.Errorf("%w: id is required", ErrValidation)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Ruleset{}, fmt.Errorf("%w: name is required", ErrValidation)
	}
	now := nowStr()
	_, err := s.DB.ExecContext(ctx, `INSERT INTO domain_routing_rulesets(id, name, description, created_at, updated_at) VALUES (?,?,?,?,?)`, id, name, description, now, now)
	if err != nil {
		return Ruleset{}, fmt.Errorf("%w: a ruleset with that id or name already exists: %v", ErrValidation, err)
	}
	return Ruleset{ID: id, Name: name, Description: description, CreatedAt: now, UpdatedAt: now}, nil
}

// DeleteRuleset refuses to delete a ruleset still referenced by any
// policy_layers row OR still containing any rule -- never orphans a
// live policy assignment or silently detaches its own rules.
func (s *Service) DeleteRuleset(ctx context.Context, id string) error {
	var inPolicy int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_layers WHERE domain_routing_ruleset_id = ?`, id).Scan(&inPolicy); err != nil {
		return err
	}
	if inPolicy > 0 {
		return fmt.Errorf("%w: still assigned to at least one policy scope", ErrValidation)
	}
	var ruleCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM domain_routing_rules WHERE ruleset_id = ?`, id).Scan(&ruleCount); err != nil {
		return err
	}
	if ruleCount > 0 {
		return fmt.Errorf("%w: still contains %d rule(s) -- delete or reassign them first", ErrValidation, ruleCount)
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM domain_routing_rulesets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func nowStr() string { return time.Now().UTC().Format(time.RFC3339) }

// Create validates and inserts a rule. The referenced upstream profile's
// existence is checked explicitly here, in application code, not left
// to the schema's own FOREIGN KEY clause -- this codebase's SQLite
// connections don't set `PRAGMA foreign_keys=ON` (see
// cmd/alderpointdns-go/main.go's openDB), so that clause is advisory
// documentation of the relationship only, same as
// upstream_endpoints -> upstream_profiles' own pre-existing FK. A
// duplicate (match_kind, domain) pair fails via the schema's real,
// always-enforced UNIQUE constraint.
// Create validates and inserts a rule. rulesetID == "" makes the rule
// apply globally in every scope (unchanged prior behavior); a non-empty
// rulesetID must name an existing domain_routing_rulesets row.
func (s *Service) Create(ctx context.Context, matchKind, domain, upstreamProfileID, rulesetID string) (Rule, error) {
	domain, err := validate(matchKind, domain, upstreamProfileID)
	if err != nil {
		return Rule{}, err
	}
	var exists int
	if err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM upstream_profiles WHERE upstream_profile_id=?`, upstreamProfileID).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return Rule{}, fmt.Errorf("%w: unknown upstream_profile_id: %q", ErrValidation, upstreamProfileID)
		}
		return Rule{}, err
	}
	var rulesetArg any
	if rulesetID != "" {
		var rsExists int
		if err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM domain_routing_rulesets WHERE id=?`, rulesetID).Scan(&rsExists); err != nil {
			if err == sql.ErrNoRows {
				return Rule{}, fmt.Errorf("%w: unknown ruleset_id: %q", ErrValidation, rulesetID)
			}
			return Rule{}, err
		}
		rulesetArg = rulesetID
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO domain_routing_rules(match_kind, domain, upstream_profile_id, ruleset_id, created_at) VALUES(?,?,?,?,datetime('now'))`,
		matchKind, domain, upstreamProfileID, rulesetArg)
	if err != nil {
		return Rule{}, fmt.Errorf("%w: a rule for this exact match_kind+domain already exists: %v", ErrValidation, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Rule{}, err
	}
	var r Rule
	err = s.DB.QueryRowContext(ctx, `SELECT id, match_kind, domain, upstream_profile_id, COALESCE(ruleset_id, ''), created_at FROM domain_routing_rules WHERE id=?`, id).
		Scan(&r.ID, &r.MatchKind, &r.Domain, &r.UpstreamProfileID, &r.RulesetID, &r.CreatedAt)
	return r, err
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM domain_routing_rules WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
