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
// Deliberately narrower than Python's real design, disclosed rather
// than hidden: Python scopes these rules into named "rulesets" (a
// `ruleset_id` column, referenced by a policy layer's own
// `domain_routing_ruleset_id`), so a different network/group/client
// scope could in principle use a different ruleset. This package has
// exactly one implicit global ruleset -- the same "global scope only"
// narrowing internal/policy and internal/dnscompile already carry
// (there is no per-network effective-policy resolution engine in Go
// yet to select a different ruleset by). Every rule here compiles into
// every client's traffic, unconditionally.
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
	CreatedAt         string `json:"created_at"`
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
		`SELECT id, match_kind, domain, upstream_profile_id, created_at
		 FROM domain_routing_rules ORDER BY domain ASC, match_kind ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		if err := rows.Scan(&r.ID, &r.MatchKind, &r.Domain, &r.UpstreamProfileID, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Create validates and inserts a rule. The referenced upstream profile's
// existence is checked explicitly here, in application code, not left
// to the schema's own FOREIGN KEY clause -- this codebase's SQLite
// connections don't set `PRAGMA foreign_keys=ON` (see
// cmd/alderpointdns-go/main.go's openDB), so that clause is advisory
// documentation of the relationship only, same as
// upstream_endpoints -> upstream_profiles' own pre-existing FK. A
// duplicate (match_kind, domain) pair fails via the schema's real,
// always-enforced UNIQUE constraint.
func (s *Service) Create(ctx context.Context, matchKind, domain, upstreamProfileID string) (Rule, error) {
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
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO domain_routing_rules(match_kind, domain, upstream_profile_id, created_at) VALUES(?,?,?,datetime('now'))`,
		matchKind, domain, upstreamProfileID)
	if err != nil {
		return Rule{}, fmt.Errorf("%w: a rule for this exact match_kind+domain already exists: %v", ErrValidation, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Rule{}, err
	}
	var r Rule
	err = s.DB.QueryRowContext(ctx, `SELECT id, match_kind, domain, upstream_profile_id, created_at FROM domain_routing_rules WHERE id=?`, id).
		Scan(&r.ID, &r.MatchKind, &r.Domain, &r.UpstreamProfileID, &r.CreatedAt)
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
