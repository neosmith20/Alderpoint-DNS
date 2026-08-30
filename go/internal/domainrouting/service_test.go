package domainrouting

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/upstreams"
)

func newTestService(t *testing.T) (*Service, *upstreams.Service) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Service{DB: db}, &upstreams.Service{DB: db}
}

func TestCreateRejectsInvalidMatchKind(t *testing.T) {
	s, up := newTestService(t)
	if err := up.Create(context.Background(), "corp", "Corp", "plain", "ordered", []upstreams.Endpoint{{Address: "10.0.0.1:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	_, err := s.Create(context.Background(), "wildcard", "example.com", "corp", "")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for an invalid match_kind, got %v", err)
	}
}

func TestCreateRejectsAnUnknownUpstreamProfileID(t *testing.T) {
	s, _ := newTestService(t)
	_, err := s.Create(context.Background(), "suffix", "example.com", "does-not-exist", "")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for an unknown upstream_profile_id, got %v", err)
	}
}

func TestCreateNormalizesDomainAndRejectsDuplicates(t *testing.T) {
	s, up := newTestService(t)
	if err := up.Create(context.Background(), "corp", "Corp", "plain", "ordered", []upstreams.Endpoint{{Address: "10.0.0.1:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Create(context.Background(), "suffix", "Example.COM.", "corp", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Domain != "example.com" {
		t.Fatalf("expected the domain to be normalized to lowercase with no trailing dot, got %q", r.Domain)
	}
	if _, err := s.Create(context.Background(), "suffix", "example.com", "corp", ""); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for a duplicate (match_kind, domain), got %v", err)
	}
	// A different match_kind for the same domain is not a duplicate.
	if _, err := s.Create(context.Background(), "exact", "example.com", "corp", ""); err != nil {
		t.Fatalf("expected exact+suffix for the same domain to coexist, got %v", err)
	}
}

func TestListReturnsCreatedRulesOrderedByDomain(t *testing.T) {
	s, up := newTestService(t)
	if err := up.Create(context.Background(), "corp", "Corp", "plain", "ordered", []upstreams.Endpoint{{Address: "10.0.0.1:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(context.Background(), "suffix", "z.example.com", "corp", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(context.Background(), "suffix", "a.example.com", "corp", ""); err != nil {
		t.Fatal(err)
	}
	rules, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0].Domain != "a.example.com" || rules[1].Domain != "z.example.com" {
		t.Fatalf("expected 2 rules ordered by domain, got %+v", rules)
	}
}

func TestDeleteRemovesARule(t *testing.T) {
	s, up := newTestService(t)
	if err := up.Create(context.Background(), "corp", "Corp", "plain", "ordered", []upstreams.Endpoint{{Address: "10.0.0.1:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Create(context.Background(), "suffix", "example.com", "corp", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	rules, err := s.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("expected the rule to be gone after delete, got %+v", rules)
	}
}

func TestDeleteUnknownIDReturnsNotFound(t *testing.T) {
	s, _ := newTestService(t)
	if err := s.Delete(context.Background(), 999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestRuleWithNoRulesetIDAppliesGlobally(t *testing.T) {
	s, up := newTestService(t)
	if err := up.Create(context.Background(), "corp", "Corp", "plain", "ordered", []upstreams.Endpoint{{Address: "10.0.0.1:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	r, err := s.Create(context.Background(), "suffix", "example.com", "corp", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.RulesetID != "" {
		t.Fatalf("expected empty RulesetID for a global rule, got %q", r.RulesetID)
	}
	global, err := s.ListForRuleset(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(global) != 1 || global[0].ID != r.ID {
		t.Fatalf("expected the global rule in ListForRuleset(\"\"), got %+v", global)
	}
}

func TestRuleWithRulesetIDIsScopedNotGlobal(t *testing.T) {
	s, up := newTestService(t)
	if err := up.Create(context.Background(), "corp", "Corp", "plain", "ordered", []upstreams.Endpoint{{Address: "10.0.0.1:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRuleset(context.Background(), "kids-routes", "Kids Routes", ""); err != nil {
		t.Fatal(err)
	}
	r, err := s.Create(context.Background(), "suffix", "example.com", "corp", "kids-routes")
	if err != nil {
		t.Fatal(err)
	}
	if r.RulesetID != "kids-routes" {
		t.Fatalf("expected RulesetID=kids-routes, got %q", r.RulesetID)
	}
	global, _ := s.ListForRuleset(context.Background(), "")
	if len(global) != 0 {
		t.Fatalf("a ruleset-scoped rule must not appear in the global (\"\") list, got %+v", global)
	}
	scoped, err := s.ListForRuleset(context.Background(), "kids-routes")
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || scoped[0].ID != r.ID {
		t.Fatalf("expected the rule under its own ruleset, got %+v", scoped)
	}
}

func TestCreateRejectsUnknownRulesetID(t *testing.T) {
	s, up := newTestService(t)
	if err := up.Create(context.Background(), "corp", "Corp", "plain", "ordered", []upstreams.Endpoint{{Address: "10.0.0.1:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create(context.Background(), "suffix", "example.com", "corp", "does-not-exist"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for an unknown ruleset_id, got %v", err)
	}
}

func TestDeleteRulesetRefusedWhilePolicyAssignedOrNonEmpty(t *testing.T) {
	s, up := newTestService(t)
	if err := up.Create(context.Background(), "corp", "Corp", "plain", "ordered", []upstreams.Endpoint{{Address: "10.0.0.1:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRuleset(context.Background(), "kids-routes", "Kids Routes", ""); err != nil {
		t.Fatal(err)
	}
	r, err := s.Create(context.Background(), "suffix", "example.com", "corp", "kids-routes")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRuleset(context.Background(), "kids-routes"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation while the ruleset still has a rule, got %v", err)
	}
	if err := s.Delete(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRuleset(context.Background(), "kids-routes"); err != nil {
		t.Fatalf("expected delete to succeed once empty, got %v", err)
	}
}
