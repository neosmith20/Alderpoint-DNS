package policyentities

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`
		CREATE TABLE policy_layers (id INTEGER PRIMARY KEY, scope TEXT, scope_ref TEXT,
			filtering_profile_id TEXT, parental_policy_id TEXT, security_policy_id TEXT,
			service_blocking_ruleset_id TEXT, domain_routing_ruleset_id TEXT);

		CREATE TABLE filtering_profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
		CREATE TABLE filtering_profile_categories (profile_id TEXT NOT NULL, category TEXT NOT NULL, PRIMARY KEY(profile_id, category));

		CREATE TABLE parental_policies (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', safesearch_mode TEXT NOT NULL DEFAULT 'off', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
		CREATE TABLE parental_policy_categories (policy_id TEXT NOT NULL, category TEXT NOT NULL, PRIMARY KEY(policy_id, category));

		CREATE TABLE security_policies (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
		CREATE TABLE security_policy_categories (policy_id TEXT NOT NULL, category TEXT NOT NULL, PRIMARY KEY(policy_id, category));

		CREATE TABLE service_blocking_rulesets (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
		CREATE TABLE service_blocking_ruleset_domains (ruleset_id TEXT NOT NULL, domain TEXT NOT NULL, PRIMARY KEY(ruleset_id, domain));
	`)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{DB: db}
}

func TestFilteringProfileCreateListUpdateDelete(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	p, err := s.CreateFilteringProfile(ctx, "standard", "Standard", "Everyday protection", []string{"malware", "ads_trackers", "malware"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Categories) != 2 {
		t.Fatalf("expected deduped categories, got %v", p.Categories)
	}

	list, err := s.ListFilteringProfiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "standard" || len(list[0].Categories) != 2 {
		t.Fatalf("unexpected list: %+v", list)
	}

	if err := s.UpdateFilteringProfile(ctx, "standard", "Standard Protection", "updated", []string{"malware"}); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListFilteringProfiles(ctx)
	if list[0].Name != "Standard Protection" || len(list[0].Categories) != 1 {
		t.Fatalf("update did not take effect: %+v", list[0])
	}

	if _, err := s.CreateFilteringProfile(ctx, "standard", "Dup", "", nil); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate for a reused id, got %v", err)
	}

	if err := s.DeleteFilteringProfile(ctx, "standard"); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListFilteringProfiles(ctx)
	if len(list) != 0 {
		t.Fatalf("expected empty list after delete, got %+v", list)
	}
}

func TestFilteringProfileDeleteRefusedWhileInUse(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateFilteringProfile(ctx, "kids", "Kids", "", []string{"adult_content"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO policy_layers(scope, scope_ref, filtering_profile_id) VALUES ('network','n1','kids')`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFilteringProfile(ctx, "kids"); !errors.Is(err, ErrInUse) {
		t.Fatalf("expected ErrInUse, got %v", err)
	}
}

func TestParentalPolicySafesearchModeValidatedAndPersisted(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	if _, err := s.CreateParentalPolicy(ctx, "strict-kids", "Strict Kids", "", "not-a-real-mode", nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for a bad safesearch_mode, got %v", err)
	}

	p, err := s.CreateParentalPolicy(ctx, "strict-kids", "Strict Kids", "", "strict", []string{"adult_content"})
	if err != nil {
		t.Fatal(err)
	}
	if p.SafesearchMode != "strict" {
		t.Fatalf("expected strict, got %q", p.SafesearchMode)
	}
	list, err := s.ListParentalPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].SafesearchMode != "strict" || len(list[0].Categories) != 1 {
		t.Fatalf("unexpected list: %+v", list)
	}

	if err := s.UpdateParentalPolicy(ctx, "strict-kids", "Strict Kids", "", "moderate", []string{"adult_content"}); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListParentalPolicies(ctx)
	if list[0].SafesearchMode != "moderate" {
		t.Fatalf("expected moderate after update, got %q", list[0].SafesearchMode)
	}
}

func TestSecurityPolicyCreateAndDeleteInUse(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateSecurityPolicy(ctx, "iot-sec", "IoT Security", "", []string{"malware", "iot_telemetry"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO policy_layers(scope, scope_ref, security_policy_id) VALUES ('network','n1','iot-sec')`); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSecurityPolicy(ctx, "iot-sec"); !errors.Is(err, ErrInUse) {
		t.Fatalf("expected ErrInUse, got %v", err)
	}
}

func TestServiceBlockingRulesetDomainsRoundTrip(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	r, err := s.CreateServiceBlockingRuleset(ctx, "social-apps", "Social Apps", "", []string{"Example-Social.com.", "example-social.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Domains) != 1 || r.Domains[0] != "example-social.com" {
		t.Fatalf("expected normalized, deduped domain, got %v", r.Domains)
	}
	list, err := s.ListServiceBlockingRulesets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || len(list[0].Domains) != 1 {
		t.Fatalf("unexpected list: %+v", list)
	}
	if err := s.UpdateServiceBlockingRuleset(ctx, "social-apps", "Social Apps", "", []string{"a.example", "b.example"}); err != nil {
		t.Fatal(err)
	}
	list, _ = s.ListServiceBlockingRulesets(ctx)
	if len(list[0].Domains) != 2 {
		t.Fatalf("expected 2 domains after update, got %v", list[0].Domains)
	}
}

func TestValidateIDRejectsUppercaseAndSpaces(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.CreateFilteringProfile(ctx, "Not Valid", "x", "", nil); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for an id with spaces/uppercase, got %v", err)
	}
}
