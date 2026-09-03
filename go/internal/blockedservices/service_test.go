package blockedservices

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/policyentities"

	_ "modernc.org/sqlite"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &Service{DB: db, Policy: &policy.Service{DB: db}, PolicyEntities: &policyentities.Service{DB: db}}
}

func TestSetEnabledServicesCompilesRulesetAndAssignsGlobalPolicy(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	settings, err := s.SetEnabledServices(ctx, []string{"facebook", "youtube", "not-a-real-service"})
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.EnabledServiceIDs) != 2 {
		t.Fatalf("expected the unknown id to be dropped, got %v", settings.EnabledServiceIDs)
	}

	rulesets, err := s.PolicyEntities.ListServiceBlockingRulesets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got *policyentities.ServiceBlockingRuleset
	for i := range rulesets {
		if rulesets[i].ID == RulesetID {
			got = &rulesets[i]
		}
	}
	if got == nil {
		t.Fatal("expected the reserved ruleset to exist after toggling services on")
	}
	domainSet := map[string]bool{}
	for _, d := range got.Domains {
		domainSet[d] = true
	}
	if !domainSet["facebook.com"] || !domainSet["youtube.com"] {
		t.Fatalf("expected the ruleset's domains to include both toggled services' real domains, got %v", got.Domains)
	}

	layer, err := s.Policy.Load(ctx, "global", "global")
	if err != nil {
		t.Fatal(err)
	}
	if layer.ServiceBlockingRulesetID == nil || *layer.ServiceBlockingRulesetID != RulesetID {
		t.Fatalf("expected global policy to point at the reserved ruleset, got %v", layer.ServiceBlockingRulesetID)
	}
}

func TestSetEnabledServicesEmptyClearsRulesetDomains(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.SetEnabledServices(ctx, []string{"facebook"}); err != nil {
		t.Fatal(err)
	}
	settings, err := s.SetEnabledServices(ctx, []string{})
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.EnabledServiceIDs) != 0 {
		t.Fatalf("expected no enabled services, got %v", settings.EnabledServiceIDs)
	}
	rulesets, err := s.PolicyEntities.ListServiceBlockingRulesets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rulesets {
		if r.ID == RulesetID && len(r.Domains) != 0 {
			t.Fatalf("expected the reserved ruleset to have zero domains once nothing is toggled on, got %v", r.Domains)
		}
	}
}

func TestScheduleWindowGatesEnforcement(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.SetEnabledServices(ctx, []string{"facebook"}); err != nil {
		t.Fatal(err)
	}

	// Fixed "now": a real Wednesday 10:00.
	fixedNow := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC) // a Wednesday
	s.Now = func() time.Time { return fixedNow }

	// Schedule active only Mon/Tue/Thu/Fri (not Wednesday) -- outside the window.
	settings, err := s.SetSchedule(ctx, ScheduleInput{Enabled: true, Days: []string{"mon", "tue", "thu", "fri"}, Start: "00:00", End: "23:59"})
	if err != nil {
		t.Fatal(err)
	}
	if settings.ScheduleActiveNow {
		t.Fatal("expected the schedule to be inactive on a day not in its own list")
	}
	rulesets, err := s.PolicyEntities.ListServiceBlockingRulesets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rulesets {
		if r.ID == RulesetID && len(r.Domains) != 0 {
			t.Fatalf("expected zero enforced domains outside the schedule window, got %v", r.Domains)
		}
	}
	if settings.NextActivation == nil {
		t.Fatal("expected a real next-activation time to be computed")
	}

	// Now include Wednesday and a time window that covers 10:00 -- active.
	settings, err = s.SetSchedule(ctx, ScheduleInput{Enabled: true, Days: []string{"wed"}, Start: "09:00", End: "11:00"})
	if err != nil {
		t.Fatal(err)
	}
	if !settings.ScheduleActiveNow {
		t.Fatal("expected the schedule to be active: correct day, correct time window")
	}
	if settings.NextActivation != nil {
		t.Fatalf("expected no next-activation while already active, got %v", *settings.NextActivation)
	}
}
