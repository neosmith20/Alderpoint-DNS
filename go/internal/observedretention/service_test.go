package observedretention

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dbmigrate"

	_ "modernc.org/sqlite"
)

// fakeAnalytics is a minimal in-memory stand-in for dnsanalytics.Reader
// so these tests never need a real analytics database -- just the
// PreviewStaleClients/CleanStaleClients contract this package actually
// depends on (AnalyticsCleaner).
type fakeAnalytics struct {
	staleAtCutoff map[int64]int // cutoff -> how many clients CleanStaleClients should report removed
	cleanCalls    []int64
	failNext      error
}

func (f *fakeAnalytics) PreviewStaleClients(ctx context.Context, cutoff int64) (int, error) {
	return f.staleAtCutoff[cutoff], nil
}

func (f *fakeAnalytics) CleanStaleClients(ctx context.Context, cutoff int64) (int, error) {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return 0, err
	}
	f.cleanCalls = append(f.cleanCalls, cutoff)
	return f.staleAtCutoff[cutoff], nil
}

func newTestService(t *testing.T) (*Service, *fakeAnalytics) {
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
	fa := &fakeAnalytics{staleAtCutoff: map[int64]int{}}
	return &Service{DB: db, Analytics: fa}, fa
}

func TestSettingsDefaultsAreSafe(t *testing.T) {
	svc, _ := newTestService(t)
	got, err := svc.GetSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Schedule != "manual" {
		t.Errorf("schedule = %q, want %q (auto-clean off by default -- never silently start deleting on upgrade)", got.Schedule, "manual")
	}
	if got.RetentionDays != 90 {
		t.Errorf("retention_days = %d, want 90 (a safe default, comfortably beyond routine absence)", got.RetentionDays)
	}
	if got.LastRunAt != "" {
		t.Errorf("expected no prior run recorded on a fresh instance, got %+v", got)
	}
}

func TestSetSettingsPersistsAndValidates(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	if err := svc.SetSettings(ctx, 30, "weekly"); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.RetentionDays != 30 || got.Schedule != "weekly" {
		t.Fatalf("settings did not persist, got %+v", got)
	}

	for _, tc := range []struct {
		name          string
		retentionDays int
		schedule      string
	}{
		{"zero retention (would mean delete everyone)", 0, "weekly"},
		{"negative retention", -1, "weekly"},
		{"retention too high", 3651, "weekly"},
		{"unknown schedule", 30, "hourly"},
	} {
		if err := svc.SetSettings(ctx, tc.retentionDays, tc.schedule); !errors.Is(err, ErrInvalidSettings) {
			t.Errorf("%s: expected ErrInvalidSettings, got %v", tc.name, err)
		}
	}
	// A rejected update must not have clobbered the real, previously-saved settings.
	after, err := svc.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.RetentionDays != 30 || after.Schedule != "weekly" {
		t.Fatalf("a rejected SetSettings call changed the stored settings: %+v", after)
	}
}

func TestCleanNowRecordsOutcomeAndReturnsRemovedCount(t *testing.T) {
	svc, fa := newTestService(t)
	ctx := context.Background()
	if err := svc.SetSettings(ctx, 30, "manual"); err != nil {
		t.Fatal(err)
	}
	cutoffTS := cutoff(30, time.Now().UTC())
	fa.staleAtCutoff[cutoffTS] = 3

	removed, err := svc.CleanNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 3 {
		t.Fatalf("CleanNow removed = %d, want 3", removed)
	}

	settings, err := svc.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.LastStatus != "succeeded" || settings.LastRunAt == "" || settings.LastRemovedClients != 3 {
		t.Fatalf("expected the run to be recorded, got %+v", settings)
	}
}

func TestCleanNowNoAnalyticsIsAClearError(t *testing.T) {
	svc, _ := newTestService(t)
	svc.Analytics = nil
	ctx := context.Background()

	_, err := svc.CleanNow(ctx)
	if !errors.Is(err, ErrAnalyticsUnavailable) {
		t.Fatalf("expected ErrAnalyticsUnavailable, got %v", err)
	}
	settings, err := svc.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.LastStatus != "failed" {
		t.Fatalf("expected the failure to be recorded, got %+v", settings)
	}
}

func TestDueForCleanupManualNeverAutoRuns(t *testing.T) {
	// Even with no prior run ever recorded, "manual" must never be due --
	// this is the safe-default guarantee: an appliance with auto-clean
	// off never silently starts deleting on its own.
	if dueForCleanup(Settings{Schedule: "manual"}, time.Now()) {
		t.Fatal("schedule=manual must never be due, regardless of last_run_at")
	}
}

func TestDueForCleanupNeverRunYetIsAlwaysDueForAnAutoSchedule(t *testing.T) {
	for _, schedule := range []string{"daily", "weekly", "monthly"} {
		if !dueForCleanup(Settings{Schedule: schedule}, time.Now()) {
			t.Errorf("schedule=%s with no prior run must be due immediately", schedule)
		}
	}
}

func TestDueForCleanupRespectsInterval(t *testing.T) {
	now := time.Now().UTC()
	settings := Settings{Schedule: "daily", LastRunAt: now.Add(-25 * time.Hour).Format(time.RFC3339)}
	if !dueForCleanup(settings, now) {
		t.Fatal("expected due once the daily interval has elapsed")
	}
	settings.LastRunAt = now.Add(-1 * time.Hour).Format(time.RFC3339)
	if dueForCleanup(settings, now) {
		t.Fatal("expected NOT due before the daily interval has elapsed")
	}
}

func TestRunTickOnceSkipsWhenNotDue(t *testing.T) {
	svc, fa := newTestService(t)
	ctx := context.Background()
	if err := svc.SetSettings(ctx, 90, "manual"); err != nil {
		t.Fatal(err)
	}
	result := svc.runTickOnce(ctx)
	if result.Ran {
		t.Fatal("expected no cleanup to run while schedule=manual")
	}
	if len(fa.cleanCalls) != 0 {
		t.Fatalf("expected CleanStaleClients never called, got %d calls", len(fa.cleanCalls))
	}
}

func TestRunTickOnceRunsWhenDue(t *testing.T) {
	svc, fa := newTestService(t)
	ctx := context.Background()
	if err := svc.SetSettings(ctx, 90, "daily"); err != nil {
		t.Fatal(err)
	}
	fa.staleAtCutoff[cutoff(90, time.Now().UTC())] = 5

	result := svc.runTickOnce(ctx)
	if !result.Ran || result.Failed || result.Removed != 5 {
		t.Fatalf("expected a real due cleanup to run successfully, got %+v", result)
	}

	// A second tick immediately after must NOT run again -- the real
	// interval (24h) has not elapsed.
	result2 := svc.runTickOnce(ctx)
	if result2.Ran {
		t.Fatal("expected the second tick to be a no-op (not yet due again)")
	}
	if len(fa.cleanCalls) != 1 {
		t.Fatalf("expected exactly one real clean call, got %d", len(fa.cleanCalls))
	}
}
