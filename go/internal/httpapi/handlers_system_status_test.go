package httpapi

// Real proof for System Status' 2026-09-03 expansion: database sizes,
// last DNS deployment, and recent warnings (see the user-facing
// instruction this closes: "Expand System Status with database sizes,
// last DNS deployment and recent warnings"). All three are backed by
// real, already-persisted rows -- nothing synthesized.

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnsgenerations"
	"alderpointdns/go-controlplane/internal/notifications"
	"alderpointdns/go-controlplane/internal/updatehistory"
)

func newSystemStatusTestServer(t *testing.T) (*Server, string) {
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
	s := &Server{
		DB:            db,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		Generations:   &dnsgenerations.Store{DB: db},
		UpdateHistory: &updatehistory.Service{DB: db},
		Notifications: &notifications.Service{DB: db},
		ControlDBPath: dbPath,
	}
	return s, dbPath
}

func TestSystemStatusReportsRealDatabaseSize(t *testing.T) {
	s, dbPath := newSystemStatusTestServer(t)
	sizes := s.databaseSizes()
	if len(sizes) != 1 {
		t.Fatalf("expected exactly one database entry (only ControlDBPath is set), got %+v", sizes)
	}
	entry := sizes[0]
	if entry["path"] != dbPath {
		t.Fatalf("expected path %q, got %+v", dbPath, entry)
	}
	bytes, ok := entry["bytes"].(int64)
	if !ok || bytes <= 0 {
		t.Fatalf("expected a real positive byte count for a migrated sqlite db, got %+v", entry)
	}
}

func TestSystemStatusDatabaseSizeUnavailableWhenPathMissing(t *testing.T) {
	s, _ := newSystemStatusTestServer(t)
	s.ControlDBPath = filepath.Join(t.TempDir(), "does-not-exist.db")
	sizes := s.databaseSizes()
	if len(sizes) != 1 || sizes[0]["unavailable"] != true {
		t.Fatalf("expected an honest unavailable entry for a missing file, got %+v", sizes)
	}
}

func TestSystemStatusLastDNSDeploymentReflectsRealLatestPromotedGeneration(t *testing.T) {
	s, _ := newSystemStatusTestServer(t)
	ctx := context.Background()

	if got := s.lastDNSDeployment(ctx); got != nil {
		t.Fatalf("expected nil before any generation was ever promoted, got %+v", got)
	}

	if _, err := s.Generations.Record(ctx, dnsgenerations.RecordInput{Trigger: "manual_apply", Promoted: true, DnsdistConf: "-- gen1"}); err != nil {
		t.Fatal(err)
	}
	num, err := s.Generations.Record(ctx, dnsgenerations.RecordInput{Trigger: "scheduled_recompile", Promoted: true, DnsdistConf: "-- gen2"})
	if err != nil {
		t.Fatal(err)
	}

	got := s.lastDNSDeployment(ctx)
	if got == nil {
		t.Fatal("expected a real last deployment after a promotion")
	}
	if got["generation_number"] != num {
		t.Fatalf("expected generation_number=%d (the most recent promotion), got %+v", num, got)
	}
	if got["trigger"] != "scheduled_recompile" {
		t.Fatalf("expected the real trigger of the latest promoted generation, got %+v", got)
	}
}

func TestSystemStatusRecentWarningsMergesAllThreeRealSourcesNewestFirst(t *testing.T) {
	s, _ := newSystemStatusTestServer(t)
	ctx := context.Background()

	// A failed generation -- real DNS Runtime warning source.
	if _, err := s.Generations.Record(ctx, dnsgenerations.RecordInput{
		Trigger: "manual_apply", Promoted: false, Error: "hostagent unreachable",
	}); err != nil {
		t.Fatal(err)
	}

	// A failed software update -- real Software Updates warning source.
	s.UpdateHistory.Record(ctx, updatehistory.RecordInput{
		FromVersion: "2.4.0", ToVersion: "2.5.0", Source: "manual", Result: "failed", Error: "backup step failed",
	})

	// A failed notification delivery -- real Notifications warning
	// source. recordHistory itself is unexported (dispatch.go), so this
	// inserts directly into the same real table it writes, matching
	// what a real dispatch attempt leaves behind.
	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO notification_history (at, event_category, severity, component, message, began_at, recovered, provider_id, provider_name, status, error)
		VALUES ('2026-09-03T10:00:00Z', 'deploy_failure', 'critical', 'dns_runtime', 'DNS deploy failed', '2026-09-03T10:00:00Z', 0, 'p1', 'Ops Slack', 'failed', 'connection refused')
	`); err != nil {
		t.Fatal(err)
	}
	// A successful, non-warning delivery -- must NOT appear.
	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO notification_history (at, event_category, severity, component, message, began_at, recovered, provider_id, provider_name, status, error)
		VALUES ('2026-09-03T11:00:00Z', 'deploy_failure', 'info', 'dns_runtime', 'DNS deployed fine', '2026-09-03T11:00:00Z', 1, 'p1', 'Ops Slack', 'sent', '')
	`); err != nil {
		t.Fatal(err)
	}

	warnings := s.recentWarnings(ctx)
	if len(warnings) != 3 {
		t.Fatalf("expected exactly 3 real warnings (the successful delivery must be excluded), got %d: %+v", len(warnings), warnings)
	}
	sources := map[string]bool{}
	for _, w := range warnings {
		sources[w.Source] = true
		if w.At == "" || w.Severity == "" || w.Message == "" {
			t.Fatalf("expected every warning to carry a real at/severity/message, got %+v", w)
		}
	}
	for _, want := range []string{"DNS Runtime", "Software Updates", "Notifications"} {
		if !sources[want] {
			t.Fatalf("expected a warning from %q, got sources=%+v full=%+v", want, sources, warnings)
		}
	}
}

func TestHandleSystemStatusIncludesTheThreeNewExpansionFields(t *testing.T) {
	s, _ := newSystemStatusTestServer(t)
	if _, err := s.Generations.Record(context.Background(), dnsgenerations.RecordInput{Trigger: "manual_apply", Promoted: true, DnsdistConf: "-- x"}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	s.handleSystemStatus(rec, httptest.NewRequest("GET", "/api/system/status", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["database_sizes"]; !ok {
		t.Fatalf("expected database_sizes in the response, got %+v", body)
	}
	if _, ok := body["last_dns_deployment"]; !ok {
		t.Fatalf("expected last_dns_deployment in the response, got %+v", body)
	}
	if _, ok := body["recent_warnings"]; !ok {
		t.Fatalf("expected recent_warnings in the response, got %+v", body)
	}
}
