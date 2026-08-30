package httpapi

// HTTP-layer proof for the real scheduled-backups settings routes
// (GET/PUT /api/backup/schedule).

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func newBackupScheduleTestServer(t *testing.T) *Server {
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
	return &Server{
		Backup: &backup.Service{DB: db, Dir: t.TempDir(), Version: "test"},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestBackupScheduleGetReturnsRealDefaults(t *testing.T) {
	s := newBackupScheduleTestServer(t)
	code, body := doHandler(t, s.handleGetBackupSchedule, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code=%d body=%+v", code, body)
	}
	if body["enabled"] != false {
		t.Errorf("expected enabled=false by default, got %+v", body)
	}
	if body["interval_hours"] != float64(24) {
		t.Errorf("expected interval_hours=24 by default, got %+v", body)
	}
	if body["retention_count"] != float64(7) {
		t.Errorf("expected retention_count=7 by default, got %+v", body)
	}
}

func TestBackupSchedulePutPersistsRealSettings(t *testing.T) {
	s := newBackupScheduleTestServer(t)
	code, body := doHandler(t, s.handleSetBackupSchedule, "PUT",
		`{"enabled":true,"interval_hours":12,"retention_count":3}`, nil)
	if code != 200 {
		t.Fatalf("put: code=%d body=%+v", code, body)
	}
	if body["enabled"] != true || body["interval_hours"] != float64(12) || body["retention_count"] != float64(3) {
		t.Fatalf("put response did not reflect saved settings: %+v", body)
	}

	code, body = doHandler(t, s.handleGetBackupSchedule, "GET", "", nil)
	if code != 200 {
		t.Fatalf("get after put: code=%d", code)
	}
	if body["enabled"] != true || body["interval_hours"] != float64(12) || body["retention_count"] != float64(3) {
		t.Fatalf("settings did not actually persist to the database: %+v", body)
	}
}

func TestBackupSchedulePutRejectsOutOfRangeValues(t *testing.T) {
	s := newBackupScheduleTestServer(t)
	for _, tc := range []string{
		`{"enabled":true,"interval_hours":0,"retention_count":7}`,
		`{"enabled":true,"interval_hours":721,"retention_count":7}`,
		`{"enabled":true,"interval_hours":24,"retention_count":-1}`,
		`{"enabled":true,"interval_hours":24,"retention_count":101}`,
	} {
		code, body := doHandler(t, s.handleSetBackupSchedule, "PUT", tc, nil)
		if code != 400 {
			t.Errorf("body=%s: expected 400, got %d (%+v)", tc, code, body)
		}
	}
	// A rejected update must not have changed the real, still-default settings.
	code, body := doHandler(t, s.handleGetBackupSchedule, "GET", "", nil)
	if code != 200 || body["interval_hours"] != float64(24) || body["retention_count"] != float64(7) {
		t.Fatalf("a rejected PUT changed the stored settings: %+v", body)
	}
}

func TestBackupSchedulePutRejectsMalformedJSON(t *testing.T) {
	s := newBackupScheduleTestServer(t)
	code, _ := doHandler(t, s.handleSetBackupSchedule, "PUT", `not json`, nil)
	if code != 400 {
		t.Fatalf("expected 400 for malformed JSON, got %d", code)
	}
}
