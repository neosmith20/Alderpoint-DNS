package httpapi

// HTTP-layer proof for the mandatory pre-upgrade backup guard on
// POST /api/updates/apply -- matching V1.1.1's own real
// system_software_updates.html guarantee ("A mandatory pre-upgrade
// backup is created before installation. If it fails, the update is
// aborted -- no changes are made.").

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func newUpdateApplyTestServer(t *testing.T) *Server {
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
	return &Server{DB: db, Backup: &backup.Service{DB: db, Dir: t.TempDir()}}
}

func TestUpdateApplyTakesRealBackupBeforeCallingAgent(t *testing.T) {
	s := newUpdateApplyTestServer(t)
	// No HostAgent configured -- if the handler reaches callAgent at all
	// (proving the mandatory backup step ran and succeeded first), it
	// must fail with a clean "unavailable", never a panic.
	req := httptest.NewRequest("POST", "/api/updates/apply", nil)
	// handleUpdateApply records a real audit entry once it reaches
	// callAgent (2026-08-30: Administration parity), which needs a real
	// session in context -- requireAuth always provides one in
	// production; this test drives the handler directly.
	req = req.WithContext(auth.WithSession(req.Context(), &auth.Session{AdminID: 0, Username: "test"}))
	rec := httptest.NewRecorder()
	s.handleUpdateApply(rec, req)
	if rec.Code != 503 {
		t.Fatalf("expected 503 (unavailable, reached via callAgent after a successful mandatory backup), got %d: %s", rec.Code, rec.Body.String())
	}

	backups, err := s.Backup.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, b := range backups {
		if b.Reason == "pre-update-safety" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a real pre-update-safety backup to have been created, got %+v", backups)
	}
}

func TestUpdateApplyAbortsWhenMandatoryBackupFails(t *testing.T) {
	s := newUpdateApplyTestServer(t)
	// Point the backup dir at a file (not a directory) so Create's own
	// MkdirAll fails -- a real, disclosed failure mode, not a mock.
	badDir := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(badDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.Backup.Dir = badDir

	req := httptest.NewRequest("POST", "/api/updates/apply", nil)
	rec := httptest.NewRecorder()
	s.handleUpdateApply(rec, req)
	if rec.Code != 500 {
		t.Fatalf("expected 500 when the mandatory backup fails, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "backup_failed" {
		t.Fatalf("expected error=backup_failed, got %v", body)
	}
}
