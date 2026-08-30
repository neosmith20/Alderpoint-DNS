package httpapi

// HTTP-layer proof for the real scheduled-backups settings routes
// (GET/PUT /api/backup/schedule).

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
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

// HTTP-layer proof for passphrase-protected native backups (2026-08-29,
// closing a real owner-facing gap versus V1.1.1's own optional
// password-protected archives) -- internal/backup's own encryption_test.go
// proves the crypto/service-layer logic; this proves the real routes
// (create/validate/restore) carry a passphrase correctly end to end and
// never accept a wrong one, and that create/upload/validate never echo
// a passphrase back in any response body.

func TestCreateBackupHTTPWithPassphraseIsEncryptedAndListShowsIt(t *testing.T) {
	s := newBackupScheduleTestServer(t)
	code, body := doHandler(t, s.handleCreateBackup, "POST", `{"passphrase":"a real test passphrase"}`, nil)
	if code != 201 {
		t.Fatalf("create: code=%d body=%+v", code, body)
	}
	backupInfo := body["backup"].(map[string]any)
	if backupInfo["encrypted"] != true {
		t.Fatalf("expected encrypted:true in the create response, got %+v", backupInfo)
	}
	respJSON, _ := json.Marshal(body)
	if strings.Contains(string(respJSON), "a real test passphrase") {
		t.Fatal("the passphrase must never be echoed back in the create response")
	}

	code, body = doHandler(t, s.handleListBackups, "GET", "", nil)
	if code != 200 {
		t.Fatalf("list: code=%d", code)
	}
	backups, _ := body["backups"].([]any)
	if len(backups) != 1 {
		t.Fatalf("expected exactly one backup listed, got %+v", backups)
	}
	row := backups[0].(map[string]any)
	if row["encrypted"] != true {
		t.Fatalf("expected the list row to report encrypted:true without needing a passphrase, got %+v", row)
	}
}

func TestPreviewBackupHTTPRequiresAndValidatesPassphrase(t *testing.T) {
	s := newBackupScheduleTestServer(t)
	code, body := doHandler(t, s.handleCreateBackup, "POST", `{"passphrase":"another real test passphrase"}`, nil)
	if code != 201 {
		t.Fatalf("create: code=%d body=%+v", code, body)
	}
	name := body["backup"].(map[string]any)["filename"].(string)

	code, body = doHandler(t, s.handlePreviewBackup, "POST", `{}`, map[string]string{"name": name})
	if code != 422 || body["error"] != "passphrase_required" {
		t.Fatalf("expected 422 passphrase_required with no passphrase, got code=%d body=%+v", code, body)
	}

	code, body = doHandler(t, s.handlePreviewBackup, "POST", `{"passphrase":"wrong"}`, map[string]string{"name": name})
	if code != 422 || body["error"] != "wrong_passphrase" {
		t.Fatalf("expected 422 wrong_passphrase, got code=%d body=%+v", code, body)
	}

	code, body = doHandler(t, s.handlePreviewBackup, "POST", `{"passphrase":"another real test passphrase"}`, map[string]string{"name": name})
	if code != 200 {
		t.Fatalf("expected 200 with the correct passphrase, got code=%d body=%+v", code, body)
	}
	if body["encrypted"] != true || body["table_counts"] == nil {
		t.Fatalf("expected a real, full preview once the correct passphrase is given, got %+v", body)
	}
}

func TestRestoreBackupHTTPRequiresAndValidatesPassphrase(t *testing.T) {
	s := newBackupScheduleTestServer(t)
	code, body := doHandler(t, s.handleCreateBackup, "POST", `{"passphrase":"restore test passphrase"}`, nil)
	if code != 201 {
		t.Fatalf("create: code=%d body=%+v", code, body)
	}
	name := body["backup"].(map[string]any)["filename"].(string)

	code, body = doHandler(t, s.handleRestoreBackup, "POST", `{}`, map[string]string{"name": name})
	if code != 422 || body["error"] != "passphrase_required" {
		t.Fatalf("expected 422 passphrase_required, got code=%d body=%+v", code, body)
	}

	code, body = doHandler(t, s.handleRestoreBackup, "POST", `{"passphrase":"nope"}`, map[string]string{"name": name})
	if code != 422 || body["error"] != "wrong_passphrase" {
		t.Fatalf("expected 422 wrong_passphrase, got code=%d body=%+v", code, body)
	}

	code, body = doHandler(t, s.handleRestoreBackup, "POST", `{"passphrase":"restore test passphrase"}`, map[string]string{"name": name})
	if code != 200 {
		t.Fatalf("expected 200 with the correct passphrase, got code=%d body=%+v", code, body)
	}
	// The mandatory pre-restore safety backup this real restore also
	// took must never itself be encrypted (see Restore's own doc
	// comment) -- reported right in this same response.
	safety := body["safety_backup"].(map[string]any)
	if safety["encrypted"] == true {
		t.Fatalf("expected the pre-restore safety backup to be unencrypted, got %+v", safety)
	}
}

func TestCreateBackupHTTPWithoutPassphraseIsUnencrypted(t *testing.T) {
	s := newBackupScheduleTestServer(t)
	code, body := doHandler(t, s.handleCreateBackup, "POST", "", nil)
	if code != 201 {
		t.Fatalf("create: code=%d body=%+v", code, body)
	}
	if body["backup"].(map[string]any)["encrypted"] != false {
		t.Fatalf("expected encrypted:false by default (backward-compatible, historical behavior), got %+v", body)
	}
}
