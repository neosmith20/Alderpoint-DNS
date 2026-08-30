package httpapi

// HTTP-layer proof for Administration's Sessions table and Recent
// Administrative Activity table (GET /api/administration/sessions,
// GET /api/administration/audit-log).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"alderpointdns/go-controlplane/internal/auditlog"
	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/dbmigrate"
)

func jsonBody(t *testing.T, v any) io.Reader {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(raw)
}

func newAdministrationTestServer(t *testing.T) (*Server, *auth.Session) {
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
	authStore := &auth.Store{DB: db}
	adminID, err := authStore.CreateFirstAdmin(context.Background(), "admin", "TestPassw0rd!123")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := authStore.Login(context.Background(), "admin", "TestPassw0rd!123", "203.0.113.9", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if sess.AdminID != adminID {
		t.Fatalf("expected session admin_id %d, got %d", adminID, sess.AdminID)
	}
	s := &Server{DB: db, Auth: authStore, AuditLog: &auditlog.Service{DB: db}}
	return s, sess
}

func TestListSessionsReportsRealSessionWithIsCurrent(t *testing.T) {
	s, sess := newAdministrationTestServer(t)
	req := httptest.NewRequest("GET", "/api/administration/sessions", nil)
	req = req.WithContext(auth.WithSession(req.Context(), sess))
	rec := httptest.NewRecorder()
	s.handleListSessions(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Sessions []struct {
			IP        string `json:"ip"`
			IsCurrent bool   `json:"is_current"`
		} `json:"sessions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Sessions) != 1 {
		t.Fatalf("expected exactly the one real session from Login, got %+v", body.Sessions)
	}
	if body.Sessions[0].IP != "203.0.113.9" {
		t.Fatalf("expected the real IP recorded at Login, got %q", body.Sessions[0].IP)
	}
	if !body.Sessions[0].IsCurrent {
		t.Fatalf("expected is_current=true for the session making this request")
	}
}

func TestListAuditLogReportsRealRecordedEntries(t *testing.T) {
	s, sess := newAdministrationTestServer(t)
	s.AuditLog.Record(context.Background(), sess.AdminID, sess.Username, "protection_disabled", true, "203.0.113.9", "")

	req := httptest.NewRequest("GET", "/api/administration/audit-log", nil)
	req = req.WithContext(auth.WithSession(req.Context(), sess))
	rec := httptest.NewRecorder()
	s.handleListAuditLog(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Entries []struct {
			Action  string `json:"action"`
			Success bool   `json:"success"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Entries) != 1 || body.Entries[0].Action != "protection_disabled" {
		t.Fatalf("expected the real recorded entry, got %+v", body.Entries)
	}
}

func TestChangePasswordRecordsRealAuditEntryOnSuccessAndFailure(t *testing.T) {
	s, sess := newAdministrationTestServer(t)

	// Wrong current password -> a real, recorded failure.
	req := httptest.NewRequest("POST", "/api/session/password", jsonBody(t, map[string]any{
		"current_password": "wrong", "new_password": "NewPassw0rd!123",
	}))
	req = req.WithContext(auth.WithSession(req.Context(), sess))
	rec := httptest.NewRecorder()
	s.handleChangePassword(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401 for a wrong current password, got %d: %s", rec.Code, rec.Body.String())
	}

	// Correct current password -> a real, recorded success.
	req2 := httptest.NewRequest("POST", "/api/session/password", jsonBody(t, map[string]any{
		"current_password": "TestPassw0rd!123", "new_password": "NewPassw0rd!123",
	}))
	req2 = req2.WithContext(auth.WithSession(req2.Context(), sess))
	rec2 := httptest.NewRecorder()
	s.handleChangePassword(rec2, req2)
	if rec2.Code != 200 {
		t.Fatalf("expected 200 for a correct password change, got %d: %s", rec2.Code, rec2.Body.String())
	}

	entries, err := s.AuditLog.List(context.Background(), sess.AdminID, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 recorded password_change entries (fail then success), got %d: %+v", len(entries), entries)
	}
	if entries[0].Action != "password_change" || !entries[0].Success {
		t.Fatalf("expected the most recent entry to be the successful change, got %+v", entries[0])
	}
	if entries[1].Success {
		t.Fatalf("expected the earlier entry to be the recorded failure, got %+v", entries[1])
	}
}
