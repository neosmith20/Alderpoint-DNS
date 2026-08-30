package httpapi

// HTTP-layer proof for Statistics settings (GET/PUT
// /api/statistics/settings): real persistence to the analytics_settings
// row plus the live SettingsHolder swap the analytics Writer reads on
// its own hot path.

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/dnsanalytics"
)

func getAnalyticsSettingsReq(t *testing.T, s *Server) (int, dnsanalytics.Settings) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/statistics/settings", nil)
	rec := httptest.NewRecorder()
	s.handleGetAnalyticsSettings(rec, req)
	var out dnsanalytics.Settings
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, out
}

func putAnalyticsSettingsReq(t *testing.T, s *Server, body dnsanalytics.Settings) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("PUT", "/api/statistics/settings", bytes.NewReader(raw))
	// handleUpdateAnalyticsSettings records a real audit entry
	// (2026-08-30: Administration parity), which needs a real session
	// in context -- requireAuth always provides one in production.
	req = req.WithContext(auth.WithSession(req.Context(), &auth.Session{AdminID: 0, Username: "test"}))
	rec := httptest.NewRecorder()
	s.handleUpdateAnalyticsSettings(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestAnalyticsSettingsDefaultsMatchMigration(t *testing.T) {
	s := newTestDomainTestServer(t)
	s.AnalyticsSettings = dnsanalytics.NewSettingsHolder(dnsanalytics.DefaultSettings())
	code, got := getAnalyticsSettingsReq(t, s)
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	want := dnsanalytics.DefaultSettings()
	if got != want {
		t.Fatalf("expected the migration's own defaults, got %+v want %+v", got, want)
	}
}

func TestAnalyticsSettingsUpdatePersistsAndSwapsHolder(t *testing.T) {
	s := newTestDomainTestServer(t)
	holder := dnsanalytics.NewSettingsHolder(dnsanalytics.DefaultSettings())
	s.AnalyticsSettings = holder

	next := dnsanalytics.Settings{
		AnalyticsEnabled:            true,
		DetailedQueryLoggingEnabled: false,
		PrivacyMode:                 "aggregate_only",
		ClientAnonymization:         "hash",
		DetailedRetentionDays:       3,
		DBSizeLimitBytes:            10 * 1024 * 1024,
		RecentQueryLimit:            50,
	}
	code, _ := putAnalyticsSettingsReq(t, s, next)
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}

	// Persisted: a fresh GET (independent of the in-memory holder) sees it.
	_, got := getAnalyticsSettingsReq(t, s)
	if got != next {
		t.Fatalf("expected the saved settings to persist, got %+v want %+v", got, next)
	}

	// Live holder swapped: the Writer's own hot-path read sees it immediately.
	if holder.Load() != next {
		t.Fatalf("expected the SettingsHolder to be swapped in place, got %+v want %+v", holder.Load(), next)
	}
}

func TestAnalyticsSettingsUpdateRejectsInvalidPrivacyMode(t *testing.T) {
	s := newTestDomainTestServer(t)
	s.AnalyticsSettings = dnsanalytics.NewSettingsHolder(dnsanalytics.DefaultSettings())
	bad := dnsanalytics.DefaultSettings()
	bad.PrivacyMode = "not-a-real-mode"
	code, body := putAnalyticsSettingsReq(t, s, bad)
	if code != 400 {
		t.Fatalf("expected 400 for an invalid privacy_mode, got %d (%v)", code, body)
	}
}

func TestAnalyticsSettingsUpdateRejectsTooSmallSizeLimit(t *testing.T) {
	s := newTestDomainTestServer(t)
	s.AnalyticsSettings = dnsanalytics.NewSettingsHolder(dnsanalytics.DefaultSettings())
	bad := dnsanalytics.DefaultSettings()
	bad.DBSizeLimitBytes = 100
	code, body := putAnalyticsSettingsReq(t, s, bad)
	if code != 400 {
		t.Fatalf("expected 400 for a too-small db_size_limit_bytes, got %d (%v)", code, body)
	}
}
