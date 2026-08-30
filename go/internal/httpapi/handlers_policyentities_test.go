package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/policyentities"
)

func newPolicyEntitiesTestServer(t *testing.T) *Server {
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
	return &Server{DB: db, PolicyEntities: &policyentities.Service{DB: db}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decoding response body %q: %v", rec.Body.String(), err)
	}
	return body
}

func TestHandleFilteringProfilesCRUD(t *testing.T) {
	s := newPolicyEntitiesTestServer(t)

	create := httptest.NewRequest("POST", "/api/policy-entities/filtering-profiles", bytes.NewReader([]byte(`{"id":"standard","name":"Standard","categories":["malware","ads_trackers"]}`)))
	rec := httptest.NewRecorder()
	s.handleCreateFilteringProfile(rec, create)
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	list := httptest.NewRequest("GET", "/api/policy-entities/filtering-profiles", nil)
	rec = httptest.NewRecorder()
	s.handleListFilteringProfiles(rec, list)
	body := decodeBody(t, rec)
	profiles, _ := body["profiles"].([]any)
	if len(profiles) != 1 {
		t.Fatalf("expected one profile listed, got %+v", body)
	}

	dup := httptest.NewRequest("POST", "/api/policy-entities/filtering-profiles", bytes.NewReader([]byte(`{"id":"standard","name":"Dup"}`)))
	rec = httptest.NewRecorder()
	s.handleCreateFilteringProfile(rec, dup)
	if rec.Code != 409 {
		t.Fatalf("expected 409 conflict for a duplicate id, got %d: %s", rec.Code, rec.Body.String())
	}

	upd := httptest.NewRequest("PUT", "/api/policy-entities/filtering-profiles/standard", bytes.NewReader([]byte(`{"name":"Standard Protection","categories":["malware"]}`)))
	upd.SetPathValue("id", "standard")
	rec = httptest.NewRecorder()
	s.handleUpdateFilteringProfile(rec, upd)
	if rec.Code != 200 {
		t.Fatalf("expected 200 on update, got %d: %s", rec.Code, rec.Body.String())
	}

	del := httptest.NewRequest("DELETE", "/api/policy-entities/filtering-profiles/standard", nil)
	del.SetPathValue("id", "standard")
	rec = httptest.NewRecorder()
	s.handleDeleteFilteringProfile(rec, del)
	if rec.Code != 200 {
		t.Fatalf("expected 200 on delete, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleParentalPolicyValidatesSafesearchMode(t *testing.T) {
	s := newPolicyEntitiesTestServer(t)
	req := httptest.NewRequest("POST", "/api/policy-entities/parental-policies", bytes.NewReader([]byte(`{"id":"kids","name":"Kids","safesearch_mode":"not-real"}`)))
	rec := httptest.NewRecorder()
	s.handleCreateParentalPolicy(rec, req)
	if rec.Code != 400 {
		t.Fatalf("expected 400 validation error for a bad safesearch_mode, got %d: %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("POST", "/api/policy-entities/parental-policies", bytes.NewReader([]byte(`{"id":"kids","name":"Kids","safesearch_mode":"strict","categories":["adult_content"]}`)))
	rec = httptest.NewRecorder()
	s.handleCreateParentalPolicy(rec, req)
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleServiceBlockingRulesetCRUD(t *testing.T) {
	s := newPolicyEntitiesTestServer(t)
	req := httptest.NewRequest("POST", "/api/policy-entities/service-blocking-rulesets", bytes.NewReader([]byte(`{"id":"social","name":"Social Apps","domains":["example-social.com"]}`)))
	rec := httptest.NewRecorder()
	s.handleCreateServiceBlockingRuleset(rec, req)
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	list := httptest.NewRequest("GET", "/api/policy-entities/service-blocking-rulesets", nil)
	rec = httptest.NewRecorder()
	s.handleListServiceBlockingRulesets(rec, list)
	body := decodeBody(t, rec)
	rulesets, _ := body["rulesets"].([]any)
	if len(rulesets) != 1 {
		t.Fatalf("expected one ruleset listed, got %+v", body)
	}
}
