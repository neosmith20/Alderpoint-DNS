package httpapi

// HTTP-layer proof for Protection Control (POST /api/protection/toggle,
// GET /api/protection/status): real bulk enable/disable across real
// blocklists.Service + customrules.Service rows, not a hand-rolled
// status computation.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func protectionStatusReq(t *testing.T, s *Server) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", "/api/protection/status", nil)
	rec := httptest.NewRecorder()
	s.handleProtectionStatus(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

func protectionToggleReq(t *testing.T, s *Server) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/protection/toggle", nil)
	rec := httptest.NewRecorder()
	s.handleProtectionToggle(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, rec.Body.String())
	}
	return rec.Code, body
}

func TestProtectionToggleDisablesThenEnablesEverything(t *testing.T) {
	s := newTestDomainTestServer(t)
	ctx := context.Background()

	if _, _, err := s.Blocklists.Create(ctx, "sub-1", "Sub One", "http://example.com/list.txt", ""); err != nil {
		t.Fatalf("create blocklist: %v", err)
	}
	if _, err := s.CustomRules.Create(ctx, "block", "example.net", nil); err != nil {
		t.Fatalf("create custom rule: %v", err)
	}

	// Freshly created rows start enabled -- protection should read as active.
	if code, body := protectionStatusReq(t, s); code != 200 || body["active"] != true {
		t.Fatalf("expected active=true after create, got %d %v", code, body)
	}

	// Toggle #1: everything currently enabled -> disable all.
	if code, body := protectionToggleReq(t, s); code != 200 || body["active"] != false {
		t.Fatalf("expected active=false after first toggle, got %d %v", code, body)
	}
	subs, err := s.Blocklists.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range subs {
		if sub.Enabled {
			t.Fatalf("expected subscription %s disabled after toggle, still enabled", sub.SubscriptionID)
		}
	}
	rules, err := s.CustomRules.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Enabled {
			t.Fatalf("expected rule %d disabled after toggle, still enabled", rule.ID)
		}
	}
	if code, body := protectionStatusReq(t, s); code != 200 || body["active"] != false {
		t.Fatalf("expected active=false via status after toggle, got %d %v", code, body)
	}

	// Toggle #2: everything disabled -> re-enable all.
	if code, body := protectionToggleReq(t, s); code != 200 || body["active"] != true {
		t.Fatalf("expected active=true after second toggle, got %d %v", code, body)
	}
	subs, _ = s.Blocklists.List(ctx)
	for _, sub := range subs {
		if !sub.Enabled {
			t.Fatalf("expected subscription %s re-enabled after second toggle, still disabled", sub.SubscriptionID)
		}
	}
	rules, _ = s.CustomRules.List(ctx)
	for _, rule := range rules {
		if !rule.Enabled {
			t.Fatalf("expected rule %d re-enabled after second toggle, still disabled", rule.ID)
		}
	}
}

func TestProtectionStatusNoRowsIsInactive(t *testing.T) {
	s := newTestDomainTestServer(t)
	code, body := protectionStatusReq(t, s)
	if code != 200 {
		t.Fatalf("expected 200, got %d", code)
	}
	if body["active"] != false {
		t.Fatalf("expected active=false with no rows, got %v", body["active"])
	}
}
