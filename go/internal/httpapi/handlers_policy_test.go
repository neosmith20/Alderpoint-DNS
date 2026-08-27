package httpapi

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/policy"
)

func newPolicyTestServer(t *testing.T) *Server {
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
		DB:      db,
		Policy:  &policy.Service{DB: db},
		Clients: &clients.Service{DB: db},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func putPolicy(t *testing.T, s *Server, path string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", path, bytes.NewReader([]byte(`{"blocking_response_mode":"refused"}`)))
	switch {
	case path == "/api/policy/global":
		s.handlePutGlobalPolicy(rec, req)
	case bytes.Contains([]byte(path), []byte("/network/")):
		req.SetPathValue("id", "net-1")
		s.handlePutNetworkPolicy(rec, req)
	case bytes.Contains([]byte(path), []byte("/group/")):
		req.SetPathValue("id", "grp-1")
		s.handlePutGroupPolicy(rec, req)
	case bytes.Contains([]byte(path), []byte("/client/")):
		req.SetPathValue("id", "1")
		s.handlePutClientPolicy(rec, req)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v\nbody: %s", err, rec.Body.String())
	}
	return body
}

// TestPutGlobalPolicyReportsARealDNSRuntimeAttemptNotAFakeSuccess is the
// direct regression proof for the bug this fix closes: this handler
// used to unconditionally respond with a hardcoded "promoted": true,
// "binding_count": 0 regardless of whether any compiled-runtime step
// ever ran at all -- a fake-success report matching the exact
// "Runtime / Control / UI Truth" P0 acceptance rule violation class
// already fixed for Upstreams/Custom Rules/Blocklists. With no
// s.DNSRuntime configured (as here), the real, honest answer is
// attempted=false, never promoted=true.
func TestPutGlobalPolicyReportsARealDNSRuntimeAttemptNotAFakeSuccess(t *testing.T) {
	s := newPolicyTestServer(t)
	body := putPolicy(t, s, "/api/policy/global")

	// With no s.DNSRuntime configured, applyDNSRuntimeBestEffort honestly
	// returns nil (JSON null) -- the same nil-safe contract every other
	// auto-applying mutation on this server already uses (Local DNS,
	// Upstreams, Custom Rules, Blocklists). The old bug this replaces
	// unconditionally returned {"promoted": true, "binding_count": 0}
	// here regardless of DNSRuntime's presence -- a fabricated success
	// that could never actually have happened.
	if v, present := body["dns_runtime"]; !present || v != nil {
		t.Fatalf("expected dns_runtime: null with no DNS runtime configured, got %+v", body)
	}
	if promoted, ok := body["promoted"].(bool); ok && promoted {
		t.Fatalf("must never report promoted=true at the top level either, got %+v", body)
	}
}

// TestPutNetworkGroupClientPolicyNeverClaimsCompiledRuntimeEffect proves
// the other half: internal/dnscompile only ever reads the *global*
// policy layer today (Orchestrator.build calls Policy.Load(ctx,
// "global", "global") only) -- a network/group/client-scoped save must
// never claim a compiled-runtime effect it cannot possibly have had,
// regardless of whether a DNS runtime is even configured on this
// deployment.
func TestPutNetworkGroupClientPolicyNeverClaimsCompiledRuntimeEffect(t *testing.T) {
	s := newPolicyTestServer(t)
	for _, path := range []string{"/api/policy/network/net-1", "/api/policy/group/grp-1", "/api/policy/client/1"} {
		body := putPolicy(t, s, path)
		runtime, ok := body["dns_runtime"].(map[string]any)
		if !ok {
			t.Fatalf("%s: expected a dns_runtime object, got %+v", path, body)
		}
		if attempted, _ := runtime["attempted"].(bool); attempted {
			t.Fatalf("%s: expected attempted=false for a scope the compiler never reads, got %+v", path, runtime)
		}
		if promoted, ok := runtime["promoted"].(bool); ok && promoted {
			t.Fatalf("%s: must never claim promoted=true for a scope that was never compiled, got %+v", path, runtime)
		}
		if detail, _ := runtime["detail"].(string); detail == "" {
			t.Fatalf("%s: expected an explicit, non-empty detail explaining why this scope isn't compiled, got %+v", path, runtime)
		}
	}
}

// TestPutGlobalPolicyActuallyPromotesARealDNSRuntime is the strongest
// proof of the whole fix: a real end-to-end chain, not just an honest
// "not attempted" fallback -- saving the global blocking_response_mode
// through this exact HTTP handler, with a real DNS runtime wired up
// (the same fixture internal/dnsruntime's own end-to-end test uses),
// actually reaches a real compile+promote cycle. Skips if the real DNS
// binaries aren't available, matching this repo's existing pattern.
func TestPutGlobalPolicyActuallyPromotesARealDNSRuntime(t *testing.T) {
	s, _ := newServerWithRealDNSRuntime(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PUT", "/api/policy/global", strings.NewReader(`{"blocking_response_mode":"refused"}`))
	s.handlePutGlobalPolicy(rec, req)

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v\nbody: %s", err, rec.Body.String())
	}
	runtime, ok := body["dns_runtime"].(map[string]any)
	if !ok {
		t.Fatalf("expected a real dns_runtime object with a DNS runtime configured, got %+v", body)
	}
	if attempted, _ := runtime["attempted"].(bool); !attempted {
		t.Fatalf("expected a real compile+promote attempt with a DNS runtime configured, got %+v", runtime)
	}
	if promoted, _ := runtime["promoted"].(bool); !promoted {
		t.Fatalf("expected the real promotion to succeed, got %+v", runtime)
	}
}

// TestHandlePolicyExplainResolvesTheRealPrecedenceStack is the HTTP-level
// proof for the "effective policy explain" feature: global -> network ->
// group -> client, through the real handler, real storage, real client
// group membership -- not a fixture double.
func TestHandlePolicyExplainResolvesTheRealPrecedenceStack(t *testing.T) {
	s := newPolicyTestServer(t)
	ctx := context.Background()

	if err := s.Policy.Save(ctx, "global", "global", policy.Layer{SafesearchMode: strPtr("off")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Policy.CreateNetwork(ctx, "corp-lan", "10.1.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := s.Policy.Save(ctx, "network", "corp-lan", policy.Layer{SafesearchMode: strPtr("moderate")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Clients.CreateGroup(ctx, "kids", "Kids", 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Policy.Save(ctx, "group", "kids", policy.Layer{SafesearchMode: strPtr("strict")}); err != nil {
		t.Fatal(err)
	}
	clientID, err := s.Clients.CreateClient(ctx, "Kid's Tablet", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Clients.AddToGroup(ctx, clientID, "kids"); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/policy/explain?client_id=%d&client_ip=10.1.5.5", clientID), nil)
	s.handlePolicyExplain(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["network_match"] != "network:corp-lan" {
		t.Fatalf("expected network_match=network:corp-lan, got %+v", body)
	}
	contributions, _ := body["group_contributions"].([]any)
	if len(contributions) != 1 || contributions[0] != "group:kids" {
		t.Fatalf("expected group_contributions=[group:kids], got %+v", body["group_contributions"])
	}
	fields, _ := body["fields"].(map[string]any)
	safesearch, _ := fields["safesearch_mode"].(map[string]any)
	if safesearch["value"] != "strict" || safesearch["source"] != "group:kids" {
		t.Fatalf("expected safesearch_mode=strict from group:kids (higher precedence than the matched network), got %+v", safesearch)
	}
}

func TestHandlePolicyExplainRequiresAValidClientID(t *testing.T) {
	s := newPolicyTestServer(t)
	rec := httptest.NewRecorder()
	s.handlePolicyExplain(rec, httptest.NewRequest("GET", "/api/policy/explain", nil))
	if rec.Code != 400 {
		t.Fatalf("expected 400 for a missing client_id, got %d", rec.Code)
	}
}

func strPtr(s string) *string { return &s }
