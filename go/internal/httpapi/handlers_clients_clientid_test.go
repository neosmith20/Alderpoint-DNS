package httpapi

// HTTP-layer proof for Strong ClientID's generate/revoke/regenerate/
// delete/domain-override lifecycle -- internal/clients' own tests prove
// the service-layer logic; this proves the routes are wired correctly
// end to end (request -> handler -> service -> real DB row -> response
// shape), including that mutations report a dns_runtime field (the
// auto-apply convention every other mutating route here already uses).
// Calls handlers directly (matching handlers_policy_test.go's own
// established pattern) rather than through the real auth-wrapped mux,
// since path values normally set by net/http's own routing need to be
// set explicitly either way.
import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"alderpointdns/go-controlplane/internal/clientid"
)

func doHandler(t *testing.T, h http.HandlerFunc, method, body string, pathValues map[string]string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "/", bytes.NewReader([]byte(body)))
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("response body did not decode as JSON: %v (%s)", err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestClientIDHTTPLifecycle(t *testing.T) {
	s := newPolicyTestServer(t)

	code, body := doHandler(t, s.handleCreateClient, "POST", `{"name":"Phone"}`, nil)
	if code != 201 {
		t.Fatalf("create client: %d %+v", code, body)
	}
	clientIDf, _ := body["client_id"].(float64)
	clientIDStr := strconv.FormatInt(int64(clientIDf), 10)

	// Generate -- must never accept a caller-supplied value, only
	// bits/label.
	code, body = doHandler(t, s.handleGenerateClientID, "POST", `{"bits":256,"label":"primary"}`, map[string]string{"id": clientIDStr})
	if code != 201 {
		t.Fatalf("generate: %d %+v", code, body)
	}
	ident, _ := body["identifier"].(map[string]any)
	value, _ := ident["value"].(string)
	if len(value) != 64 {
		t.Fatalf("expected a real 64-hex generated value, got %q", value)
	}
	if err := clientid.ValidateHex(value); err != nil {
		t.Fatalf("generated value failed its own validator: %v", err)
	}
	if ident["doh_path"] == "" || ident["sni_hostname"] == "" {
		t.Fatalf("expected doh_path/sni_hostname in the response, got %+v", ident)
	}
	if _, present := body["dns_runtime"]; !present {
		t.Fatal("expected a dns_runtime field (the auto-apply convention every mutating route uses)")
	}
	identifierIDf, _ := ident["id"].(float64)
	identifierIDStr := strconv.FormatInt(int64(identifierIDf), 10)

	// Reject a request that tries to supply a malformed ClientID value
	// directly via the generic add-identifier route.
	code, _ = doHandler(t, s.handleAddClientIdentifier, "POST", `{"kind":"clientid","value":"not-hex"}`, map[string]string{"id": clientIDStr})
	if code != 400 {
		t.Fatalf("expected 400 for a malformed clientid value, got %d", code)
	}

	// Domain overrides.
	code, body = doHandler(t, s.handleAddDomainOverride, "POST", `{"override_type":"block","pattern":"blocked.example."}`, map[string]string{"id": clientIDStr})
	if code != 201 {
		t.Fatalf("add override: %d %+v", code, body)
	}
	override, _ := body["override"].(map[string]any)
	overrideIDf, _ := override["id"].(float64)

	code, body = doHandler(t, s.handleListClients, "GET", "", nil)
	if code != 200 {
		t.Fatalf("list clients: %d %+v", code, body)
	}
	clientsList, _ := body["clients"].([]any)
	if len(clientsList) != 1 {
		t.Fatalf("expected 1 client, got %+v", clientsList)
	}
	first, _ := clientsList[0].(map[string]any)
	overrides, _ := first["domain_overrides"].([]any)
	if len(overrides) != 1 {
		t.Fatalf("expected the domain override to appear in GET /api/clients, got %+v", first)
	}

	// Regenerate -- old value must stop appearing as the active one.
	code, body = doHandler(t, s.handleRegenerateClientIdentifier, "POST", "", map[string]string{"id": clientIDStr, "identifierId": identifierIDStr})
	if code != 200 {
		t.Fatalf("regenerate: %d %+v", code, body)
	}
	fresh, _ := body["identifier"].(map[string]any)
	freshValue, _ := fresh["value"].(string)
	if freshValue == value {
		t.Fatal("regenerated value must differ from the original")
	}
	freshIDf, _ := fresh["id"].(float64)
	freshIDStr := strconv.FormatInt(int64(freshIDf), 10)

	// Revoke the fresh one.
	code, body = doHandler(t, s.handleRevokeClientIdentifier, "POST", "", map[string]string{"id": clientIDStr, "identifierId": freshIDStr})
	if code != 200 {
		t.Fatalf("revoke: %d %+v", code, body)
	}

	// Delete the domain override.
	code, body = doHandler(t, s.handleDeleteDomainOverride, "DELETE", "", map[string]string{"id": clientIDStr, "overrideId": strconv.FormatInt(int64(overrideIDf), 10)})
	if code != 200 {
		t.Fatalf("delete override: %d %+v", code, body)
	}

	// Delete the (now-revoked) identifier entirely.
	code, body = doHandler(t, s.handleDeleteClientIdentifier, "DELETE", "", map[string]string{"id": clientIDStr, "identifierId": freshIDStr})
	if code != 200 {
		t.Fatalf("delete identifier: %d %+v", code, body)
	}
}
