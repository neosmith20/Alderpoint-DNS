package httpapi

// Regression test for a real live UI defect: the Cache page's dnsdist
// "Attempt flush" button called a backend operation that ALWAYS denies
// the request by design (dnsdist has no live cache-flush channel) --
// a broken button, not a degraded one. handleCacheDnsdistRestart
// replaces it with a real, safe action (a DNS Runtime re-promote, which
// restarts dnsdist and clears its cache as a side effect, with the same
// validate/health-check/auto-rollback guarantees every other DNS
// Runtime change already has). The full real-restart path needs a
// fully wired Orchestrator + a real hostagent (covered by
// internal/dnsruntime's own tests and this session's live verification);
// this test covers the handler's own contract: honest unavailability
// when no DNS runtime is configured, matching every other optional
// boundary in this file.

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"
)

func TestCacheDnsdistRestartWithoutDNSRuntimeReturnsUnavailable(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	rec := httptest.NewRecorder()
	s.handleCacheDnsdistRestart(rec, httptest.NewRequest("POST", "/api/cache/dnsdist-restart", nil))
	if rec.Code != 503 {
		t.Fatalf("expected 503 when no DNS runtime is configured, got %d: %s", rec.Code, rec.Body.String())
	}
}
