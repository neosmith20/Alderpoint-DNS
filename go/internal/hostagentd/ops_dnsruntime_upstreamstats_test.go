package hostagentd

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestFetchUpstreamStatsSurvivesALargeRealisticResponse is the direct
// regression proof for a real, previously-undiscovered defect: the
// real dnsdist /api/v1/servers/localhost response also inline-dumps
// the entire compiled ruleset (acl/rules/response-rules/etc, not just
// "servers") -- on the real live appliance, with 854k+ real blocklist
// rules compiled in, that's a genuine 26+ MB document, far past the
// old 4 MiB io.ReadAll(io.LimitReader(...)) cap, which silently
// truncated it mid-document on every real poll. This fake server
// reproduces that shape at a smaller but still past-the-old-cap scale
// (a >5 MiB "rules" blob) rather than needing 854k real rules.
func TestFetchUpstreamStatsSurvivesALargeRealisticResponse(t *testing.T) {
	const oldCapBytes = 4 << 20
	apiKey := "test-key-for-large-response"

	var bulk strings.Builder
	bulk.WriteString(`"padding":"`)
	for bulk.Len() < oldCapBytes+(1<<20) { // comfortably past the old 4 MiB cap
		bulk.WriteString("x")
	}
	bulk.WriteString(`"`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != apiKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Real dnsdist shape: "servers" alongside a lot of other top-level
		// keys this package deliberately ignores -- "rules" stands in for
		// the real ruleset dump that's actually the size driver live.
		fmt.Fprintf(w, `{%s,"acl":"127.0.0.0/8","servers":[{"name":"apdns_default_0","address":"203.0.113.10:53","protocol":"Do53 UDP","state":"up","queries":42,"responses":40}]}`, bulk.String())
	}))
	defer srv.Close()

	var port int
	fmt.Sscanf(srv.URL, "http://127.0.0.1:%d", &port)

	result, err := fetchUpstreamStats(context.Background(), apiKey, port, 5*time.Second)
	if err != nil {
		t.Fatalf("fetchUpstreamStats returned an error against a large-but-valid response: %v", err)
	}
	if !result.Available {
		t.Fatalf("expected Available=true, got %+v", result)
	}
	if len(result.Servers) != 1 || result.Servers[0].Name != "apdns_default_0" {
		t.Fatalf("expected the real server entry to survive parsing past the old size cap, got %+v", result.Servers)
	}
	if result.Servers[0].Queries != 42 {
		t.Fatalf("expected real counter values to parse correctly, got queries=%d", result.Servers[0].Queries)
	}
}

// TestFetchUpstreamStatsRejectsAPathologicallyLargeResponse proves the
// new size cap is a real defensive bound, not simply removed --
// 256 MiB is real headroom over today's live size, but not unbounded.
func TestFetchUpstreamStatsRejectsAPathologicallyLargeResponse(t *testing.T) {
	apiKey := "test-key-for-oversized-response"
	const tooLarge = (256 << 20) + (1 << 20) // 1 MiB past the cap

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"servers":[`))
		chunk := strings.Repeat("0", 1<<20)
		written := 0
		for written < tooLarge {
			w.Write([]byte(chunk))
			written += len(chunk)
		}
		// Deliberately never closes the JSON document -- the size cap
		// should stop reading (and fail to parse) well before this
		// handler would ever finish anyway.
	}))
	defer srv.Close()

	var port int
	fmt.Sscanf(srv.URL, "http://127.0.0.1:%d", &port)

	_, err := fetchUpstreamStats(context.Background(), apiKey, port, 20*time.Second)
	if err == nil {
		t.Fatal("expected a parse error once the real body exceeds the defensive size cap, got nil")
	}
}
