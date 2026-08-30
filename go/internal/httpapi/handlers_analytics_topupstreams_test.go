package httpapi

// HTTP-layer proof for GET /api/analytics/top-upstreams: real per-
// resolver telemetry recorded via internal/dnsanalytics.RecordUpstreamSample
// is ranked and returned, and a nil Analytics reader honestly degrades
// rather than fabricating data -- same contract every other analytics
// handler here already has (see handlers_analytics_topclients_test.go).

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dnsanalytics"
)

func TestHandleAnalyticsTopUpstreamsReturnsRealRankedData(t *testing.T) {
	analyticsDB, err := dnsanalytics.Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { analyticsDB.Close() })
	ctx := context.Background()
	now := time.Now()

	// First poll establishes a baseline (zero delta), second poll is
	// what actually contributes real numbers -- see RecordUpstreamSample's
	// own doc comment for why.
	if err := dnsanalytics.RecordUpstreamSample(ctx, analyticsDB, []dnsanalytics.UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Protocol: "Do53 UDP", Address: "9.9.9.9:53", HealthState: "up"},
		{ResolverKey: "apdns_default_1", Protocol: "Do53 UDP", Address: "1.1.1.1:53", HealthState: "up"},
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := dnsanalytics.RecordUpstreamSample(ctx, analyticsDB, []dnsanalytics.UpstreamServerSample{
		{ResolverKey: "apdns_default_0", Protocol: "Do53 UDP", Address: "9.9.9.9:53", HealthState: "up", Queries: 10, Responses: 10, Latency: 20},
		{ResolverKey: "apdns_default_1", Protocol: "Do53 UDP", Address: "1.1.1.1:53", HealthState: "up", Queries: 90, Responses: 85, Latency: 8},
	}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	s := &Server{
		Analytics: &dnsanalytics.Reader{DB: analyticsDB},
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	code, body := doHandler(t, s.handleAnalyticsTopUpstreams, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code = %d, body = %+v", code, body)
	}
	rows, _ := body["resolvers"].([]any)
	if len(rows) != 2 {
		t.Fatalf("resolvers = %+v, want 2 rows", rows)
	}
	top, _ := rows[0].(map[string]any)
	if top["resolver_key"] != "apdns_default_1" {
		t.Fatalf("top row = %+v, want apdns_default_1 first (90 queries beats 10)", top)
	}
	if v, _ := top["queries_attempted"].(float64); v != 90 {
		t.Errorf("queries_attempted = %v, want 90", top["queries_attempted"])
	}
	if v, _ := top["successful_responses"].(float64); v != 85 {
		t.Errorf("successful_responses = %v, want 85", top["successful_responses"])
	}
	if top["address"] != "1.1.1.1:53" {
		t.Errorf("address = %v, want the real configured backend address", top["address"])
	}
	if top["health_state"] != "up" {
		t.Errorf("health_state = %v, want up", top["health_state"])
	}
	if v, _ := top["avg_latency_ms"].(float64); v != 8 {
		t.Errorf("avg_latency_ms = %v, want 8", top["avg_latency_ms"])
	}
}

func TestHandleAnalyticsTopUpstreamsDegradedWithoutReader(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	code, body := doHandler(t, s.handleAnalyticsTopUpstreams, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code = %d, body = %+v", code, body)
	}
	if degraded, _ := body["degraded"].(bool); !degraded {
		t.Fatalf("expected degraded=true with no Analytics reader configured, got %+v", body)
	}
	rows, _ := body["resolvers"].([]any)
	if len(rows) != 0 {
		t.Fatalf("expected an empty resolvers list, got %+v", rows)
	}
}
