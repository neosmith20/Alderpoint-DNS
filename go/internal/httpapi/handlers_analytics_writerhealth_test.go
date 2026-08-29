package httpapi

// A real, previously-undisclosed inconsistency found while chasing down
// a Chromium test failure: unlike handleAnalyticsTopDomains,
// handleAnalyticsTopBlockedDomains and handleAnalyticsQueryLog used to
// report degraded:false unconditionally whenever their own SQL query
// succeeded, never consulting the analytics writer/dnstap-ingestion
// health check at all -- the exact "DNS kept running while the
// analytics writer died and the page kept showing a convincing chart"
// failure class internal/pyanalytics/health.go was built to close
// everywhere else. These two tests prove both endpoints now honestly
// report degraded when no *dnsanalytics.Writer is wired (the same
// no-writer-means-degraded fixture shape handlers_analytics_topclients_test.go
// already established is the correct, minimal way to exercise this),
// while still returning the real underlying rows -- degraded is a
// liveness signal layered on top of a genuinely successful read, never
// a reason to hide real data that was actually found.
import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dnsanalytics"
)

func decodeJSON(t *testing.T, body []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(body, v); err != nil {
		t.Fatalf("response body did not decode as JSON: %v (%s)", err, body)
	}
}

func TestHandleAnalyticsTopBlockedDomainsReportsWriterDegraded(t *testing.T) {
	analyticsDB, err := dnsanalytics.Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { analyticsDB.Close() })

	now := time.Now().Unix()
	if _, err := analyticsDB.Exec(
		`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome) VALUES (?, ?, 'A', 'NXDOMAIN', 'udp', '10.0.0.5', 1.0, 'blocked')`,
		now, "ads.example.com.",
	); err != nil {
		t.Fatal(err)
	}

	reader := &dnsanalytics.Reader{DB: analyticsDB} // no Writer wired -- the real degraded condition
	s := &Server{Analytics: reader, RawQueryLog: reader}

	req := httptest.NewRequest("GET", "/api/analytics/top-blocked-domains?minutes=60", nil)
	rec := httptest.NewRecorder()
	s.handleAnalyticsTopBlockedDomains(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Rows           [][2]any `json:"rows"`
		Degraded       bool     `json:"degraded"`
		DegradedReason string   `json:"degraded_reason"`
	}
	decodeJSON(t, rec.Body.Bytes(), &out)
	if !out.Degraded {
		t.Fatal("expected degraded:true when no writer is wired, got false -- the real writer-health signal is not being consulted")
	}
	if out.DegradedReason == "" {
		t.Fatal("expected a real, non-empty degraded_reason explaining why")
	}
	if len(out.Rows) != 1 || out.Rows[0][0] != "ads.example.com." {
		t.Fatalf("expected the real seeded row to still be returned alongside the honest degraded flag, got %+v", out.Rows)
	}
}

func TestHandleAnalyticsQueryLogReportsWriterDegraded(t *testing.T) {
	analyticsDB, err := dnsanalytics.Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { analyticsDB.Close() })

	now := time.Now().Unix()
	if _, err := analyticsDB.Exec(
		`INSERT INTO query_events (ts, domain, qtype, rcode, protocol, client, latency_ms, outcome) VALUES (?, ?, 'A', 'NOERROR', 'udp', '10.0.0.5', 1.0, 'allowed')`,
		now, "example.com.",
	); err != nil {
		t.Fatal(err)
	}

	reader := &dnsanalytics.Reader{DB: analyticsDB}
	s := &Server{Analytics: reader, RawQueryLog: reader}

	req := httptest.NewRequest("GET", "/api/analytics/query-log?minutes=60", nil)
	rec := httptest.NewRecorder()
	s.handleAnalyticsQueryLog(rec, req)
	if rec.Code != 200 {
		t.Fatalf("code = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Rows           []any  `json:"rows"`
		Degraded       bool   `json:"degraded"`
		DegradedReason string `json:"degraded_reason"`
	}
	decodeJSON(t, rec.Body.Bytes(), &out)
	if !out.Degraded {
		t.Fatal("expected degraded:true when no writer is wired, got false -- Query Log is the page an owner is most likely to check first during a real writer outage")
	}
	if out.DegradedReason == "" {
		t.Fatal("expected a real, non-empty degraded_reason explaining why")
	}
	if len(out.Rows) != 1 {
		t.Fatalf("expected the real seeded row to still be returned alongside the honest degraded flag, got %+v", out.Rows)
	}
}
