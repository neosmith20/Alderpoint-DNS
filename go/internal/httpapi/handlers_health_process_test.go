package httpapi

// Real proof for the new /api/health "process" component -- added
// 2026-08-29 after a live OOM incident where the web container's RSS
// grew unmonitored (see handlers_health_process.go's own doc comment
// and AGENT_PROGRESS.md's 2026-08-29 OOM-incident entry).

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestCurrentProcessStatsReportsRealRuntimeNumbers(t *testing.T) {
	stats := currentProcessStats()
	if stats.GoroutineCount < 1 {
		t.Fatalf("expected at least the calling goroutine to be counted, got %d", stats.GoroutineCount)
	}
	if stats.HeapSysBytes == 0 {
		t.Fatal("expected a non-zero HeapSysBytes -- the Go runtime always reserves some heap")
	}
	// RSSBytes is best-effort (0 on a platform without /proc/self/status)
	// -- on this test's own Linux CI/dev environment it must be real and
	// non-zero, proving readSelfRSS actually parsed the file rather than
	// silently no-op'ing.
	if stats.RSSBytes == 0 {
		t.Fatal("expected a real non-zero RSS reading from /proc/self/status on Linux")
	}
}

func TestHandleHealthIncludesProcessComponent(t *testing.T) {
	analytics := newAnalyticsFixtureReader(t)
	s := newHealthTestServer(t, analytics)

	rec := httptest.NewRecorder()
	s.handleHealth(rec, httptest.NewRequest("GET", "/api/health", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	components := body["components"].(map[string]any)
	process, ok := components["process"].(map[string]any)
	if !ok {
		t.Fatalf("expected a process component, got %+v", components)
	}
	if _, ok := process["goroutine_count"]; !ok {
		t.Fatalf("expected goroutine_count in the process component, got %+v", process)
	}
	if _, ok := process["heap_alloc_bytes"]; !ok {
		t.Fatalf("expected heap_alloc_bytes in the process component, got %+v", process)
	}
	// A process component reporting real growing numbers must never, by
	// itself, demote overall status -- there is no validated threshold
	// yet (see the doc comment); this is visibility, not a health gate.
	if body["status"] != "ok" {
		t.Fatalf("process component must not demote overall status on its own, got status=%v", body["status"])
	}
}
