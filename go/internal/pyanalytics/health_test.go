package pyanalytics

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/analyticssnapshot"
)

func writeHeartbeat(t *testing.T, dir, worker string, payload map[string]any) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, worker+".json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHealthReportsOkWithAFreshHeartbeat(t *testing.T) {
	r := newTestReader(t)
	dir := t.TempDir()
	now := time.Now()
	writeHeartbeat(t, dir, "analytics-worker", map[string]any{
		"worker": "analytics-worker", "status": "ok", "tick_count": 5,
		"tick_started_at": float64(now.Unix()), "last_success_at": float64(now.Unix()),
		"last_result": 0, "last_error": nil,
	})
	r.WorkerHeartbeatsDir = dir

	h := r.Health(context.Background())
	if h.Status != "ok" {
		t.Fatalf("expected ok status with a fresh heartbeat, got %+v", h)
	}
	if !h.DBReachable {
		t.Fatal("expected the DB to be reported reachable")
	}
	if h.WriterStale {
		t.Fatal("a heartbeat from just now must not be reported stale")
	}
	if h.LastCommittedBucket == nil || *h.LastCommittedBucket != 1002 {
		t.Fatalf("expected the real MAX(bucket_start)=1002 from the fixture live_buckets, got %+v", h.LastCommittedBucket)
	}
}

// TestHealthDegradesOnAStaleHeartbeatEvenThoughTheDBReadSucceeds is the
// central proof this whole file exists for: the exact V1.1.1 failure
// class named in the governing task. A dead/stalled writer must never
// be masked by a DB read that still happens to succeed against
// whatever was last durably committed.
func TestHealthDegradesOnAStaleHeartbeatEvenThoughTheDBReadSucceeds(t *testing.T) {
	r := newTestReader(t)
	dir := t.TempDir()
	longAgo := time.Now().Add(-1 * time.Hour)
	writeHeartbeat(t, dir, "analytics-worker", map[string]any{
		"worker": "analytics-worker", "status": "ok", "tick_count": 5,
		"tick_started_at": float64(longAgo.Unix()), "last_success_at": float64(longAgo.Unix()),
		"last_result": 0, "last_error": nil,
	})
	r.WorkerHeartbeatsDir = dir

	h := r.Health(context.Background())
	if !h.DBReachable {
		t.Fatal("the DB read itself must still succeed in this scenario -- that's the whole point")
	}
	if h.Status != "degraded" {
		t.Fatalf("expected degraded status for a stale writer heartbeat despite a successful DB read, got %+v", h)
	}
	if !h.WriterStale {
		t.Fatal("expected the writer to be reported stale")
	}
	if h.Reason == "" {
		t.Fatal("a degraded status must carry an explicit reason, not a silent flag")
	}
}

// TestHealthDegradesOnATickFailedStatus is the direct SQLITE_BUSY proof:
// the writer's own last tick recorded a real failure (last_error set,
// status="tick_failed"), even though last_success_at is recent enough
// that wall-clock staleness alone would not catch it yet.
func TestHealthDegradesOnATickFailedStatus(t *testing.T) {
	r := newTestReader(t)
	dir := t.TempDir()
	now := time.Now()
	writeHeartbeat(t, dir, "analytics-worker", map[string]any{
		"worker": "analytics-worker", "status": "tick_failed", "tick_count": 42,
		"tick_started_at": float64(now.Unix()), "last_success_at": float64(now.Add(-5 * time.Second).Unix()),
		"last_result": nil, "last_error": "sqlite3.OperationalError: database is locked",
	})
	r.WorkerHeartbeatsDir = dir

	h := r.Health(context.Background())
	if h.Status != "degraded" {
		t.Fatalf("expected degraded status for a tick_failed writer, got %+v", h)
	}
	if h.WriterLastError == "" {
		t.Fatal("expected the sanitized last_error to be surfaced")
	}
}

func TestHealthReportsFailedWhenTheDBItselfIsUnreachable(t *testing.T) {
	// No generation has ever been published to this directory --
	// ResolveCurrent fails honestly, exactly like an unreachable file.
	r, err := Open(filepath.Join(t.TempDir(), "never-published"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })

	h := r.Health(context.Background())
	if h.Status != "failed" {
		t.Fatalf("expected failed status when the DB itself can't be read, got %+v", h)
	}
	if h.DBReachable {
		t.Fatal("expected DBReachable=false")
	}
}

// TestHealthConsecutiveReadFailuresIncrementsAndRecoversWithoutRestart
// proves the "recovery occurs without rebooting the appliance"
// requirement directly: the exact same live Reader, no restart, no new
// process -- just probing a snapshot directory that starts with nothing
// published and then gets a real generation published to it (exactly
// what apdns-hostagent's first successful Refresh after a rocky start
// looks like) -- must reflect that recovery on its very next Health()
// call.
func TestHealthConsecutiveReadFailuresIncrementsAndRecoversWithoutRestart(t *testing.T) {
	published := filepath.Join(t.TempDir(), "published") // nothing published yet
	r, err := Open(published)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })

	h1 := r.Health(context.Background())
	if h1.Status != "failed" || h1.ConsecutiveReadFailures != 1 {
		t.Fatalf("expected the first probe to fail with count=1, got %+v", h1)
	}
	h2 := r.Health(context.Background())
	if h2.ConsecutiveReadFailures != 2 {
		t.Fatalf("expected consecutive failures to keep incrementing across repeated probes, got %+v", h2)
	}

	// Now publish a real generation to that exact directory -- the real
	// mechanism, not a white-box field swap -- simulating
	// apdns-hostagent successfully refreshing with no restart of this
	// Reader at all.
	source := newTestSourceDB(t)
	staging := filepath.Join(t.TempDir(), "staging")
	if _, err := analyticssnapshot.Refresh(context.Background(), source, published, staging, 3); err != nil {
		t.Fatal(err)
	}

	h3 := r.Health(context.Background())
	if h3.Status != "ok" && h3.Status != "degraded" {
		// "degraded" is acceptable here too (no heartbeat dir configured
		// in this test means WriterConfigured=false, so it should
		// actually be "ok" -- but assert DBReachable strictly, which is
		// the real recovery proof, without over-constraining the rest).
		t.Fatalf("expected recovery to be reflected immediately, got %+v", h3)
	}
	if !h3.DBReachable {
		t.Fatal("expected the DB to be reported reachable again immediately after recovery, with no restart")
	}
	if h3.ConsecutiveReadFailures != 0 {
		t.Fatalf("expected the failure counter to reset to 0 the instant a read succeeds again, got %d", h3.ConsecutiveReadFailures)
	}
}

func TestHealthQueueDepthCountsRegularFilesInTheInboxDirectory(t *testing.T) {
	r := newTestReader(t)
	dir := t.TempDir()
	for _, name := range []string{"batch-1.json", "batch-2.json", "batch-3.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "not-a-file"), 0o755); err != nil {
		t.Fatal(err)
	}
	r.InboxDir = dir

	h := r.Health(context.Background())
	if !h.QueueDepthAvailable {
		t.Fatal("expected queue depth to be reported available")
	}
	if h.QueueDepth != 3 {
		t.Fatalf("expected exactly the 3 regular files counted (subdirectory excluded), got %d", h.QueueDepth)
	}
}

func TestHealthWithoutWorkerHeartbeatsDirConfiguredReportsUnconfiguredNotDegraded(t *testing.T) {
	r := newTestReader(t)
	h := r.Health(context.Background())
	if h.WriterConfigured {
		t.Fatal("expected WriterConfigured=false when no dir is set")
	}
	if h.Status != "ok" {
		t.Fatalf("a deployment that hasn't wired the heartbeats mount up yet must not be falsely reported degraded, got %+v", h)
	}
}

func TestIsStaleTreatsAMissingHeartbeatAsStale(t *testing.T) {
	var hb *WorkerHeartbeat
	if !hb.IsStale(15, time.Now()) {
		t.Fatal("a nil/missing heartbeat must always be reported stale")
	}
}

func TestIsStaleTreatsAHungRunningTickAsStalePastGrace(t *testing.T) {
	startedAt := float64(time.Now().Add(-200 * time.Second).Unix())
	hb := &WorkerHeartbeat{Worker: "analytics-worker", Status: "running", TickStartedAt: &startedAt}
	if !hb.IsStale(15, time.Now()) {
		t.Fatal("a tick that has been 'running' for 200s (past the 120s grace) must be reported stale")
	}
}

func TestReadHeartbeatReturnsNilForAMissingFile(t *testing.T) {
	if hb := ReadHeartbeat(t.TempDir(), "analytics-worker"); hb != nil {
		t.Fatalf("expected nil for a missing heartbeat file, got %+v", hb)
	}
}
