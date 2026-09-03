package blocklists

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	// Root cause of a real, reproduced-under-load flake
	// (TestAttentionRequiredAfterThreeConsecutiveFailures): this test
	// fixture used a bare sql.Open with none of the safety settings
	// cmd/alderpointdns-go's own real openDB() always uses (busy_timeout,
	// WAL, SetMaxOpenConns(1)). A background job's own goroutine
	// (Service.runJob, writing state='running'/'succeeded') and the
	// test's own polling goroutine (waitJob's GetJob reads) genuinely
	// run concurrently against the SAME sql.DB; with no MaxOpenConns
	// cap, Go's database/sql pool can and did open a second physical
	// SQLite connection to serve that concurrent read, and with no
	// busy_timeout configured, a write that lands on the other
	// connection's shared lock at that moment fails with SQLITE_BUSY
	// *immediately* -- an error runJob's own state-transition writes
	// don't check (matching production's real, safe assumption that a
	// single-connection, WAL, busy_timeout'd sql.DB never contends with
	// itself this way -- an assumption this fixture alone violated).
	// Reproduced directly: instrumenting waitJob to log job state
	// transitions caught a real failure stuck at state="queued" for the
	// full wait window -- proof the state='running' write was silently
	// dropped, not merely slow. Matching production's real connection
	// settings here (not a larger timeout, not a retry loop) is the
	// actual fix: it removes the second connection entirely, so there
	// is no longer anything for the writer to contend with.
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`
		CREATE TABLE blocklist_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE blocklist_subscriptions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			subscription_id TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL, url TEXT NOT NULL, category TEXT NOT NULL DEFAULT '',
			enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
			last_refresh_at TEXT, last_status TEXT, last_error TEXT, rule_count INTEGER,
			last_success_at TEXT, next_update_at TEXT, update_duration_ms INTEGER,
			update_interval_seconds INTEGER, failure_count INTEGER NOT NULL DEFAULT 0,
			first_failure_at TEXT, update_in_progress INTEGER NOT NULL DEFAULT 0,
			list_type TEXT NOT NULL DEFAULT 'block'
		);
		CREATE TABLE blocklist_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, subscription_ids TEXT NOT NULL,
			state TEXT NOT NULL, results TEXT, started_at TEXT NOT NULL, finished_at TEXT
		);
		CREATE TABLE blocklist_categories (
			id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL, updated_at TEXT NOT NULL
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// A dedicated, keep-alive-disabled Transport per test: httptest
	// servers are short-lived and each test binds a fresh port, so
	// sharing http.DefaultTransport's process-wide idle-connection pool
	// across many rapid test iterations (-count=N) was observed to wedge
	// a request indefinitely after several iterations in the same
	// process -- this avoids that class of interaction entirely rather
	// than chasing the exact interaction inside net/http's pool.
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	return &Service{
		DB: db, HTTPClient: client,
		StagingDir: filepath.Join(dir, "staging"), RuntimeDir: filepath.Join(dir, "runtime"),
		MaxConcurrent: 3,
	}
}

func waitJob(t *testing.T, s *Service, jobID int64) *Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var lastState string
	for time.Now().Before(deadline) {
		j, err := s.GetJob(context.Background(), jobID)
		if err != nil {
			t.Fatal(err)
		}
		if j != nil {
			lastState = j.State
		}
		if j != nil && j.State == "succeeded" {
			return j
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job did not finish in time (last observed state=%q)", lastState)
	return nil
}

func TestCreateTriggersImmediatePull(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.com\n"))
	}))
	defer srv.Close()

	s := newTestService(t)
	ctx := context.Background()
	sub, jobID, err := s.Create(ctx, "sub1", "Test List", srv.URL, "standard", "block")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !sub.UpdateInProgress {
		t.Error("expected update_in_progress=true immediately after create")
	}

	waitJob(t, s, jobID)

	updated, err := s.Get(ctx, "sub1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.LastStatus == nil || *updated.LastStatus != "ok" {
		t.Fatalf("last_status = %v, want ok", updated.LastStatus)
	}
	if updated.RuleCount == nil || *updated.RuleCount != 2 {
		t.Fatalf("rule_count = %v, want 2", updated.RuleCount)
	}
	if updated.UpdateInProgress {
		t.Error("update_in_progress should be false after job completes")
	}
}

// TestCreateListTypeRoundTrips proves an Allowlist ("allow") and a
// Blocklist ("block", the default) are real, distinct, persisted rows
// on this same table -- not just an in-memory label -- and that an
// unrecognized value never silently becomes "allow".
func TestCreateListTypeRoundTrips(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("0.0.0.0 example.com\n"))
	}))
	defer srv.Close()
	s := newTestService(t)
	ctx := context.Background()

	allowSub, jobID, err := s.Create(ctx, "allow1", "An Allowlist", srv.URL, "standard", "allow")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if allowSub.ListType != "allow" {
		t.Fatalf("ListType = %q immediately after Create, want allow", allowSub.ListType)
	}
	waitJob(t, s, jobID)
	reloaded, err := s.Get(ctx, "allow1")
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.ListType != "allow" {
		t.Fatalf("ListType = %q after reload from disk, want allow", reloaded.ListType)
	}

	blockSub, _, err := s.Create(ctx, "block1", "Default", srv.URL, "standard", "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if blockSub.ListType != "block" {
		t.Fatalf("ListType = %q for an unrecognized/empty value, want the safe default block", blockSub.ListType)
	}
}

func TestFailedPullRetainsPreviousGoodArtifact(t *testing.T) {
	var good atomic.Bool
	good.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if good.Load() {
			w.Write([]byte("0.0.0.0 good.example.com\n"))
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	s := newTestService(t)
	ctx := context.Background()
	_, jobID, err := s.Create(ctx, "sub2", "Flaky List", srv.URL, "standard", "block")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, s, jobID)

	runtimeFile := filepath.Join(s.RuntimeDir, "sub2.rpz")
	firstContent, err := os.ReadFile(runtimeFile)
	if err != nil {
		t.Fatalf("expected a promoted runtime file after success: %v", err)
	}

	good.Store(false)
	jobID2, err := s.RefreshOne(ctx, "sub2")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	var job *Job
	for time.Now().Before(deadline) {
		job, _ = s.GetJob(ctx, jobID2)
		if job != nil && job.State == "succeeded" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	sub, err := s.Get(ctx, "sub2")
	if err != nil {
		t.Fatal(err)
	}
	if sub.LastStatus == nil || *sub.LastStatus != "error" {
		t.Fatalf("expected last_status=error after the failed pull, got %v", sub.LastStatus)
	}
	if sub.FailureCount != 1 {
		t.Fatalf("failure_count = %d, want 1", sub.FailureCount)
	}

	secondContent, err := os.ReadFile(runtimeFile)
	if err != nil {
		t.Fatalf("runtime file should still exist after a failed refresh: %v", err)
	}
	if string(firstContent) != string(secondContent) {
		t.Fatal("previous-good runtime artifact was overwritten by a failed pull")
	}
}

func TestAttentionRequiredAfterThreeConsecutiveFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := newTestService(t)
	ctx := context.Background()
	_, jobID, err := s.Create(ctx, "sub3", "Always Broken", srv.URL, "standard", "block")
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, s, jobID)

	sub, _ := s.Get(ctx, "sub3")
	if sub.AttentionRequired {
		t.Fatal("attention_required should be false after only 1 failure")
	}

	for i := 0; i < 2; i++ {
		j, err := s.RefreshOne(ctx, "sub3")
		if err != nil {
			t.Fatal(err)
		}
		waitJob(t, s, j)
	}

	sub, _ = s.Get(ctx, "sub3")
	if sub.FailureCount != 3 {
		t.Fatalf("failure_count = %d, want 3", sub.FailureCount)
	}
	if !sub.AttentionRequired {
		t.Fatal("attention_required should be true after 3 consecutive failures")
	}
}

func TestRefreshOneRejectsWhileAlreadyRunning(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
		w.Write([]byte("0.0.0.0 x.example.com\n"))
	}))
	defer srv.Close()
	defer close(block)

	s := newTestService(t)
	ctx := context.Background()
	_, _, err := s.Create(ctx, "sub4", "Slow List", srv.URL, "standard", "block")
	if err != nil {
		t.Fatal(err)
	}
	// Give the background job time to mark sub4 as running.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.runningMu.Lock()
		running := s.running["sub4"]
		s.runningMu.Unlock()
		if running {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if _, err := s.RefreshOne(ctx, "sub4"); err != ErrAlreadyRunning {
		t.Fatalf("expected ErrAlreadyRunning, got %v", err)
	}
}

func TestValidateIntervalRejectsArbitraryValues(t *testing.T) {
	if err := ValidateInterval(3600); err != nil {
		t.Errorf("3600 (1 hour) should be valid: %v", err)
	}
	if err := ValidateInterval(1234); err == nil {
		t.Error("1234 should be rejected (not one of the presets)")
	}
}
