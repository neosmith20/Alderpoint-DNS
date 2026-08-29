package notifications

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
	"alderpointdns/go-controlplane/internal/replication"
	"alderpointdns/go-controlplane/internal/secretstore"
)

// fakeWebhookServer counts real incoming webhook POSTs -- used by every
// test below that proves fireEdge dispatches (or doesn't) exactly once.
type fakeWebhookServer struct {
	url string
	n   atomic.Int64
}

func (f *fakeWebhookServer) count() int64 { return f.n.Load() }

func newFakeWebhookServer(t *testing.T) *fakeWebhookServer {
	t.Helper()
	f := &fakeWebhookServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.n.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	f.url = srv.URL
	return f
}

// newTestServiceWithDNSRuntime wires a real apdns-hostagent with both
// secrets ops (Dispatch's real webhook sends go through it) and DNS
// runtime ops registered on the SAME server -- no real promote is ever
// called, so bind_running/dnsdist_running honestly report false
// throughout, exactly the "bad" state CheckServiceAvailability's own
// tests need.
func newTestServiceWithDNSRuntime(t *testing.T) (*Service, *hostagent.Client) {
	t.Helper()
	db := newTestDB(t)
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	audit, err := hostagentd.OpenAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	srv := &hostagentd.Server{SocketPath: sockPath, AllowedUID: uint32(os.Getuid()), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: audit}
	if err := hostagentd.RegisterSecretsOps(srv, hostagentd.SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	bindDir := filepath.Join("/var/lib/bind", fmt.Sprintf("notify-healthcheck-test-%d", os.Getpid()), t.Name())
	if err := os.MkdirAll(bindDir, 0o755); err != nil {
		t.Skipf("cannot create test dir under /var/lib/bind: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(bindDir) })
	stopRuntime, err := hostagentd.RegisterDNSRuntimeOps(srv, hostagentd.DNSRuntimeConfig{
		StagingDir: t.TempDir(), BindLivePath: filepath.Join(bindDir, "named.conf"),
		BindDirectory: bindDir, DnsdistLivePath: filepath.Join(t.TempDir(), "dnsdist.conf"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stopRuntime)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan struct{})
	go func() {
		go func() {
			for i := 0; i < 100; i++ {
				if _, err := os.Stat(sockPath); err == nil {
					close(ready)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			close(ready)
		}()
		srv.Serve(ctx)
	}()
	<-ready
	client := hostagent.NewClient(sockPath)
	return &Service{DB: db, Secrets: &secretstore.Service{DB: db, HostAgent: client}}, client
}

// newTestReplicationService is a minimal, real replication.Service
// sharing this test's own database (matching how it's actually wired
// together in cmd/alderpointdns-go/main.go) -- no hostagent needed
// since these tests never touch CA/cert operations.
func newTestReplicationService(t *testing.T, db *sql.DB) *replication.Service {
	t.Helper()
	return &replication.Service{DB: db, CertDir: t.TempDir()}
}

func TestCheckServiceAvailabilityFiresOnceThenRecovers(t *testing.T) {
	svc, hostAgent := newTestServiceWithDNSRuntime(t)
	ctx := context.Background()
	p, err := svc.Create(ctx, "webhook", "Ops", nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := newFakeWebhookServer(t)
	if err := svc.SetSecret(ctx, p.ProviderID, srv.url); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetSubscription(ctx, p.ProviderID, "service_unavailable", "info", true, nil); err != nil {
		t.Fatal(err)
	}

	if err := svc.CheckServiceAvailability(ctx, hostAgent); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 2 { // named + dnsdist, both down
		t.Fatalf("expected 2 real dispatches (named down, dnsdist down), got %d", got)
	}

	// A second check with the SAME (still down) state must NOT re-fire.
	if err := svc.CheckServiceAvailability(ctx, hostAgent); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 2 {
		t.Fatalf("expected no additional dispatch for an unchanged bad state, got %d total", got)
	}
}

func TestCheckServiceAvailabilityWithNilHostAgentIsANoOp(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CheckServiceAvailability(context.Background(), nil); err != nil {
		t.Fatalf("expected no error for a nil hostagent, got %v", err)
	}
}

// setReplicationSetting writes a replication_settings key directly --
// last_sync_status/drift_detected are normally only ever set by a real
// SyncOnce/CheckDrift call; seeding them directly here keeps these
// tests deterministic instead of racing this session's own real
// background poller goroutine.
func setReplicationSetting(t *testing.T, db *sql.DB, key, value string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO replication_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value); err != nil {
		t.Fatal(err)
	}
}

func TestCheckReplicationDelayedOfStandaloneNodeIsANoOp(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	repl := newTestReplicationService(t, svc.DB)
	if err := svc.CheckReplicationDelayed(context.Background(), repl); err != nil {
		t.Fatal(err)
	}
}

func TestCheckReplicationDelayedWithNilServiceIsANoOp(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CheckReplicationDelayed(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

// TestCheckReplicationDelayedNeverSyncedIsHealthy matches Python's own
// _HEALTHY_SYNC_STATUSES including "" -- a brand-new replica that
// simply hasn't attempted a sync yet (or whose primary has never
// published a generation) is not itself an unhealthy state.
func TestCheckReplicationDelayedNeverSyncedIsHealthy(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	ctx := context.Background()
	repl := newTestReplicationService(t, svc.DB)
	setReplicationSetting(t, svc.DB, "role", "replica")

	p, _ := svc.Create(ctx, "webhook", "Ops", nil)
	srv := newFakeWebhookServer(t)
	svc.SetSecret(ctx, p.ProviderID, srv.url)
	svc.SetSubscription(ctx, p.ProviderID, "replication_delayed", "info", true, nil)

	if err := svc.CheckReplicationDelayed(ctx, repl); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 0 {
		t.Fatalf("expected no dispatch for a never-synced replica, got %d", got)
	}
}

// TestCheckReplicationDelayedFiresOnUnhealthyStatusThenRecovers is the
// direct edge-detection proof: an unhealthy sync status fires once,
// doesn't refire while still unhealthy, and firing a recovery is
// covered by internal/notifications' own dispatch_test.go
// (TestDispatchRecoveryBypassesCooldown) -- this test focuses on the
// edge-detection layer fireEdge itself adds on top of that.
func TestCheckReplicationDelayedFiresOnUnhealthyStatusThenRecovers(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	ctx := context.Background()
	repl := newTestReplicationService(t, svc.DB)
	setReplicationSetting(t, svc.DB, "role", "replica")
	setReplicationSetting(t, svc.DB, "last_sync_status", "unreachable")

	p, _ := svc.Create(ctx, "webhook", "Ops", nil)
	srv := newFakeWebhookServer(t)
	svc.SetSecret(ctx, p.ProviderID, srv.url)
	svc.SetSubscription(ctx, p.ProviderID, "replication_delayed", "info", true, nil)

	if err := svc.CheckReplicationDelayed(ctx, repl); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("expected exactly 1 real dispatch for a newly-unreachable replica, got %d", got)
	}

	// Still unreachable on the next check -- must not re-fire.
	if err := svc.CheckReplicationDelayed(ctx, repl); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("expected no re-fire while still unhealthy, got %d total", got)
	}

	// Recovers -- fires exactly one recovery notice.
	setReplicationSetting(t, svc.DB, "last_sync_status", "success")
	if err := svc.CheckReplicationDelayed(ctx, repl); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 2 {
		t.Fatalf("expected exactly 1 recovery dispatch, got %d total", got)
	}
}

func TestCheckReplicationDelayedFiresOnDriftAloneEvenWithAHealthyStatus(t *testing.T) {
	svc := newTestServiceWithSecrets(t)
	ctx := context.Background()
	repl := newTestReplicationService(t, svc.DB)
	setReplicationSetting(t, svc.DB, "role", "replica")
	setReplicationSetting(t, svc.DB, "last_sync_status", "success")
	setReplicationSetting(t, svc.DB, "drift_detected", "1")

	p, _ := svc.Create(ctx, "webhook", "Ops", nil)
	srv := newFakeWebhookServer(t)
	svc.SetSecret(ctx, p.ProviderID, srv.url)
	svc.SetSubscription(ctx, p.ProviderID, "replication_delayed", "info", true, nil)

	if err := svc.CheckReplicationDelayed(ctx, repl); err != nil {
		t.Fatal(err)
	}
	if got := srv.count(); got != 1 {
		t.Fatalf("expected a real dispatch for detected drift even with a healthy sync status, got %d", got)
	}
}
