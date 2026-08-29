package httpapi

// HTTP-layer proof for the real Go-native Replication routes.

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
	"alderpointdns/go-controlplane/internal/replication"
)

func newReplicationTestHostAgent(t *testing.T) *hostagent.Client {
	t.Helper()
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
	return hostagent.NewClient(sockPath)
}

func newReplicationTestServer(t *testing.T) *Server {
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
		Replication: &replication.Service{
			DB: db, HostAgent: newReplicationTestHostAgent(t), CertDir: t.TempDir(),
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestReplicationStatusDefaultsToStandalone(t *testing.T) {
	s := newReplicationTestServer(t)
	code, body := doHandler(t, s.handleReplicationStatus, "GET", "", nil)
	if code != 200 {
		t.Fatalf("code=%d body=%+v", code, body)
	}
	settings, _ := body["settings"].(map[string]any)
	if settings["role"] != "standalone" {
		t.Fatalf("expected default role standalone, got %+v", settings)
	}
}

func TestReplicationSetRoleRejectsUnknown(t *testing.T) {
	s := newReplicationTestServer(t)
	code, _ := doHandler(t, s.handleReplicationSetRole, "POST", `{"role":"overlord"}`, nil)
	if code != 400 {
		t.Fatalf("expected 400, got %d", code)
	}
}

func TestReplicationFullPrimaryWorkflowHTTP(t *testing.T) {
	s := newReplicationTestServer(t)

	code, _ := doHandler(t, s.handleReplicationSetRole, "POST", `{"role":"primary"}`, nil)
	if code != 200 {
		t.Fatalf("set role: code=%d", code)
	}

	code, body := doHandler(t, s.handleReplicationGenerateToken, "POST", `{"node_name":"replica-1"}`, nil)
	if code != 200 {
		t.Fatalf("generate token: code=%d body=%+v", code, body)
	}
	if body["token"] == "" || body["token"] == nil {
		t.Fatalf("expected a real token, got %+v", body)
	}

	code, body = doHandler(t, s.handleReplicationStatus, "GET", "", nil)
	if code != 200 {
		t.Fatalf("status: code=%d", code)
	}
	enrollments, _ := body["enrollments"].([]any)
	if len(enrollments) != 1 {
		t.Fatalf("expected 1 real enrollment, got %+v", body["enrollments"])
	}
	if body["listener_running"] != true {
		t.Fatalf("expected the real listener to be running, got %+v", body["listener_running"])
	}

	enrollment := enrollments[0].(map[string]any)
	enrollmentID := strconv.FormatInt(int64(enrollment["id"].(float64)), 10)
	code, _ = doHandler(t, s.handleReplicationRevokeEnrollment, "POST", "", map[string]string{"id": enrollmentID})
	if code != 200 {
		t.Fatalf("revoke enrollment: code=%d", code)
	}

	// Publish a generation for real.
	code, body = doHandler(t, s.handleReplicationPublishGeneration, "POST", "", nil)
	if code != 201 {
		t.Fatalf("publish generation: code=%d body=%+v", code, body)
	}
	if body["generation_number"] != float64(1) {
		t.Fatalf("expected generation_number=1, got %+v", body)
	}

	s.Replication.StopPrimaryListener()
}

func TestReplicationSettingsValidation(t *testing.T) {
	s := newReplicationTestServer(t)
	code, _ := doHandler(t, s.handleReplicationSettings, "POST", `{"listen_host":"0.0.0.0","listen_port":99999,"poll_interval_seconds":60}`, nil)
	if code != 400 {
		t.Fatalf("expected 400 for an out-of-range port, got %d", code)
	}
	code, _ = doHandler(t, s.handleReplicationSettings, "POST", `{"listen_host":"0.0.0.0","listen_port":8843,"poll_interval_seconds":60}`, nil)
	if code != 200 {
		t.Fatalf("expected 200 for valid settings, got %d", code)
	}
}

func TestReplicationPauseRoundTrip(t *testing.T) {
	s := newReplicationTestServer(t)
	code, _ := doHandler(t, s.handleReplicationPause, "POST", `{"paused":true}`, nil)
	if code != 200 {
		t.Fatalf("code=%d", code)
	}
	_, body := doHandler(t, s.handleReplicationStatus, "GET", "", nil)
	settings, _ := body["settings"].(map[string]any)
	if settings["paused"] != true {
		t.Fatalf("expected paused=true to persist, got %+v", settings)
	}
}

func TestReplicationConnectRejectsMissingFields(t *testing.T) {
	s := newReplicationTestServer(t)
	code, _ := doHandler(t, s.handleReplicationConnect, "POST", `{}`, nil)
	if code != 400 {
		t.Fatalf("expected 400 for a missing primary_host/token, got %d", code)
	}
}

func TestReplicationRouteWhenUnconfiguredReturnsUnavailable(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	code, _ := doHandler(t, s.handleReplicationStatus, "GET", "", nil)
	if code != 503 {
		t.Fatalf("expected 503 when Replication is not wired, got %d", code)
	}
}
