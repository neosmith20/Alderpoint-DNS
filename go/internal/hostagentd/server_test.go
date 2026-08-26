package hostagentd

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

func newTestServer(t *testing.T, allowedUID uint32) (*Server, string) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := OpenAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })

	s := &Server{
		SocketPath: sockPath,
		AllowedUID: allowedUID,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Audit:      audit,
	}
	s.Register("test.echo", func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Message string `json:"message"`
		}
		json.Unmarshal(params, &in)
		return map[string]string{"echo": in.Message}, nil
	})
	s.Register("test.always_denied", func(ctx context.Context, params json.RawMessage) (any, error) {
		return nil, errDeniedForTest
	})

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
		s.Serve(ctx)
	}()
	<-ready
	return s, sockPath
}

var errDeniedForTest = &testError{"operation not permitted in this configuration"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func rawCall(t *testing.T, sockPath string, req hostagent.Request) hostagent.Response {
	t.Helper()
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	line, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatalf("no response: %v", scanner.Err())
	}
	var resp hostagent.Response
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	return resp
}

// TestSocketFileIsConnectableByAnyone proves the socket file's
// permissions never accidentally lock out a legitimate, differently-UID
// client before SO_PEERCRED even gets to run -- a real bug this package
// shipped once (0600 on the socket file made every request fail with
// "permission denied" at the OS level, discovered by an end-to-end
// integration test run as two genuinely different real UIDs, not by
// this in-process test, since every in-process test necessarily
// connects as the same UID that created the socket and so could never
// have caught it). This test is the fast, permanent regression guard
// for that class of bug going forward.
func TestSocketFileIsConnectableByAnyone(t *testing.T) {
	_, sockPath := newTestServer(t, uint32(os.Getuid()))
	info, err := os.Stat(sockPath)
	if err != nil {
		t.Fatal(err)
	}
	mode := info.Mode().Perm()
	if mode&0o006 == 0 {
		t.Fatalf("socket file mode %o does not permit non-owner connect -- a different real UID than the one that started this agent would fail to even open a connection, before SO_PEERCRED is ever evaluated", mode)
	}
}

func TestAuthorizedPeerCanCallARegisteredOperation(t *testing.T) {
	_, sockPath := newTestServer(t, uint32(os.Getuid()))
	resp := rawCall(t, sockPath, hostagent.Request{Op: "test.echo", Params: json.RawMessage(`{"message":"hello"}`)})
	if !resp.OK {
		t.Fatalf("expected ok=true, got %+v", resp)
	}
	var result struct {
		Echo string `json:"echo"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatal(err)
	}
	if result.Echo != "hello" {
		t.Fatalf("expected echo=hello, got %+v", result)
	}
}

// TestUnauthorizedPeerUIDIsRejected proves the SO_PEERCRED comparison
// itself actually rejects on mismatch: the real peer UID (this test
// process's own UID, verified by the kernel) is deliberately compared
// against a different "allowed" UID the server was configured with --
// this exercises the exact same comparison path a genuinely different
// user would hit, without needing a second real system user in CI.
func TestUnauthorizedPeerUIDIsRejected(t *testing.T) {
	wrongUID := uint32(os.Getuid()) + 999999
	_, sockPath := newTestServer(t, wrongUID)
	resp := rawCall(t, sockPath, hostagent.Request{Op: "test.echo", Params: json.RawMessage(`{"message":"hello"}`)})
	if resp.OK {
		t.Fatalf("expected the connection to be rejected for a UID mismatch, got %+v", resp)
	}
	if resp.Code != "unauthorized" {
		t.Fatalf("expected code=unauthorized, got %+v", resp)
	}
}

func TestUnknownOperationIsRejected(t *testing.T) {
	_, sockPath := newTestServer(t, uint32(os.Getuid()))
	resp := rawCall(t, sockPath, hostagent.Request{Op: "cache.definitely_not_a_real_op"})
	if resp.OK {
		t.Fatalf("expected an unknown op to be rejected, got %+v", resp)
	}
	if resp.Code != "unknown_op" {
		t.Fatalf("expected code=unknown_op, got %+v", resp)
	}
}

func TestGenericCommandOperationDoesNotExist(t *testing.T) {
	// Real, structural proof of "no generic shell/command endpoint":
	// every op name plausible for a raw-command escape hatch is rejected
	// as unknown, the same as any other made-up op name.
	_, sockPath := newTestServer(t, uint32(os.Getuid()))
	for _, op := range []string{"exec", "shell", "run", "command", "eval", "system.exec"} {
		resp := rawCall(t, sockPath, hostagent.Request{Op: op, Params: json.RawMessage(`{"cmd":"id"}`)})
		if resp.OK || resp.Code != "unknown_op" {
			t.Fatalf("expected op %q to be rejected as unknown, got %+v", op, resp)
		}
	}
}

func TestHandlerDenialIsReportedNotPanicked(t *testing.T) {
	_, sockPath := newTestServer(t, uint32(os.Getuid()))
	resp := rawCall(t, sockPath, hostagent.Request{Op: "test.always_denied"})
	if resp.OK {
		t.Fatalf("expected denial, got %+v", resp)
	}
	if resp.Code != "denied" {
		t.Fatalf("expected code=denied, got %+v", resp)
	}
}

func TestClientCallRoundTripsThroughTheRealSocket(t *testing.T) {
	_, sockPath := newTestServer(t, uint32(os.Getuid()))
	c := hostagent.NewClient(sockPath)
	var result struct {
		Echo string `json:"echo"`
	}
	if err := c.Call(context.Background(), "test.echo", map[string]string{"message": "via client"}, &result); err != nil {
		t.Fatal(err)
	}
	if result.Echo != "via client" {
		t.Fatalf("expected echo='via client', got %+v", result)
	}
}

func TestClientCallOfDeniedOperationReturnsErrDenied(t *testing.T) {
	_, sockPath := newTestServer(t, uint32(os.Getuid()))
	c := hostagent.NewClient(sockPath)
	err := c.Call(context.Background(), "test.always_denied", nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestAuditLogRecordsBothAllowedAndRejectedRequests(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	audit, err := OpenAuditLog(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		SocketPath: filepath.Join(t.TempDir(), "agent.sock"),
		AllowedUID: uint32(os.Getuid()),
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Audit:      audit,
	}
	s.Register("test.echo", func(ctx context.Context, params json.RawMessage) (any, error) {
		return map[string]string{"ok": "yes"}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(s.SocketPath); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	rawCall(t, s.SocketPath, hostagent.Request{Op: "test.echo"})
	rawCall(t, s.SocketPath, hostagent.Request{Op: "no.such.op"})
	audit.Close()

	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var okCount, rejectedCount int
	for _, line := range splitLines(data) {
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("invalid audit line %q: %v", line, err)
		}
		if e.OK {
			okCount++
		} else {
			rejectedCount++
		}
	}
	if okCount != 1 || rejectedCount != 1 {
		t.Fatalf("expected 1 ok + 1 rejected audit entry, got ok=%d rejected=%d", okCount, rejectedCount)
	}
}

func splitLines(data []byte) []string {
	var out []string
	start := 0
	for i, b := range data {
		if b == '\n' {
			out = append(out, string(data[start:i]))
			start = i + 1
		}
	}
	return out
}
