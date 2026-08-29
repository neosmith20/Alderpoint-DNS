// Package hostagentd is the server side of apdns-hostagent: the actual
// privileged operation handlers, peer-credential authorization, and
// audit logging. See internal/hostagent's doc comment for the protocol
// and design rationale this package implements.
package hostagentd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"alderpointdns/go-controlplane/internal/hostagent"
)

// connDeadline bounds one whole request (dial to response written),
// generic across every op this agent handles. Must comfortably exceed
// the slowest real operation's worst-case duration -- see its own use
// below for the real live defect that got it raised from 30s to 90s.
// Raised again to 150s once DNSRuntimeConfig.HealthCheckTimeout's own
// default was raised from 30s to 60s (direct instrumentation of a real
// promote showed dnsdist itself finishing startup only ~4s after a
// 30s health-check budget had already given up) -- this must stay
// clear of both the new 60s health-check budget plus real compile/
// stage/reload overhead, and of the callers' own 120s client timeouts
// (main.go's newPromoteHostAgentClient / hostAgentClient), or a client
// can still give up while a genuinely-still-running promote holds this
// connection open.
const connDeadline = 150 * time.Second

// Handler is the shape every allowlisted operation implements. params is
// the raw JSON body (already known to come from an authorized peer);
// the handler decodes it itself into whatever typed struct it needs --
// there is no generic/untyped path from wire bytes to a system call
// anywhere in this package.
type Handler func(ctx context.Context, params json.RawMessage) (any, error)

type Server struct {
	SocketPath string
	// AllowedUID is the UID the web control-plane process runs as. Only
	// a connecting process with exactly this UID (verified via the
	// kernel, SO_PEERCRED -- never anything the client asserts in its
	// request) is authorized to call any operation at all.
	AllowedUID uint32
	Log        *slog.Logger
	Audit      *AuditLog

	handlers map[string]Handler
}

// Register adds one allowlisted operation. Called only from this
// package's own op_*.go files at startup (see cmd/apdns-hostagent/main.go)
// -- never from request-handling code, so the allowlist is fixed for
// the lifetime of the process.
func (s *Server) Register(op string, h Handler) {
	if s.handlers == nil {
		s.handlers = map[string]Handler{}
	}
	s.handlers[op] = h
}

func (s *Server) Serve(ctx context.Context) error {
	os.Remove(s.SocketPath) // a stale socket from a previous run must not block us
	if dir := parentDir(s.SocketPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("creating socket directory: %w", err)
		}
	}
	ln, err := net.Listen("unix", s.SocketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.SocketPath, err)
	}
	defer ln.Close()
	// The socket file itself must be connect()-able by the unprivileged
	// web process, or its connection attempt fails at the OS level
	// before SO_PEERCRED (checked per-connection below, the *real*
	// authorization boundary) ever runs at all -- a real bug this
	// package's own end-to-end integration test (run as two genuinely
	// different real UIDs, not both as root) caught: 0600 here silently
	// made every legitimate request fail with "permission denied"
	// before authorization was ever evaluated. World-connectable is
	// correct and safe specifically because SO_PEERCRED does not depend
	// on filesystem permissions at all -- any process that connects
	// still gets rejected here unless its real UID matches AllowedUID.
	os.Chmod(s.SocketPath, 0o666)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	s.Log.Info("apdns-hostagent listening", "socket", s.SocketPath, "allowed_uid", s.AllowedUID, "operations", len(s.handlers))
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown
			}
			s.Log.Warn("accept failed", "err", err)
			continue
		}
		go s.handleConn(ctx, conn)
	}
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return ""
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	started := time.Now()

	peerUID, err := peerUID(conn)
	if err != nil {
		s.Log.Warn("could not determine peer credentials; rejecting", "err", err)
		writeResponse(conn, hostagent.Response{OK: false, Error: "could not verify peer credentials", Code: "unauthorized"})
		return
	}
	if peerUID != s.AllowedUID {
		s.Log.Warn("connection from unauthorized UID rejected", "peer_uid", peerUID, "allowed_uid", s.AllowedUID)
		writeResponse(conn, hostagent.Response{OK: false, Error: "unauthorized peer", Code: "unauthorized"})
		s.Audit.Record(AuditEntry{Time: time.Now(), Op: "(rejected)", PeerUID: peerUID, OK: false, Detail: "unauthorized peer UID"})
		return
	}

	// connDeadline (see its own doc comment, currently 150s), not the
	// originally-shipped 30s: a real live defect found during a
	// durability pass, directly caused by raising DNSRuntimeConfig's
	// own health-check timeout (see ops_dnsruntime.go's own comment on
	// that change, now 60s) -- a real promote of a blocklist-heavy
	// config can now legitimately need close to that budget for its
	// health check alone, on top of real compile/stage/reload time
	// before that, so this connection-wide deadline (which bounds the
	// ENTIRE request, not just the health check) started closing the
	// connection out from under a promote that was still
	// genuinely in progress -- observed live as "hostagent unavailable:
	// no response" after ~38s, followed by DNS answering correctly
	// again once the (still-running, now-orphaned-from-the-caller's-
	// perspective) promote finished on its own. 90s leaves real margin
	// above the ~30s health check plus realistic compile/reload
	// overhead for every operation this agent handles, not just
	// promote -- a fast op still returns in milliseconds either way.
	conn.SetDeadline(time.Now().Add(connDeadline))
	var req hostagent.Request
	dec := json.NewDecoder(conn)
	if err := dec.Decode(&req); err != nil {
		writeResponse(conn, hostagent.Response{OK: false, Error: "invalid request", Code: "invalid_params"})
		return
	}

	handler, known := s.handlers[req.Op]
	if !known {
		s.Log.Warn("rejected unknown operation", "op", req.Op, "peer_uid", peerUID)
		writeResponse(conn, hostagent.Response{OK: false, Error: fmt.Sprintf("unknown operation %q", req.Op), Code: "unknown_op", RequestID: req.RequestID})
		s.Audit.Record(AuditEntry{Time: time.Now(), Op: req.Op, PeerUID: peerUID, OK: false, Detail: "unknown operation"})
		return
	}

	result, err := handler(ctx, req.Params)
	dur := time.Since(started)
	if err != nil {
		s.Log.Info("operation denied/failed", "op", req.Op, "peer_uid", peerUID, "err", err, "dur_ms", dur.Milliseconds())
		writeResponse(conn, hostagent.Response{OK: false, Error: err.Error(), Code: "denied", RequestID: req.RequestID})
		s.Audit.Record(AuditEntry{Time: time.Now(), Op: req.Op, PeerUID: peerUID, OK: false, Detail: err.Error(), DurationMS: dur.Milliseconds()})
		return
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		writeResponse(conn, hostagent.Response{OK: false, Error: "internal error encoding result", Code: "internal", RequestID: req.RequestID})
		s.Audit.Record(AuditEntry{Time: time.Now(), Op: req.Op, PeerUID: peerUID, OK: false, Detail: "result encoding failed", DurationMS: dur.Milliseconds()})
		return
	}
	writeResponse(conn, hostagent.Response{OK: true, Result: resultJSON, RequestID: req.RequestID})
	s.Log.Info("operation completed", "op", req.Op, "peer_uid", peerUID, "dur_ms", dur.Milliseconds())
	s.Audit.Record(AuditEntry{Time: time.Now(), Op: req.Op, PeerUID: peerUID, OK: true, DurationMS: dur.Milliseconds()})
}

func writeResponse(conn net.Conn, resp hostagent.Response) {
	line, err := json.Marshal(resp)
	if err != nil {
		return
	}
	conn.Write(append(line, '\n'))
}

// peerUID reads the real, kernel-verified UID of the process on the
// other end of a Unix socket connection (SO_PEERCRED) -- this is the
// entire authorization mechanism. It cannot be spoofed by the client:
// the kernel fills in the credentials of the actual connecting process
// at accept() time, not anything read from the byte stream.
func peerUID(conn net.Conn) (uint32, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if credErr != nil {
		return 0, credErr
	}
	return cred.Uid, nil
}
