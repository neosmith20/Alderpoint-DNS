package dnsanalytics

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"google.golang.org/protobuf/proto"
)

func buildResponse(t *testing.T, qname string, qtype uint16, rcode int) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	m.Rcode = rcode
	packed, err := m.Pack()
	if err != nil {
		t.Fatalf("pack DNS response: %v", err)
	}
	return packed
}

func buildDnstapMessage(t *testing.T, respMsg []byte, protocol dnstap.SocketProtocol, extra string, qSec, rSec uint64) []byte {
	t.Helper()
	mtype := dnstap.Message_CLIENT_RESPONSE
	dt := dnstap.Dnstap{
		Type: dnstap.Dnstap_MESSAGE.Enum(),
		Message: &dnstap.Message{
			Type:            &mtype,
			SocketProtocol:  &protocol,
			QueryAddress:    net.ParseIP("192.0.2.10").To4(),
			QueryTimeSec:    &qSec,
			ResponseTimeSec: &rSec,
			ResponseMessage: respMsg,
		},
	}
	if extra != "" {
		dt.Extra = []byte(extra)
	}
	raw, err := proto.Marshal(&dt)
	if err != nil {
		t.Fatalf("marshal dnstap message: %v", err)
	}
	return raw
}

func TestDecodeFrameAllowed(t *testing.T) {
	resp := buildResponse(t, "example.com", dns.TypeA, dns.RcodeSuccess)
	raw := buildDnstapMessage(t, resp, dnstap.SocketProtocol_UDP, "", 100, 100)
	ev, ok := decodeFrame(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.domain != "example.com" {
		t.Errorf("domain = %q, want example.com", ev.domain)
	}
	if ev.outcome != OutcomeAllowed {
		t.Errorf("outcome = %q, want allowed (no Extra set)", ev.outcome)
	}
	if ev.qtype != "A" {
		t.Errorf("qtype = %q, want A", ev.qtype)
	}
	if ev.rcode != "NOERROR" {
		t.Errorf("rcode = %q, want NOERROR", ev.rcode)
	}
	if ev.protocol != "udp" {
		t.Errorf("protocol = %q, want udp", ev.protocol)
	}
	if ev.client != "192.0.2.10" {
		t.Errorf("client = %q, want 192.0.2.10", ev.client)
	}
}

func TestDecodeFrameBlockedViaExtraTag(t *testing.T) {
	resp := buildResponse(t, "ads.example.com", dns.TypeA, dns.RcodeNameError)
	raw := buildDnstapMessage(t, resp, dnstap.SocketProtocol_TCP, "blocked", 100, 101)
	ev, ok := decodeFrame(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.outcome != OutcomeBlocked {
		t.Errorf("outcome = %q, want blocked", ev.outcome)
	}
	if ev.protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", ev.protocol)
	}
	if ev.latencyMs != 1000 {
		t.Errorf("latencyMs = %v, want 1000 (1 real second of query->response delta)", ev.latencyMs)
	}
	// A genuine NXDOMAIN for a domain nothing tagged "blocked" must never
	// be misclassified -- proven by the companion allowed-NXDOMAIN test
	// below rather than assumed here.
}

func TestDecodeFrameParsesPerScopeQuerylogAndStatsFlags(t *testing.T) {
	resp := buildResponse(t, "example.com", dns.TypeA, dns.RcodeSuccess)
	raw := buildDnstapMessage(t, resp, dnstap.SocketProtocol_UDP, "allowed|nolog|nostat", 100, 100)
	ev, ok := decodeFrame(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if !ev.noLog {
		t.Error("expected noLog=true for Extra containing |nolog")
	}
	if !ev.noStats {
		t.Error("expected noStats=true for Extra containing |nostat")
	}
	if ev.outcome != OutcomeAllowed {
		t.Errorf("outcome = %q, want allowed", ev.outcome)
	}
}

func TestDecodeFrameBlockedWithNolog(t *testing.T) {
	resp := buildResponse(t, "ads.example.com", dns.TypeA, dns.RcodeNameError)
	raw := buildDnstapMessage(t, resp, dnstap.SocketProtocol_UDP, "blocked|nolog", 100, 100)
	ev, ok := decodeFrame(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.outcome != OutcomeBlocked {
		t.Errorf("outcome = %q, want blocked (the compound Extra format must not break outcome parsing)", ev.outcome)
	}
	if !ev.noLog {
		t.Error("expected noLog=true")
	}
	if ev.noStats {
		t.Error("expected noStats=false (only |nolog was present)")
	}
}

func TestDecodeFrameGenuineNXDOMAINIsNotMisclassifiedAsBlocked(t *testing.T) {
	resp := buildResponse(t, "typo-that-does-not-exist.example.com", dns.TypeA, dns.RcodeNameError)
	raw := buildDnstapMessage(t, resp, dnstap.SocketProtocol_UDP, "", 100, 100)
	ev, ok := decodeFrame(raw)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if ev.outcome != OutcomeAllowed {
		t.Errorf("outcome = %q, want allowed -- a real NXDOMAIN with no apdns_outcome=blocked tag must never be inferred as blocked from rcode alone", ev.outcome)
	}
	if ev.rcode != "NXDOMAIN" {
		t.Errorf("rcode = %q, want NXDOMAIN", ev.rcode)
	}
}

func TestDecodeFrameRejectsGarbage(t *testing.T) {
	if _, ok := decodeFrame([]byte("not a protobuf message")); ok {
		t.Fatal("expected ok=false for garbage input")
	}
	if _, ok := decodeFrame(nil); ok {
		t.Fatal("expected ok=false for empty input")
	}
}

func TestDecodeFrameRejectsMessageWithNoResponse(t *testing.T) {
	mtype := dnstap.Message_CLIENT_QUERY
	dt := dnstap.Dnstap{Type: dnstap.Dnstap_MESSAGE.Enum(), Message: &dnstap.Message{Type: &mtype}}
	raw, err := proto.Marshal(&dt)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeFrame(raw); ok {
		t.Fatal("expected ok=false for a message with no ResponseMessage")
	}
}

// TestWriterEndToEndOverRealUnixSocket proves the real Frame Streams
// handshake and protobuf decode path, not just decodeFrame in isolation:
// a real dnstap client (the same library dnsdist itself is built against
// conceptually, if not literally) connects to Writer.Run's real unix
// socket and a real row lands durably in SQLite.
func TestWriterEndToEndOverRealUnixSocket(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	wtr := &Writer{DB: db}

	sockPath := filepath.Join(t.TempDir(), "dnstap.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go wtr.Run(ctx, sockPath)

	// Wait for the socket to exist before dialing.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := net.Dial("unix", sockPath); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("dnstap socket never came up")
		}
		time.Sleep(20 * time.Millisecond)
	}

	out, err := dnstap.NewFrameStreamSockOutput(&net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	out.SetTimeout(5 * time.Second)
	out.SetFlushTimeout(20 * time.Millisecond)
	go out.RunOutputLoop()
	defer out.Close()

	resp := buildResponse(t, "real-e2e.example.com", dns.TypeAAAA, dns.RcodeSuccess)
	raw := buildDnstapMessage(t, resp, dnstap.SocketProtocol_UDP, "", uint64(time.Now().Unix()), uint64(time.Now().Unix()))
	out.GetOutputChannel() <- raw

	deadline = time.Now().Add(5 * time.Second)
	var count int
	for {
		if err := db.QueryRow(`SELECT COUNT(*) FROM query_events WHERE domain = ?`, "real-e2e.example.com").Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("row never landed (count=%d) -- real end-to-end dnstap ingestion failed", count)
		}
		time.Sleep(20 * time.Millisecond)
	}

	inserted, decodeErrs := wtr.Stats()
	if inserted != 1 {
		t.Errorf("insertedTotal = %d, want 1", inserted)
	}
	if decodeErrs != 0 {
		t.Errorf("decodeErrors = %d, want 0", decodeErrs)
	}
}

// newRealConnPair returns a real, OS-buffered unix-socket connection
// pair (unlike net.Pipe, whose Write blocks until a concurrent Read
// matches it -- these tests need a Write to succeed/fail the same way a
// real dnstap connection's would, without a reader on the other end).
func newRealConnPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "pair.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err = net.Dial("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	server = <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	return server, client
}

// TestWatchdogRecoversOnConfirmedStall is the core regression test for
// the real, live-observed silent-stall failure mode (see this package's
// TrafficProbe doc comment): frames stop arriving while independent
// (BIND-derived) traffic keeps advancing. checkIngestionOnce is driven
// directly (bypassing real timers) to keep this deterministic and fast.
func TestWatchdogRecoversOnConfirmedStall(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	wtr := &Writer{DB: db, StaleThreshold: 0, WatchdogInterval: time.Hour /* driven manually */}
	wtr.startedAt.Store(time.Now().Add(-1 * time.Hour).Unix()) // force "stale" immediately regardless of threshold
	wtr.StaleThreshold = 1 * time.Millisecond

	// Attach a real accepted connection via net.Pipe so we can prove
	// checkIngestionOnce's recovery path actually closes it.
	serverSide, clientSide := newRealConnPair(t)
	defer clientSide.Close()
	wtr.trackConn(1, serverSide)

	var probeCalls int
	wtr.TrafficProbe = func(ctx context.Context) (int64, bool) {
		probeCalls++
		// First call establishes a baseline; second shows traffic
		// having advanced well past minTrafficDeltaToFlagStall.
		if probeCalls == 1 {
			return 100, true
		}
		return 100 + minTrafficDeltaToFlagStall + 1, true
	}

	ctx := context.Background()

	// Tick 1: establishes the traffic-probe baseline, must NOT yet
	// declare a stall (nothing to compare against).
	wtr.checkIngestionOnce(ctx)
	if wtr.Ingestion().Stalled {
		t.Fatal("must not report stalled on the very first probe (no baseline yet)")
	}
	if _, err := serverSide.Write([]byte("x")); err != nil {
		t.Error("connection must still be open after tick 1 -- no recovery should have fired yet")
	}

	// Re-track a fresh connection for tick 2 for an unambiguous
	// before/after write check independent of tick 1's write above.
	serverSide2, clientSide2 := newRealConnPair(t)
	defer clientSide2.Close()
	wtr.trackConn(2, serverSide2)

	// Tick 2: traffic has now advanced beyond the noise threshold with
	// zero frames received the whole time -> must recover.
	wtr.checkIngestionOnce(ctx)
	ing := wtr.Ingestion()
	if !ing.Stalled {
		t.Fatal("expected Stalled=true once traffic advanced with no frames received")
	}
	if ing.RecoveryCount != 1 {
		t.Errorf("RecoveryCount = %d, want 1", ing.RecoveryCount)
	}
	if ing.LastRecoveryAt == 0 {
		t.Error("LastRecoveryAt was never set")
	}
	if !ing.TrafficProbeOK {
		t.Error("TrafficProbeOK should be true -- the stub probe always succeeded")
	}

	// The real mechanism under test: recovery must have force-closed
	// the tracked connection so dnsdist's next write gets a real error.
	if _, err := serverSide2.Write([]byte("x")); err == nil {
		t.Error("expected the tracked connection to have been closed by recovery, but a write still succeeded")
	}

	// Durable diagnostic trail: a real row in ingestion_events.
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ingestion_events WHERE kind = 'recovery_attempted'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("ingestion_events rows for recovery_attempted = %d, want 1", count)
	}
}

// TestWatchdogDoesNotRecoverOnQuietNetwork proves the flip side: no
// frames for a long time, but the independent traffic probe also shows
// no real growth, must be treated as a genuinely idle network, not a
// failure -- the whole reason TrafficProbe exists instead of a naive
// heartbeat-only timeout.
func TestWatchdogDoesNotRecoverOnQuietNetwork(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	wtr := &Writer{DB: db, StaleThreshold: 1 * time.Millisecond}
	wtr.startedAt.Store(time.Now().Add(-1 * time.Hour).Unix())
	wtr.TrafficProbe = func(ctx context.Context) (int64, bool) {
		return 100, true // never moves
	}

	ctx := context.Background()
	wtr.checkIngestionOnce(ctx) // baseline
	wtr.checkIngestionOnce(ctx) // no movement -> must not recover

	ing := wtr.Ingestion()
	if ing.Stalled {
		t.Error("must not report stalled when the independent traffic probe shows a genuinely quiet network")
	}
	if ing.RecoveryCount != 0 {
		t.Errorf("RecoveryCount = %d, want 0 -- no recovery should have been attempted", ing.RecoveryCount)
	}
}

// TestWatchdogDegradedWhenProbeUnconfigured proves the conservative
// fallback: with no TrafficProbe wired at all, a real stale gap is
// reported as degraded (never silently "ok") but never force-closes a
// connection, since there's no independent evidence to justify it.
func TestWatchdogDegradedWhenProbeUnconfigured(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	wtr := &Writer{DB: db, StaleThreshold: 1 * time.Millisecond}
	wtr.startedAt.Store(time.Now().Add(-1 * time.Hour).Unix())

	serverSide, clientSide := newRealConnPair(t)
	defer clientSide.Close()
	wtr.trackConn(1, serverSide)

	wtr.checkIngestionOnce(context.Background())

	ing := wtr.Ingestion()
	if !ing.Stalled {
		t.Error("expected Stalled=true (conservative) with no traffic probe configured and a real stale gap")
	}
	if ing.RecoveryCount != 0 {
		t.Error("must never force-close without independent traffic evidence")
	}
	if _, err := serverSide.Write([]byte("x")); err != nil {
		t.Error("connection must not have been closed -- no probe means no basis for forcing a reconnect")
	}
}

// TestWatchdogNotStalledWhenProbeUnreachable is the regression test for
// a real live false-positive (2026-09-02): a probe IS wired up (unlike
// TestWatchdogDegradedWhenProbeUnconfigured's nil-probe case), but this
// specific poll fails (hostagent RPC hiccup, or BIND's statistics
// channel not yet available). That must be treated the same as a
// genuinely quiet/unconfirmable network -- NOT a confirmed stall -- so
// it never demotes the whole appliance's /api/health to "degraded" on
// an otherwise perfectly healthy, merely-idle connection.
func TestWatchdogNotStalledWhenProbeUnreachable(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "analytics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	wtr := &Writer{DB: db, StaleThreshold: 1 * time.Millisecond}
	wtr.startedAt.Store(time.Now().Add(-1 * time.Hour).Unix())
	wtr.TrafficProbe = func(ctx context.Context) (int64, bool) {
		return 0, false // probe configured but unreachable/unavailable this poll
	}

	wtr.checkIngestionOnce(context.Background())

	ing := wtr.Ingestion()
	if ing.Stalled {
		t.Error("must not report stalled when the traffic probe is merely unreachable this poll -- that's unconfirmable, not a confirmed stall")
	}
	if !ing.TrafficProbeConfigured || ing.TrafficProbeOK {
		t.Errorf("TrafficProbeConfigured=%v TrafficProbeOK=%v, want configured=true ok=false (the honest signal should still be visible)", ing.TrafficProbeConfigured, ing.TrafficProbeOK)
	}
	if ing.RecoveryCount != 0 {
		t.Error("must never force-close on an unconfirmable probe result")
	}
}
