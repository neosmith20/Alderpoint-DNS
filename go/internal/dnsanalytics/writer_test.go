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
