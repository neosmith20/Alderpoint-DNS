package hostagentd

import (
	"context"
	"net"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dnsperf"
	"alderpointdns/go-controlplane/internal/hostagent"
)

// startFakeDNSUDP is a minimal real UDP DNS responder -- the same
// shape internal/dnsperf's own tests use, duplicated here (not
// exported) because this package proves the op end-to-end through the
// real unix-socket protocol, not just the query engine underneath it.
func startFakeDNSUDP(t *testing.T) (port int, stop func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 512)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, addr, err := conn.ReadFromUDP(buf)
			select {
			case <-done:
				return
			default:
			}
			if err != nil {
				continue
			}
			reply := make([]byte, n)
			copy(reply, buf[:n])
			reply[2] = 0x81 // QR=1, RD=1
			reply[3] = 0x80 // RA=1, RCODE=0
			conn.WriteToUDP(reply, addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() { close(done); conn.Close() }
}

type dnsPerfResult struct {
	Samples []dnsperf.Sample `json:"samples"`
}

func TestDNSPerfBenchmarkEndToEndThroughRealSocket(t *testing.T) {
	port, stop := startFakeDNSUDP(t)
	defer stop()

	s, sockPath := newTestServer(t, uint32(0))
	RegisterDNSPerfOps(s, DNSPerfConfig{DnsdistHost: "127.0.0.1", DnsdistPort: port, BindPlainPort: port})

	c := hostagent.NewClient(sockPath)

	var hot dnsPerfResult
	if err := c.Call(context.Background(), hostagent.OpDNSPerfBenchmark, map[string]any{
		"target": "dnsdist", "domain": "example.com.", "protocol": "udp", "queries": 5, "timeout_seconds": 1,
	}, &hot); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hot.Samples) != 5 {
		t.Fatalf("expected 5 samples, got %+v", hot.Samples)
	}
	for _, s := range hot.Samples {
		if !s.OK || s.Timeout {
			t.Fatalf("expected an ok sample, got %+v", s)
		}
	}

	var direct dnsPerfResult
	if err := c.Call(context.Background(), hostagent.OpDNSPerfBenchmark, map[string]any{
		"target": "bind_plain", "domain": "example.com.", "protocol": "udp", "queries": 3, "timeout_seconds": 1,
	}, &direct); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(direct.Samples) != 3 {
		t.Fatalf("expected 3 samples, got %+v", direct.Samples)
	}
}

func TestDNSPerfBenchmarkRejectsUnconfiguredRuntimeHonestly(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	RegisterDNSPerfOps(s, DNSPerfConfig{}) // DNS Runtime not configured on this agent

	c := hostagent.NewClient(sockPath)
	var out dnsPerfResult
	err := c.Call(context.Background(), hostagent.OpDNSPerfBenchmark, map[string]any{
		"target": "dnsdist", "domain": "example.com.", "protocol": "udp", "queries": 1,
	}, &out)
	if err == nil {
		t.Fatal("expected an honest denial, not fabricated samples, when DNS runtime isn't configured")
	}
}

func TestDNSPerfBenchmarkRejectsUnknownTarget(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	RegisterDNSPerfOps(s, DNSPerfConfig{DnsdistHost: "127.0.0.1", DnsdistPort: 1})

	c := hostagent.NewClient(sockPath)
	var out dnsPerfResult
	err := c.Call(context.Background(), hostagent.OpDNSPerfBenchmark, map[string]any{
		"target": "some-remote-host", "domain": "example.com.", "protocol": "udp", "queries": 1,
	}, &out)
	if err == nil {
		t.Fatal("expected unknown target to be rejected -- this op must never accept a caller-supplied server/port")
	}
}

func TestDNSPerfBenchmarkRejectsExcessiveQueries(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	RegisterDNSPerfOps(s, DNSPerfConfig{DnsdistHost: "127.0.0.1", DnsdistPort: 1})

	c := hostagent.NewClient(sockPath)
	var out dnsPerfResult
	err := c.Call(context.Background(), hostagent.OpDNSPerfBenchmark, map[string]any{
		"target": "dnsdist", "domain": "example.com.", "protocol": "udp", "queries": maxDNSPerfQueriesPerCase + 1,
	}, &out)
	if err == nil {
		t.Fatal("expected a query-count cap to be enforced")
	}
}

func TestDNSPerfBenchmarkDoTPortIsBoundedRange(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	RegisterDNSPerfOps(s, DNSPerfConfig{DnsdistHost: "127.0.0.1", DnsdistPort: 1})

	c := hostagent.NewClient(sockPath)
	var out dnsPerfResult
	err := c.Call(context.Background(), hostagent.OpDNSPerfBenchmark, map[string]any{
		"target": "dot", "domain": "example.com.", "protocol": "dot", "queries": 1, "port": 70000,
	}, &out)
	if err == nil {
		t.Fatal("expected an out-of-range port to be rejected")
	}
}

func TestDNSPerfBenchmarkRejectsEmptyDomain(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	RegisterDNSPerfOps(s, DNSPerfConfig{DnsdistHost: "127.0.0.1", DnsdistPort: 1})

	c := hostagent.NewClient(sockPath)
	var out dnsPerfResult
	err := c.Call(context.Background(), hostagent.OpDNSPerfBenchmark, map[string]any{
		"target": "dnsdist", "protocol": "udp", "queries": 1,
	}, &out)
	if err == nil {
		t.Fatal("expected an empty domain to be rejected")
	}
}
