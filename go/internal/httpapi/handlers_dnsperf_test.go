package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dnsperf"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
)

func TestHandleDNSPerfStatusReportsUnavailableWithNoService(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodGet, "/api/dns/performance", nil)
	w := httptest.NewRecorder()
	s.handleDNSPerfStatus(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestHandleDNSPerfBenchmarkReportsUnavailableWithNoService(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest(http.MethodPost, "/api/dns/performance/benchmark", nil)
	w := httptest.NewRecorder()
	s.handleDNSPerfBenchmark(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func startFakeDNSUDPForHTTP(t *testing.T) (port int, stop func()) {
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
			reply[2] = 0x81
			reply[3] = 0x80
			conn.WriteToUDP(reply, addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port, func() { close(done); conn.Close() }
}

// TestDNSPerfBenchmarkRealEndToEnd proves the full real path: HTTP
// request -> httpapi handler -> internal/dnsperf.Service -> a real
// unix-socket hostagent client -> a real hostagentd.Server ->
// internal/dnsperf's own UDP packet exchange against a real, disposable
// UDP responder -- not a mock at any layer.
func TestDNSPerfBenchmarkRealEndToEnd(t *testing.T) {
	port, stop := startFakeDNSUDPForHTTP(t)
	defer stop()

	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	agent := &hostagentd.Server{SocketPath: sockPath, AllowedUID: uint32(os.Getuid()), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	hostagentd.RegisterDNSPerfOps(agent, hostagentd.DNSPerfConfig{DnsdistHost: "127.0.0.1", DnsdistPort: port})
	agentCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go agent.Serve(agentCtx)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	client := hostagent.NewClient(sockPath)
	svc := &dnsperf.Service{
		ReportPath: filepath.Join(t.TempDir(), "latest-report.json"),
		Querier:    dnsperf.HostAgentQuerier{Client: client},
		BuildCases: func(ctx context.Context) ([]dnsperf.BenchmarkCase, []string, error) {
			return []dnsperf.BenchmarkCase{
				{Name: "hot", Scope: "test", Target: "dnsdist", Domain: "example.com.", Protocol: "udp", Queries: 5, Timeout: time.Second},
			}, []string{"a note"}, nil
		},
	}
	s := &Server{DNSPerf: svc, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	// Before running: no report yet, not running.
	req := httptest.NewRequest(http.MethodGet, "/api/dns/performance", nil)
	w := httptest.NewRecorder()
	s.handleDNSPerfStatus(w, req)
	var status map[string]any
	json.NewDecoder(w.Body).Decode(&status)
	if status["benchmark_running"] != false || status["report"] != nil {
		t.Fatalf("expected no report and not running before the first run, got %+v", status)
	}

	// Start.
	req = httptest.NewRequest(http.MethodPost, "/api/dns/performance/benchmark", nil)
	w = httptest.NewRecorder()
	s.handleDNSPerfBenchmark(w, req)
	var started map[string]any
	json.NewDecoder(w.Body).Decode(&started)
	if started["status"] != "started" {
		t.Fatalf("expected status=started, got %+v", started)
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		running, _ := svc.Status()
		if !running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/dns/performance", nil)
	w = httptest.NewRecorder()
	s.handleDNSPerfStatus(w, req)
	json.NewDecoder(w.Body).Decode(&status)
	report, ok := status["report"].(map[string]any)
	if !ok {
		t.Fatalf("expected a real report after the run completed, got %+v", status)
	}
	cases, _ := report["cases"].([]any)
	if len(cases) != 1 {
		t.Fatalf("expected 1 case result, got %+v", report)
	}
	caseResult := cases[0].(map[string]any)
	summary := caseResult["summary"].(map[string]any)
	if summary["count"] != float64(5) || summary["success"] != float64(5) {
		t.Fatalf("expected 5/5 real success, got %+v", summary)
	}

	// Clear.
	req = httptest.NewRequest(http.MethodDelete, "/api/dns/performance", nil)
	w = httptest.NewRecorder()
	s.handleDNSPerfClear(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("clear status = %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/dns/performance", nil)
	w = httptest.NewRecorder()
	s.handleDNSPerfStatus(w, req)
	json.NewDecoder(w.Body).Decode(&status)
	if status["report"] != nil {
		t.Fatalf("expected report to be gone after Clear, got %+v", status["report"])
	}
}
