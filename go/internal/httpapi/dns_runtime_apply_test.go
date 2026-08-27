package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnsruntime"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/upstreams"
)

// newServerWithRealDNSRuntime is the real-consistency-proof fixture:
// every one of Local DNS/Custom Rules/Blocklists/DNS Settings/DNS
// Transports must reach the exact same real DNS-runtime pipeline
// (internal/hostagentd's real dnsdist/BIND, not a mock) when its own
// mutation handler is called -- this is what the governing task's
// "resolver-affecting mutations must either auto-apply... or use one
// clear, uniform... workflow" requirement means proven for real, not
// just asserted by reading the handler source.
func newServerWithRealDNSRuntime(t *testing.T) (*Server, int) {
	t.Helper()
	for _, bin := range []string{"named", "rndc", "dnsdist", "dig"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available in this environment", bin)
		}
	}
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	bindDir := filepath.Join("/var/lib/bind", fmt.Sprintf("httpapi-dnsruntime-test-%d", os.Getpid()), t.Name())
	if err := os.MkdirAll(bindDir, 0o755); err != nil {
		t.Skipf("cannot create test dir under /var/lib/bind: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(bindDir) })

	dnsdistPort := freePortForTest(t)
	cfg := hostagentd.DNSRuntimeConfig{
		StagingDir: t.TempDir(), BindLivePath: filepath.Join(bindDir, "named.conf"), BindDirectory: bindDir, BindLogPath: filepath.Join(bindDir, "named.log"),
		DnsdistLivePath: filepath.Join(t.TempDir(), "dnsdist.conf"),
		BindPlainPort:   freePortForTest(t), BindProxyPort: freePortForTest(t), BindStatsPort: freePortForTest(t), BindRNDCPort: freePortForTest(t),
		DnsdistListenAddress:  fmt.Sprintf("127.0.0.1:%d", dnsdistPort),
		HealthCheckTimeout:    8 * time.Second,
		HealthCheckRetryDelay: 100 * time.Millisecond,
	}
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	agent := &hostagentd.Server{SocketPath: sockPath, AllowedUID: uint32(os.Getuid()), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	stop, err := hostagentd.RegisterDNSRuntimeOps(agent, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Otherwise the real named/dnsdist a promotion in this test brings
	// up outlive it, orphaned under init.
	t.Cleanup(stop)
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

	customRulesSvc := &customrules.Service{DB: db}
	blocklistsSvc := &blocklists.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}
	upstreamsSvc := &upstreams.Service{DB: db}
	dnsTransportsSvc := &dnstransports.Service{DB: db}
	policySvc := &policy.Service{DB: db}
	localDNSSvc := &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}

	orch := &dnsruntime.Orchestrator{
		LocalDNS: localDNSSvc, CustomRules: customRulesSvc, Blocklists: blocklistsSvc, Upstreams: upstreamsSvc, DNSTransports: dnsTransportsSvc, Policy: policySvc,
		HostAgent: hostagent.NewClient(sockPath), DnsdistListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
	}
	s := &Server{
		DB: db, CustomRules: customRulesSvc, Blocklists: blocklistsSvc, Upstreams: upstreamsSvc, DNSTransports: dnsTransportsSvc, Policy: policySvc, LocalDNS: localDNSSvc,
		DNSRuntime: orch, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	return s, dnsdistPort
}

func freePortForTest(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func dnsRuntimeFieldFromResponse(t *testing.T, rec *httptest.ResponseRecorder) dnsruntime.Result {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v\nbody: %s", err, rec.Body.String())
	}
	raw, ok := body["dns_runtime"]
	if !ok {
		t.Fatalf("response has no dns_runtime field: %s", rec.Body.String())
	}
	var res dnsruntime.Result
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatalf("invalid dns_runtime field: %v", err)
	}
	return res
}

func realDig(t *testing.T, port int, name, qtype string) string {
	t.Helper()
	out, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@127.0.0.1", "-p", fmt.Sprint(port), name, qtype).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// TestCustomRuleCreateAutoAppliesAndRealAnswerChanges is the strongest
// form of proof: creating a block-type custom rule through the exact
// real HTTP handler must both report a real promoted dns_runtime
// result AND actually change what a real dig gets back.
func TestCustomRuleCreateAutoAppliesAndRealAnswerChanges(t *testing.T) {
	s, dnsdistPort := newServerWithRealDNSRuntime(t)

	// An initial promotion with no rules yet -- establishes the
	// baseline runtime (nothing is listening at all until the first
	// promotion), so the real "before" state is a real, running
	// dnsdist that genuinely has no rule for this domain yet, not "no
	// server running at all" (a different, uninteresting case).
	if res := s.DNSRuntime.Apply(context.Background()); !res.Promoted {
		t.Fatalf("expected the baseline promotion to succeed, got %+v", res)
	}
	before := realDig(t, dnsdistPort, "ads.consistency-test.example", "A")
	if before != "" {
		t.Fatalf("expected no answer before any rule exists, got %q", before)
	}

	body := strings.NewReader(`{"rule_type":"block","pattern":"ads.consistency-test.example"}`)
	req := httptest.NewRequest("POST", "/api/custom-rules", body)
	rec := httptest.NewRecorder()
	s.handleCreateCustomRule(rec, req)
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	res := dnsRuntimeFieldFromResponse(t, rec)
	if !res.Attempted || !res.Promoted {
		t.Fatalf("expected the custom rule create to auto-apply and promote, got %+v", res)
	}

	after := realDig(t, dnsdistPort, "ads.consistency-test.example", "A")
	// NXDOMAIN (the default blocking_response_mode) produces no A
	// record and a real dig +short prints nothing -- the real proof is
	// the status code, checked via a non-short query.
	out, err := exec.Command("dig", "+time=2", "+tries=2", "@127.0.0.1", "-p", fmt.Sprint(dnsdistPort), "ads.consistency-test.example", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "status: NXDOMAIN") {
		t.Fatalf("expected a real NXDOMAIN after the block rule was created and auto-applied, got:\n%s", out)
	}
	_ = after
}

func TestUpstreamCreateAutoApplies(t *testing.T) {
	s, _ := newServerWithRealDNSRuntime(t)
	body := strings.NewReader(`{"name":"Test","transport":"plain","strategy":"ordered","endpoints":[{"address":"9.9.9.9:53","weight":1}]}`)
	req := httptest.NewRequest("POST", "/api/upstreams", body)
	rec := httptest.NewRecorder()
	s.handleCreateUpstream(rec, req)
	if rec.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	res := dnsRuntimeFieldFromResponse(t, rec)
	if !res.Attempted || !res.Promoted {
		t.Fatalf("expected the upstream create to auto-apply and promote, got %+v", res)
	}
}

func TestDNSTransportsUpdateAutoApplies(t *testing.T) {
	s, _ := newServerWithRealDNSRuntime(t)
	certDir := t.TempDir()
	certPath := filepath.Join(certDir, "server.crt")
	keyPath := filepath.Join(certDir, "server.key")
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", "/CN=test").CombinedOutput(); err != nil {
		t.Skipf("openssl not usable: %v: %s", err, out)
	}
	s.DNSRuntime.TLSCertPath, s.DNSRuntime.TLSKeyPath = certPath, keyPath

	body := strings.NewReader(`{"dot_enabled":true,"dot_port":8853,"doh_port":443,"doh_path":"/dns-query","doq_port":853,"doh3_port":443,"dnscrypt_port":5443,"dnscrypt_provider_name":"2.dnscrypt-cert.test"}`)
	req := httptest.NewRequest("PUT", "/api/dns-transports", body)
	rec := httptest.NewRecorder()
	s.handleUpdateDNSTransports(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	res := dnsRuntimeFieldFromResponse(t, rec)
	if !res.Attempted || !res.Promoted {
		t.Fatalf("expected the DNS transports update to auto-apply and promote, got %+v", res)
	}
}

func TestBlocklistToggleAutoApplies(t *testing.T) {
	s, _ := newServerWithRealDNSRuntime(t)
	// Create bypasses the HTTP handler (which would also kick off a
	// real network pull against an unreachable URL) -- seed directly
	// via the service, matching this test's own narrow focus on the
	// Toggle handler's auto-apply wiring.
	if _, _, err := s.Blocklists.Create(context.Background(), "test-list", "Test List", "https://example.invalid/list.txt", "test"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/blocklists/test-list/toggle", nil)
	req.SetPathValue("id", "test-list")
	rec := httptest.NewRecorder()
	s.handleToggleBlocklist(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	res := dnsRuntimeFieldFromResponse(t, rec)
	if !res.Attempted || !res.Promoted {
		t.Fatalf("expected the blocklist toggle to auto-apply and promote, got %+v", res)
	}
}
