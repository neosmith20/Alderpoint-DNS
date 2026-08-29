package hostagentd

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dnscompile"
)

// dnsRuntimeTestDir returns a real, writable directory under
// /var/lib/bind (AppArmor-allowed for the real named binary -- see
// startTestBind's own comment) for this specific test's BIND instance.
func dnsRuntimeTestDir(t *testing.T) string {
	t.Helper()
	for _, bin := range []string{"named", "rndc", "dnsdist", "dig"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available in this environment", bin)
		}
	}
	dir := filepath.Join("/var/lib/bind", fmt.Sprintf("dnsruntime-test-%d", os.Getpid()), t.Name())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot create test dir under /var/lib/bind: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func newDNSRuntimeConfig(t *testing.T) (*Server, DNSRuntimeConfig) {
	t.Helper()
	bindDir := dnsRuntimeTestDir(t)
	stagingDir := t.TempDir()
	dnsdistLive := filepath.Join(t.TempDir(), "dnsdist.conf")
	dnsdistPort := freeTCPPort(t)

	cfg := DNSRuntimeConfig{
		StagingDir:   stagingDir,
		BindLivePath: filepath.Join(bindDir, "named.conf"), BindDirectory: bindDir, BindLogPath: filepath.Join(bindDir, "named.log"),
		DnsdistLivePath: dnsdistLive,
		BindPlainPort:   freeTCPPort(t), BindProxyPort: freeTCPPort(t), BindStatsPort: freeTCPPort(t), BindRNDCPort: freeTCPPort(t),
		DnsdistListenAddress:  fmt.Sprintf("127.0.0.1:%d", dnsdistPort),
		HealthCheckTimeout:    8 * time.Second,
		HealthCheckRetryDelay: 100 * time.Millisecond,
	}
	s := &Server{}
	stop, err := RegisterDNSRuntimeOps(s, cfg)
	if err != nil {
		t.Fatalf("RegisterDNSRuntimeOps: %v", err)
	}
	// Every real named/dnsdist process a promotion in this test starts
	// must be gone by the time the test exits, or it's orphaned
	// (reparented to init) and leaks for the life of the host.
	t.Cleanup(stop)
	return s, cfg
}

func callPromote(t *testing.T, s *Server, params DNSPromoteParams) *DNSPromoteResult {
	t.Helper()
	h, ok := s.handlers[promoteOpName()]
	if !ok {
		t.Fatal("dns_runtime.promote is not registered")
	}
	body, _ := json.Marshal(params)
	result, err := h(context.Background(), body)
	if err != nil {
		t.Fatalf("promote returned an error (expected a structured rejection or success): %v", err)
	}
	pr, ok := result.(*DNSPromoteResult)
	if !ok {
		t.Fatalf("unexpected result type %T", result)
	}
	return pr
}

// callPromoteExpectingError is for the "validation must reject before
// anything is touched" cases, where the handler legitimately returns a
// Go error (mapped to code=denied over the real socket).
func callPromoteExpectingError(t *testing.T, s *Server, params DNSPromoteParams) error {
	t.Helper()
	h := s.handlers[promoteOpName()]
	body, _ := json.Marshal(params)
	_, err := h(context.Background(), body)
	return err
}

func promoteOpName() string { return "dns_runtime.promote" }

func realHealthMarkerDig(t *testing.T, addr string) string {
	t.Helper()
	host, port := splitHostPort(addr)
	out, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@"+host, "-p", port, dnscompile.HealthMarkerDomain, "A").Output()
	if err != nil {
		t.Fatalf("dig failed: %v", err)
	}
	return trimNL(string(out))
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func TestDNSRuntimePromoteBringsUpRealBindAndDnsdist(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	in := dnscompile.Input{ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort), CacheMaxEntries: 1000}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted || res.RolledBack {
		t.Fatalf("expected a clean promotion, got %+v", res)
	}
	answer := realHealthMarkerDig(t, cfg.DnsdistListenAddress)
	if answer != dnscompile.HealthMarkerIP {
		t.Fatalf("expected the health marker's real answer %q, got %q", dnscompile.HealthMarkerIP, answer)
	}
}

// TestDNSRuntimePromoteHealthCheckDialsLoopbackNotWildcard is the
// direct regression proof for the 2026-08-28 incident's disclosed
// health-check bug (see AGENT_PROGRESS.md): every real live deployment
// configures DnsdistListenAddress as "0.0.0.0:53" (it must bind every
// interface to serve real LAN clients), but the health check used to
// dial "0.0.0.0" itself as the query DESTINATION, which is not a valid
// loopback alias and returned "connection refused" -- so a genuinely
// healthy promotion falsely reported rolled_back:true. Every other test
// in this file uses a "127.0.0.1:<port>" listen address (a test fixture
// has no real LAN clients to serve), so this exact bug was invisible
// everywhere except a live "0.0.0.0" deployment until now.
func TestDNSRuntimePromoteHealthCheckDialsLoopbackNotWildcard(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	wildcardAddr := strings.Replace(cfg.DnsdistListenAddress, "127.0.0.1", "0.0.0.0", 1)
	in := dnscompile.Input{ListenAddress: wildcardAddr, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort), CacheMaxEntries: 1000}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted || res.RolledBack {
		t.Fatalf("expected a real, genuinely healthy promotion on a wildcard listen address, got %+v (this is the exact false-rollback bug from the 2026-08-28 incident if it regresses)", res)
	}
	// Confirm the real dnsdist is actually reachable over the real
	// loopback address too (not just that the health check itself
	// passed) -- both UDP and TCP.
	_, port := splitHostPort(cfg.DnsdistListenAddress)
	answer := realHealthMarkerDig(t, "127.0.0.1:"+port)
	if answer != dnscompile.HealthMarkerIP {
		t.Fatalf("expected the health marker's real answer over UDP, got %q", answer)
	}
	tcpOut, err := exec.Command("dig", "+tcp", "+time=2", "+tries=2", "+short", "@127.0.0.1", "-p", port, dnscompile.HealthMarkerDomain, "A").Output()
	if err != nil || strings.TrimSpace(string(tcpOut)) != dnscompile.HealthMarkerIP {
		t.Fatalf("expected the health marker's real answer over TCP, got %q err=%v", tcpOut, err)
	}
}

// TestSplitHostPortHealthCheckMapping is a narrow unit proof of the
// wildcard-to-loopback mapping itself, independent of a real promotion.
func TestSplitHostPortHealthCheckMapping(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0:53":  "127.0.0.1",
		"10.0.0.5:53": "10.0.0.5", // a real, specific bind address must be dialed as-is, never rewritten
	}
	for addr, wantHost := range cases {
		host, _ := splitHostPort(addr)
		if host == "0.0.0.0" {
			host = "127.0.0.1"
		} else if host == "::" {
			host = "::1"
		}
		if host != wantHost {
			t.Errorf("health-check dial host for %q = %q, want %q", addr, host, wantHost)
		}
	}
}

func TestDNSRuntimePromoteRejectsInvalidDnsdistConfig(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	err := callPromoteExpectingError(t, s, DNSPromoteParams{DnsdistConf: "this is not valid Lua {{{"})
	if err == nil {
		t.Fatal("expected the invalid dnsdist config to be rejected")
	}
	if _, statErr := os.Stat(cfg.DnsdistLivePath); !os.IsNotExist(statErr) {
		t.Fatalf("nothing should have been promoted for an invalid config, but the live file exists")
	}
}

func TestDNSRuntimePromoteRejectsEmptyDnsdistConf(t *testing.T) {
	s, _ := newDNSRuntimeConfig(t)
	err := callPromoteExpectingError(t, s, DNSPromoteParams{})
	if err == nil {
		t.Fatal("expected an error for an empty dnsdist_conf")
	}
}

func TestDNSRuntimePromoteRejectsInvalidBindForwarders(t *testing.T) {
	s, _ := newDNSRuntimeConfig(t)
	in := dnscompile.Input{ListenAddress: "127.0.0.1:19999"}
	dnsdistConf, _ := dnscompile.CompileDnsdist(in)
	err := callPromoteExpectingError(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf, BindForwarders: []string{"not-a-valid-forwarder"}})
	if err == nil {
		t.Fatal("expected the malformed forwarder to be rejected before anything was staged")
	}
}

// TestDNSRuntimePromoteLocalDnsAnswer proves a real Go control-plane
// change (a Local DNS record compiled in) actually affects real
// resolver behavior: dig gets the configured answer, end to end,
// through a real dnsdist process this test brought up itself.
func TestDNSRuntimePromoteLocalDnsAnswer(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		LocalDNSRecords: []dnscompile.LocalDNSRecord{{Name: "printer.lan", RecordType: "A", Value: "10.20.30.40", TTL: 300}},
		CacheMaxEntries: 1000,
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}
	host, port := splitHostPort(cfg.DnsdistListenAddress)
	out, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@"+host, "-p", port, "printer.lan", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := trimNL(string(out)); got != "10.20.30.40" {
		t.Fatalf("expected the real compiled Local DNS answer 10.20.30.40, got %q", got)
	}
}

// TestDNSRuntimePromoteBlockedDomain proves a compiled block rule
// actually changes real resolver behavior (a real NXDOMAIN/REFUSED
// rcode from a real dig, not just config text containing the right
// string).
func TestDNSRuntimePromoteBlockedDomain(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		BlockedDomains: []string{"ads.example.test"}, BlockingResponseMode: "refused",
		CacheMaxEntries: 1000,
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}
	host, port := splitHostPort(cfg.DnsdistListenAddress)
	out, err := exec.Command("dig", "+time=2", "+tries=2", "@"+host, "-p", port, "ads.example.test", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(out), "status: REFUSED") {
		t.Fatalf("expected a real REFUSED response for the blocked domain, got:\n%s", out)
	}
}

// TestDNSRuntimePromoteUpstreamRouting proves a Go-configured default
// upstream profile actually determines which real backend answers a
// query -- a controlled fake upstream this test runs itself (no
// internet egress dependency), not BIND, so the answer can only have
// come from following the configured route.
func TestDNSRuntimePromoteUpstreamRouting(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	fakeUpstreamAddr := startFakeUpstream(t, "203.0.113.201")

	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress,
		// BindBackendAddress deliberately empty: this profile must go
		// DIRECT to the fake upstream, not through BIND, so a correct
		// answer proves real routing to the configured endpoint.
		DefaultProfile: &dnscompile.UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []dnscompile.UpstreamEndpoint{{Address: fakeUpstreamAddr}}},
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}
	host, port := splitHostPort(cfg.DnsdistListenAddress)
	out, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@"+host, "-p", port, "anything.example.test", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := trimNL(string(out)); got != "203.0.113.201" {
		t.Fatalf("expected the answer from the configured fake upstream (203.0.113.201), got %q -- routing did not follow the configured profile", got)
	}
}

// TestDNSRuntimePromoteDomainRoutingSendsMatchedDomainToItsOwnUpstream
// is domain routing's own real end-to-end proof, same rigor as upstream
// routing above: two distinct controlled fake upstreams (no internet
// egress dependency), one default and one attached only to a suffix
// route. A query for a domain under the routed suffix must get the
// ROUTE's answer; a query for anything else must still get the
// DEFAULT's answer -- proving both that the route is followed and that
// it doesn't leak into traffic it was never supposed to match.
func TestDNSRuntimePromoteDomainRoutingSendsMatchedDomainToItsOwnUpstream(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	defaultUpstreamAddr := startFakeUpstream(t, "203.0.113.10")
	routedUpstreamAddr := startFakeUpstream(t, "203.0.113.20")

	in := dnscompile.Input{
		ListenAddress:  cfg.DnsdistListenAddress,
		DefaultProfile: &dnscompile.UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []dnscompile.UpstreamEndpoint{{Address: defaultUpstreamAddr}}},
		DomainRoutes: []dnscompile.DomainRoute{{
			MatchKind: "suffix", Domain: "corp.example.test", ProfileID: "corp",
			Profile: dnscompile.UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []dnscompile.UpstreamEndpoint{{Address: routedUpstreamAddr}}},
		}},
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}

	host, port := splitHostPort(cfg.DnsdistListenAddress)
	routed, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@"+host, "-p", port, "host.corp.example.test", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := trimNL(string(routed)); got != "203.0.113.20" {
		t.Fatalf("expected a query under the routed suffix to get the ROUTE's answer (203.0.113.20), got %q", got)
	}

	unrouted, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@"+host, "-p", port, "anything.example.test", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := trimNL(string(unrouted)); got != "203.0.113.10" {
		t.Fatalf("expected a query NOT under the routed suffix to still get the DEFAULT's answer (203.0.113.10), got %q -- the route leaked into unrelated traffic", got)
	}
}

// TestDNSRuntimePromoteRollsBackOnHealthCheckFailure proves the
// automatic-rollback safety path for real: a first promotion succeeds
// and answers real queries; a second promotion whose health check is
// engineered to fail (a listen-address mismatch a real operator typo
// could produce) must restore the FIRST config, not leave the runtime
// on the broken one -- proven by dig still getting the first
// promotion's real answer afterward.
// TestDNSRuntimePromoteNetworkOverrideAppliesWhenSourceMatches and
// TestDNSRuntimePromoteNetworkOverrideDoesNotApplyOutsideItsCIDR
// together are per-network policy compilation's own real end-to-end
// proof, the same rigor as domain routing's/upstream routing's own
// tests above: a real dig query's actual source is always 127.0.0.1 in
// this test environment (no privilege to spoof a source address), so
// "genuinely scoped, not just globally applied" is proven by two
// promotions with a network override on OPPOSITE sides of that real
// source address -- one whose CIDR includes 127.0.0.1 (must apply) and
// one whose CIDR does not (must NOT apply, global still wins) -- rather
// than by one query alone, which could never distinguish "the override
// works" from "the override is accidentally unconditional".
func TestDNSRuntimePromoteNetworkOverrideAppliesWhenSourceMatches(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		BlockedDomains: []string{"ads.example.test"}, BlockingResponseMode: "nxdomain",
		NetworkOverrides: []dnscompile.NetworkOverride{{CIDR: "127.0.0.1/32", BlockingResponseMode: "refused"}},
		CacheMaxEntries:  1000,
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}
	host, port := splitHostPort(cfg.DnsdistListenAddress)
	out, err := exec.Command("dig", "+time=2", "+tries=2", "@"+host, "-p", port, "ads.example.test", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(out), "status: REFUSED") {
		t.Fatalf("query genuinely originates from 127.0.0.1 (inside the override's /32) -- expected the network-overridden REFUSED response, got:\n%s", out)
	}
}

func TestDNSRuntimePromoteNetworkOverrideDoesNotApplyOutsideItsCIDR(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	in := dnscompile.Input{
		ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
		BlockedDomains: []string{"ads.example.test"}, BlockingResponseMode: "nxdomain",
		// This override's CIDR deliberately does NOT include 127.0.0.1
		// (the real, unspoofable source of the dig query below) --
		// global nxdomain must still win.
		NetworkOverrides: []dnscompile.NetworkOverride{{CIDR: "10.0.0.0/8", BlockingResponseMode: "refused"}},
		CacheMaxEntries:  1000,
	}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res := callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res.Promoted {
		t.Fatalf("expected promotion to succeed, got %+v", res)
	}
	host, port := splitHostPort(cfg.DnsdistListenAddress)
	out, err := exec.Command("dig", "+time=2", "+tries=2", "@"+host, "-p", port, "ads.example.test", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(out), "status: NXDOMAIN") {
		t.Fatalf("query genuinely originates from 127.0.0.1 (OUTSIDE the override's 10.0.0.0/8) -- expected the real global NXDOMAIN response, not the network override, got:\n%s", out)
	}
}

func TestDNSRuntimePromoteRollsBackOnHealthCheckFailure(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	good := dnscompile.Input{
		ListenAddress:   cfg.DnsdistListenAddress,
		LocalDNSRecords: []dnscompile.LocalDNSRecord{{Name: "good.lan", RecordType: "A", Value: "10.0.0.11", TTL: 300}},
		DefaultProfile:  &dnscompile.UpstreamProfile{Transport: "plain", Endpoints: []dnscompile.UpstreamEndpoint{{Address: startFakeUpstream(t, "192.0.2.11")}}},
	}
	goodConf, err := dnscompile.CompileDnsdist(good)
	if err != nil {
		t.Fatal(err)
	}
	first := callPromote(t, s, DNSPromoteParams{DnsdistConf: goodConf})
	if !first.Promoted {
		t.Fatalf("expected the first (good) promotion to succeed, got %+v", first)
	}

	// A second config that's perfectly valid Lua (so it validates and
	// gets promoted) but whose setLocal address deliberately does not
	// match cfg.DnsdistListenAddress -- the health check dials the
	// configured address and will never see this process answer,
	// exactly the real failure mode a listen-address typo produces.
	otherPort := freeTCPPort(t)
	bad := dnscompile.Input{
		ListenAddress:   fmt.Sprintf("127.0.0.1:%d", otherPort),
		LocalDNSRecords: []dnscompile.LocalDNSRecord{{Name: "bad.lan", RecordType: "A", Value: "10.0.0.99", TTL: 300}},
		DefaultProfile:  &dnscompile.UpstreamProfile{Transport: "plain", Endpoints: []dnscompile.UpstreamEndpoint{{Address: startFakeUpstream(t, "192.0.2.99")}}},
	}
	badConf, err := dnscompile.CompileDnsdist(bad)
	if err != nil {
		t.Fatal(err)
	}
	second := callPromote(t, s, DNSPromoteParams{DnsdistConf: badConf})
	if second.Promoted || !second.RolledBack {
		t.Fatalf("expected the second promotion to roll back, got %+v", second)
	}
	if second.Stage != "health_check" {
		t.Fatalf("expected the rollback to be reported at stage=health_check, got %+v", second)
	}

	// The real proof: the runtime must still be serving the FIRST
	// (good) config's real answer, not the second's.
	host, port := splitHostPort(cfg.DnsdistListenAddress)
	out, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@"+host, "-p", port, "good.lan", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := trimNL(string(out)); got != "10.0.0.11" {
		t.Fatalf("expected the pre-rollback config's real answer to still be live (10.0.0.11), got %q", got)
	}
}

func TestDNSRuntimeStatusReportsRunningProcesses(t *testing.T) {
	s, cfg := newDNSRuntimeConfig(t)
	statusHandler := s.handlers["dns_runtime.status"]
	body, err := statusHandler(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	status := body.(DNSRuntimeStatus)
	if status.BindRunning || status.DnsdistRunning {
		t.Fatalf("expected nothing running before any promotion, got %+v", status)
	}

	in := dnscompile.Input{ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort), CacheMaxEntries: 1000}
	dnsdistConf, _ := dnscompile.CompileDnsdist(in)
	callPromote(t, s, DNSPromoteParams{DnsdistConf: dnsdistConf})

	body2, err := statusHandler(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	status2 := body2.(DNSRuntimeStatus)
	if !status2.BindRunning || !status2.DnsdistRunning {
		t.Fatalf("expected both real processes reported running after a successful promotion, got %+v", status2)
	}
}

// TestHostagentRestartAdoptsRunningNamedInsteadOfDuplicating is the
// direct regression proof for the 2026-08-29 incident (see
// trackedProcess's own doc comment): a fresh dnsRuntimeState created by
// a NEW hostagent generation (simulated here by a second, independent
// RegisterDNSRuntimeOps call against the SAME cfg/staging dir, exactly
// what a real hostagent restart does -- it never stops the previous
// generation's named/dnsdist) must ADOPT the already-running real named
// process, not spawn a second one alongside it.
func TestHostagentRestartAdoptsRunningNamedInsteadOfDuplicating(t *testing.T) {
	s1, cfg := newDNSRuntimeConfig(t)
	in := dnscompile.Input{ListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort), CacheMaxEntries: 1000}
	dnsdistConf, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	res1 := callPromote(t, s1, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res1.Promoted {
		t.Fatalf("expected the first generation's promotion to succeed, got %+v", res1)
	}
	firstBindPID := readPIDFile(t, bindPIDFile(cfg))
	firstDnsdistPID := readPIDFile(t, dnsdistPIDFile(cfg))
	if !processAlive(firstBindPID) || !processAlive(firstDnsdistPID) {
		t.Fatal("expected the first generation's real named/dnsdist to be alive")
	}

	// Simulate a real hostagent restart: a brand-new Server + a brand-
	// new dnsRuntimeState (RegisterDNSRuntimeOps creates one), same cfg
	// -- the production agent never calls the first generation's stop
	// func on this path (see RegisterDNSRuntimeOps's own doc comment:
	// "the whole point of this runtime is that the live DNS processes
	// outlive the agent's own restarts").
	s2 := &Server{}
	stop2, err := RegisterDNSRuntimeOps(s2, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop2)

	res2 := callPromote(t, s2, DNSPromoteParams{DnsdistConf: dnsdistConf})
	if !res2.Promoted {
		t.Fatalf("expected the second generation's promotion to succeed, got %+v", res2)
	}
	secondBindPID := readPIDFile(t, bindPIDFile(cfg))
	secondDnsdistPID := readPIDFile(t, dnsdistPIDFile(cfg))

	if secondBindPID != firstBindPID {
		t.Fatalf("expected the SAME named PID to be adopted and reconfigured (rndc reconfig), not a new process spawned: first=%d second=%d", firstBindPID, secondBindPID)
	}
	if !processAlive(firstBindPID) {
		t.Fatal("expected the original named process to still be the one alive after the second generation's promote")
	}

	// dnsdist has no in-place reconfig wired (see reloadDnsdist's own
	// doc comment) -- it's expected to be replaced, but the OLD one
	// must actually be stopped (adopted-then-killed), never left
	// running alongside a new one.
	if secondDnsdistPID == firstDnsdistPID {
		t.Fatal("expected reloadDnsdist to have replaced the process (no in-place reconfig exists)")
	}
	if processAlive(firstDnsdistPID) {
		t.Fatalf("expected the FIRST generation's dnsdist (pid %d) to have been stopped when the second generation replaced it -- found it still alive, a real duplicate process", firstDnsdistPID)
	}
	if !processAlive(secondDnsdistPID) {
		t.Fatal("expected the second generation's dnsdist to be alive")
	}
}

func readPIDFile(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading PID file %s: %v", path, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parsing PID file %s: %v", path, err)
	}
	return pid
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// --- a tiny, real, controlled fake upstream DNS server (UDP, plain
// A-record answers for any question), used only to prove routing
// without any internet-egress dependency in this test suite. ---

func startFakeUpstream(t *testing.T, answerIP string) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ip4 := net.ParseIP(answerIP).To4()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			resp := buildDNSAnswer(buf[:n], ip4)
			if resp != nil {
				conn.WriteToUDP(resp, addr)
			}
		}
	}()
	return conn.LocalAddr().String()
}

// buildDNSAnswer hand-builds a minimal, correct DNS response for a
// single-question A query: same ID, QR/RA set, the original question
// echoed back, and one answer RR (a compression pointer to the
// question name + fixed A record) -- just enough real wire format for
// a real dnsdist/dig client to accept it as a genuine answer.
func buildDNSAnswer(query []byte, ip4 net.IP) []byte {
	if len(query) < 12 || ip4 == nil {
		return nil
	}
	id := query[0:2]
	// Find the end of the question section (name + qtype(2) + qclass(2)).
	i := 12
	for i < len(query) {
		l := int(query[i])
		if l == 0 {
			i++
			break
		}
		i += l + 1
	}
	i += 4 // qtype + qclass
	if i > len(query) {
		return nil
	}
	question := query[12:i]

	var resp []byte
	resp = append(resp, id...)
	resp = append(resp, 0x81, 0x80) // QR=1, RD=1(echoed as 1 for simplicity), RA=1
	resp = append(resp, 0x00, 0x01) // QDCOUNT=1
	resp = append(resp, 0x00, 0x01) // ANCOUNT=1
	resp = append(resp, 0x00, 0x00) // NSCOUNT=0
	resp = append(resp, 0x00, 0x00) // ARCOUNT=0
	resp = append(resp, question...)
	resp = append(resp, 0xC0, 0x0C) // name = pointer to offset 12 (the question name)
	resp = append(resp, 0x00, 0x01) // TYPE=A
	resp = append(resp, 0x00, 0x01) // CLASS=IN
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 60)
	resp = append(resp, ttl...)
	resp = append(resp, 0x00, 0x04) // RDLENGTH=4
	resp = append(resp, ip4...)
	return resp
}

// TestDNSRuntimeConfigDefaultHealthCheckTimeoutIsGenerous is a real
// regression test for a live defect found during a durability pass: a
// realistic, blocklist-heavy compiled dnsdist config (~855k domains, a
// single large inline Lua table) measured 5.8s just to parse and start
// listening -- the original 5s default health-check timeout falsely
// reported every promote as rolled-back the moment real blocklist data
// started flowing (right after Blocklists' own CA-certificate fix).
// This asserts the default is comfortably above that measured figure,
// not the exact value, so a reasonable future tuning doesn't break this
// test for no reason -- the point is "generous enough for a real
// production-scale blocklist," not a specific number.
func TestDNSRuntimeConfigDefaultHealthCheckTimeoutIsGenerous(t *testing.T) {
	var cfg DNSRuntimeConfig
	cfg.applyDefaults()
	const measuredRealWorldLoadTime = 6 * time.Second // the actual measured 5.8s, rounded up
	if cfg.HealthCheckTimeout <= measuredRealWorldLoadTime {
		t.Fatalf("default HealthCheckTimeout %v is not comfortably above the measured real-world load time of a large blocklist-heavy config (%v) -- this would falsely roll back a genuinely successful promote", cfg.HealthCheckTimeout, measuredRealWorldLoadTime)
	}
}
