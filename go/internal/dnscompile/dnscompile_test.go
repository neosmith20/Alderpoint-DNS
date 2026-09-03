package dnscompile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/dnscryptprovision"
)

// testBindDir returns a real, writable directory this host's AppArmor
// profile for named actually permits (/var/lib/bind/**) -- /tmp is
// confined and rejected (a real bug found and fixed earlier this
// session, see internal/hostagentd/ops_cache_test.go's own comment).
// named.conf's own "directory" clause must point somewhere real for
// named-checkconf to accept it (it chdir()s there while parsing).
func testBindDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join("/var/lib/bind", fmt.Sprintf("dnscompile-test-%d", os.Getpid()), t.Name())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Skipf("cannot create test dir under /var/lib/bind (no permission in this environment?): %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// checkDnsdist runs the real installed dnsdist binary's own
// --check-config against generated text -- the same proof-against-the-
// real-target-runtime standard every compiler in this session has used,
// not just "it looks right". Skips (not fails) if dnsdist isn't
// installed on the machine running the test.
func checkDnsdist(t *testing.T, config string) {
	t.Helper()
	bin, err := exec.LookPath("dnsdist")
	if err != nil {
		t.Skip("dnsdist not installed, skipping real --check-config validation")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsdist.conf")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-C", path, "--check-config").CombinedOutput()
	if err != nil {
		t.Fatalf("dnsdist --check-config rejected generated config: %v\n%s\n--- config ---\n%s", err, out, config)
	}
}

func checkNamedConf(t *testing.T, config string) {
	t.Helper()
	bin, err := exec.LookPath("named-checkconf")
	if err != nil {
		t.Skip("named-checkconf not installed, skipping real validation")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "named.conf")
	if err := os.WriteFile(path, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, path).CombinedOutput()
	if err != nil {
		t.Fatalf("named-checkconf rejected generated config: %v\n%s\n--- config ---\n%s", err, out, config)
	}
}

func minimalInput() Input {
	return Input{
		ListenAddress:      "127.0.0.1:15353",
		BindBackendAddress: "127.0.0.1:15553",
		CacheMaxEntries:    1000,
	}
}

func TestCompileDnsdistIsDeterministic(t *testing.T) {
	in := minimalInput()
	in.LocalDNSRecords = []LocalDNSRecord{
		{Name: "b.lan", RecordType: "A", Value: "10.0.0.2", TTL: 300},
		{Name: "a.lan", RecordType: "A", Value: "10.0.0.1", TTL: 300},
	}
	in.BlockedDomains = []string{"z.example.com", "a.example.com"}
	out1, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	// Reverse slice order -- must not change the output.
	in.LocalDNSRecords[0], in.LocalDNSRecords[1] = in.LocalDNSRecords[1], in.LocalDNSRecords[0]
	in.BlockedDomains[0], in.BlockedDomains[1] = in.BlockedDomains[1], in.BlockedDomains[0]
	out2, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != out2 {
		t.Fatalf("compile is not deterministic under input reordering:\n--- out1 ---\n%s\n--- out2 ---\n%s", out1, out2)
	}
	checkDnsdist(t, out1)
}

func TestCompileDnsdistDnstapLogging(t *testing.T) {
	in := minimalInput()
	in.BlockedDomains = []string{"ads.example.com"}
	in.RegexBlock = []string{"^track\\."}
	in.ClientIdentities = []ClientIdentity{{ClientKey: "laptop", Hex: strings.Repeat("a", 48)}}
	in.ClientOverrides = []ClientOverride{{ClientKey: "laptop", Kind: "block", Domain: "denied.example.com"}}
	in.DnstapSocketPath = filepath.Join(t.TempDir(), "dnstap.sock")
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `newFrameStreamUnixLogger("`+in.DnstapSocketPath+`"`) {
		t.Fatalf("expected a dnstap unix logger for %q, got:\n%s", in.DnstapSocketPath, out)
	}
	if !strings.Contains(out, "addResponseAction(AllRule(), DnstapLogResponseAction(") {
		t.Fatalf("expected addResponseAction with DnstapLogResponseAction (real backend responses), got:\n%s", out)
	}
	if !strings.Contains(out, "addSelfAnsweredResponseAction(AllRule(), DnstapLogResponseAction(") {
		t.Fatalf("expected addSelfAnsweredResponseAction with DnstapLogResponseAction -- required for blocked/local-DNS queries, which dnsdist answers itself without ever hitting addResponseAction; got:\n%s", out)
	}
	if !strings.Contains(out, `SetTagAction("apdns_outcome", "allowed")`) {
		t.Fatalf("expected a default apdns_outcome=allowed tag rule, got:\n%s", out)
	}
	// Every real blocking site (global blocklist, regex block, and the
	// per-client explicit deny) must tag "blocked" ahead of its actual
	// blocking action, not just one of them.
	for _, want := range []string{
		`SuffixMatchNodeRule({"ads.example.com."}), SetTagAction("apdns_outcome", "blocked")`,
		`RegexRule("^track\\."), SetTagAction("apdns_outcome", "blocked")`,
		`SetTagAction("apdns_outcome", "blocked"))
addAction(AndRule({TagRule("apdns_client", "laptop"), SuffixMatchNodeRule({"denied.example.com."})}), RCodeAction`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected to find %q in:\n%s", want, out)
		}
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistNoDnstapSocketMeansNoLogging(t *testing.T) {
	out, err := CompileDnsdist(minimalInput())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Dnstap") || strings.Contains(out, "FrameStream") {
		t.Fatalf("expected no dnstap logging when DnstapSocketPath is unset, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistRejectsEmptyListenAddress(t *testing.T) {
	_, err := CompileDnsdist(Input{})
	if err == nil {
		t.Fatal("expected an error for an empty listen address")
	}
}

func TestCompileDnsdistLocalDnsRecordTypes(t *testing.T) {
	in := minimalInput()
	in.LocalDNSRecords = []LocalDNSRecord{
		{Name: "host.lan", RecordType: "A", Value: "10.0.0.5", TTL: 300},
		{Name: "host6.lan", RecordType: "AAAA", Value: "fe80::1", TTL: 300},
		{Name: "alias.lan", RecordType: "CNAME", Value: "host.lan", TTL: 300},
	}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`QNameRule("host.lan.")`, `SpoofAction({"10.0.0.5"})`,
		`QNameRule("host6.lan.")`, `SpoofAction({"fe80::1"})`,
		`QNameRule("alias.lan.")`, `SpoofCNAMEAction("host.lan.")`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected generated config to contain %q, got:\n%s", want, out)
		}
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistLocalDnsRejectsUnsupportedRecordType(t *testing.T) {
	in := minimalInput()
	in.LocalDNSRecords = []LocalDNSRecord{{Name: "x.lan", RecordType: "MX", Value: "y", TTL: 300}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for an unsupported record type")
	}
}

func TestCompileDnsdistPtrRecordsAreSkippedNotErrored(t *testing.T) {
	in := minimalInput()
	in.LocalDNSRecords = []LocalDNSRecord{{Name: "x.lan", RecordType: "PTR", Value: "y.lan", TTL: 300}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "x.lan") {
		t.Fatalf("PTR record should not be compiled at all, got:\n%s", out)
	}
}

func TestCompileDnsdistBlockedDomainsDefaultToNxdomain(t *testing.T) {
	in := minimalInput()
	in.BlockedDomains = []string{"ads.example.com"}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `SuffixMatchNodeRule({"ads.example.com."})`) || !strings.Contains(out, "RCodeAction(DNSRCode.NXDOMAIN)") {
		t.Fatalf("expected an NXDOMAIN block rule for the blocked domain, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistBlockingResponseModes(t *testing.T) {
	cases := []struct {
		mode string
		want string
	}{
		{"refused", "RCodeAction(DNSRCode.REFUSED)"},
		{"null_ip", `SpoofAction({"0.0.0.0", "::"})`},
	}
	for _, c := range cases {
		in := minimalInput()
		in.BlockedDomains = []string{"ads.example.com"}
		in.BlockingResponseMode = c.mode
		out, err := CompileDnsdist(in)
		if err != nil {
			t.Fatalf("mode %q: %v", c.mode, err)
		}
		if !strings.Contains(out, c.want) {
			t.Errorf("mode %q: expected %q in output:\n%s", c.mode, c.want, out)
		}
		checkDnsdist(t, out)
	}
}

func TestCompileDnsdistCustomIpModeRequiresAnAddress(t *testing.T) {
	in := minimalInput()
	in.BlockedDomains = []string{"ads.example.com"}
	in.BlockingResponseMode = "custom_ip"
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error when custom_ip mode has no configured address")
	}
	in.CustomIPv4 = "10.9.9.9"
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `SpoofAction({"10.9.9.9"})`) {
		t.Fatalf("expected the custom IP in the spoof action, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistExplicitAllowDomainOverridesBlock(t *testing.T) {
	// Precedence is applied by the caller before Input is built (set
	// difference) -- proven here by simply never including the allowed
	// domain in BlockedDomains at all.
	in := minimalInput()
	in.BlockedDomains = []string{"safe.example.com"}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "notblocked.example.com") {
		t.Fatalf("domain never in BlockedDomains must never appear as a block rule, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistRegexRules(t *testing.T) {
	in := minimalInput()
	in.RegexBlock = []string{`.*\.ads\.example\.com$`}
	in.RegexAllow = []string{`^good\.ads\.example\.com$`}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	allowIdx := strings.Index(out, "AllowAction()")
	blockIdx := strings.Index(out, `RegexRule(".*\\.ads\\.example\\.com$")`)
	if allowIdx < 0 || blockIdx < 0 {
		t.Fatalf("expected both a regex allow and a regex block rule, got:\n%s", out)
	}
	if allowIdx > blockIdx {
		t.Fatalf("regex allow must be emitted before regex block (allow always wins), got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistRewriteRule(t *testing.T) {
	in := minimalInput()
	in.RewriteRules = []CustomRule{{RuleType: "rewrite", Pattern: "internal.example.com", RewriteTarget: "10.0.0.9"}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `QNameRule("internal.example.com.")`) || !strings.Contains(out, `SpoofCNAMEAction("10.0.0.9.")`) {
		t.Fatalf("expected a rewrite rule, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistRewriteRuleRequiresATarget(t *testing.T) {
	in := minimalInput()
	in.RewriteRules = []CustomRule{{RuleType: "rewrite", Pattern: "x.example.com"}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for a rewrite rule with no target")
	}
}

func TestCompileDnsdistDefaultPoolRoutesThroughBindWhenPlain(t *testing.T) {
	in := minimalInput()
	in.DefaultProfile = &UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []UpstreamEndpoint{{Address: "9.9.9.9:53"}}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `newServer({address="127.0.0.1:15553", pool="", useProxyProtocol=true, name="apdns_bind_backend"})`) {
		t.Fatalf("expected the plain-transport default profile to route through BIND, got:\n%s", out)
	}
	if strings.Contains(out, "9.9.9.9") {
		t.Fatalf("the raw upstream address must not appear directly when routed through BIND, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistDefaultPoolGoesDirectForDot(t *testing.T) {
	in := minimalInput()
	in.DefaultProfile = &UpstreamProfile{Transport: "dot", Strategy: "ordered", Endpoints: []UpstreamEndpoint{{Address: "1.1.1.1:853", TLSHostname: "cloudflare-dns.com"}}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `address="1.1.1.1:853"`) || !strings.Contains(out, `tls="openssl"`) || !strings.Contains(out, `subjectName="cloudflare-dns.com"`) {
		t.Fatalf("expected a direct DoT server line, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistDohRequiresTlsHostname(t *testing.T) {
	in := minimalInput()
	in.DefaultProfile = &UpstreamProfile{Transport: "doh", Strategy: "ordered", Endpoints: []UpstreamEndpoint{{Address: "1.1.1.1:443"}}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for a DoH endpoint with no tls_hostname")
	}
}

func TestCompileDnsdistNoManagedUpstreamFallsBackToBindNativeRecursion(t *testing.T) {
	in := minimalInput()
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "127.0.0.1:15553") {
		t.Fatalf("expected the zero-managed-upstream fallback to still route through BIND, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistNoManagedUpstreamAndNoBindErrors(t *testing.T) {
	in := minimalInput()
	in.BindBackendAddress = ""
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error rather than a silently serverless pool")
	}
}

func TestCompileDnsdistDotAndDohListeners(t *testing.T) {
	in := minimalInput()
	in.Transports = TransportSettings{DotEnabled: true, DotPort: 8853, DohEnabled: true, DohPort: 8443, DohPath: "/dns-query"}
	in.TLSCertPath, in.TLSKeyPath = "/nonexistent/server.crt", "/nonexistent/server.key"
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "addTLSLocal(") || !strings.Contains(out, "addDOHLocal(") {
		t.Fatalf("expected both DoT and DoH listener directives, got:\n%s", out)
	}
	// dnsdist --check-config does not actually open the cert files at
	// parse time in every build, but this is intentionally not asserted
	// either way here -- the point of this test is the directives are
	// emitted at all, matching the enabled settings.
}

func TestCompileDnsdistDotRequiresTlsPaths(t *testing.T) {
	in := minimalInput()
	in.Transports = TransportSettings{DotEnabled: true, DotPort: 8853}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for DoT enabled with no TLS cert/key configured")
	}
}

func TestCompileDnsdistCachePool(t *testing.T) {
	in := minimalInput()
	in.CacheMaxEntries = 5000
	in.CacheMaxTTLSeconds = 3600
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "newPacketCache(5000, {maxTTL=3600})") {
		t.Fatalf("expected the configured cache size/TTL, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

// --- BIND -----------------------------------------------------------

func TestCompileNamedConfDeterministic(t *testing.T) {
	dir := testBindDir(t)
	in := NamedConfInput{
		Forwarders: []string{"9.9.9.9:53", "1.1.1.1:53"},
		PlainPort:  15453, ProxyPort: 15553, StatsPort: 18153,
		Directory: dir, LogPath: dir + "/named.log",
	}
	out1, err := CompileNamedConf(in)
	if err != nil {
		t.Fatal(err)
	}
	// Same input twice -> identical output. Unlike dnsdist's blocked-
	// domain/local-DNS lists (which have no real order dependency and
	// so are sorted), BIND forwarder ORDER is semantically meaningful
	// (first-listed is preferred) -- correctly NOT reordered/sorted by
	// the compiler, so this test (unlike the dnsdist one above) does
	// not also assert invariance under reordering.
	out2, err := CompileNamedConf(in)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != out2 {
		t.Fatalf("BIND compile is not deterministic for the same input")
	}
	checkNamedConf(t, out1)
}

func TestCompileNamedConfCacheTuningDirectives(t *testing.T) {
	dir := testBindDir(t)
	in := NamedConfInput{
		Forwarders: []string{"9.9.9.9:53"},
		PlainPort:  15453, ProxyPort: 15553, StatsPort: 18153,
		Directory: dir, LogPath: dir + "/named.log",
		MaxCacheTTLSeconds: 3600, MaxNegativeTTLSeconds: 300,
		PrefetchEnabled: true, ServeStaleEnabled: true, MaxStaleTTLSeconds: 7200,
	}
	out, err := CompileNamedConf(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"max-cache-ttl 3600;", "max-ncache-ttl 300;", "prefetch 2 9;", "stale-answer-enable yes;", "stale-cache-enable yes;", "max-stale-ttl 7200;"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected generated named.conf to contain %q, got:\n%s", want, out)
		}
	}
	checkNamedConf(t, out) // real named-checkconf syntax validation, not just a substring match
}

func TestCompileNamedConfCacheTuningDefaultsWhenUnset(t *testing.T) {
	dir := testBindDir(t)
	in := NamedConfInput{
		PlainPort: 15453, ProxyPort: 15553, StatsPort: 18153,
		Directory: dir, LogPath: dir + "/named.log",
	}
	out, err := CompileNamedConf(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"max-cache-ttl", "max-ncache-ttl", "stale-answer-enable yes", "max-stale-ttl"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("expected no %q directive when cache tuning is unconfigured (BIND's own real default should apply), got:\n%s", unwanted, out)
		}
	}
	if !strings.Contains(out, "prefetch 0 0;") {
		t.Errorf("expected prefetch to be explicitly disabled by default (PrefetchEnabled defaults false), got:\n%s", out)
	}
	checkNamedConf(t, out)
}

func TestCompileNamedConfEmptyForwardersMeansNativeRecursion(t *testing.T) {
	dir := testBindDir(t)
	in := NamedConfInput{PlainPort: 15453, ProxyPort: 15553, StatsPort: 18153, Directory: dir, LogPath: dir + "/named.log"}
	out, err := CompileNamedConf(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "forward only") || strings.Contains(out, "forwarders {") {
		t.Fatalf("expected no forwarders clause at all for native recursion, got:\n%s", out)
	}
	checkNamedConf(t, out)
}

func TestCompileNamedConfPlainPortAndProxyPortMustDiffer(t *testing.T) {
	in := NamedConfInput{PlainPort: 15453, ProxyPort: 15453, StatsPort: 18153, Directory: "/tmp/x", LogPath: "/tmp/x/n.log"}
	if _, err := CompileNamedConf(in); err == nil {
		t.Fatal("expected an error when PlainPort == ProxyPort")
	}
}

func TestCompileNamedConfDotForwarding(t *testing.T) {
	dir := testBindDir(t)
	in := NamedConfInput{
		Forwarders: []string{"1.1.1.1:853"}, TLSHostname: "cloudflare-dns.com",
		PlainPort: 15453, ProxyPort: 15553, StatsPort: 18153,
		Directory: dir, LogPath: dir + "/named.log",
	}
	out, err := CompileNamedConf(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "tls dot_upstream") || !strings.Contains(out, `remote-hostname "cloudflare-dns.com"`) {
		t.Fatalf("expected a DoT forwarder TLS block, got:\n%s", out)
	}
	checkNamedConf(t, out)
}

func TestCompileNamedConfRndcControlsBlock(t *testing.T) {
	dir := testBindDir(t)
	in := NamedConfInput{
		PlainPort: 15453, ProxyPort: 15553, StatsPort: 18153, RNDCPort: 19553, RNDCKey: "c29tZS1zZWNyZXQta2V5LWJhc2U2NA==",
		Directory: dir, LogPath: dir + "/named.log",
	}
	out, err := CompileNamedConf(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "controls {") || !strings.Contains(out, "port 19553") {
		t.Fatalf("expected an rndc controls block, got:\n%s", out)
	}
	checkNamedConf(t, out)
}

func TestCompileNamedConfRndcPortAndKeyMustBeGivenTogether(t *testing.T) {
	in := NamedConfInput{PlainPort: 15453, ProxyPort: 15553, StatsPort: 18153, RNDCPort: 19553, Directory: "/tmp/x", LogPath: "/tmp/x/n.log"}
	if _, err := CompileNamedConf(in); err == nil {
		t.Fatal("expected an error when RNDCPort is set without RNDCKey")
	}
}

func TestCompileDnsdistDomainRoutingSuffixMatch(t *testing.T) {
	in := minimalInput()
	in.DomainRoutes = []DomainRoute{{
		MatchKind: "suffix", Domain: "corp.example.com", ProfileID: "corp-dns",
		Profile: UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []UpstreamEndpoint{{Address: "10.9.9.9:53"}}},
	}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `SuffixMatchNodeRule({"corp.example.com."})`) {
		t.Fatalf("expected a suffix-match routing rule, got:\n%s", out)
	}
	if !strings.Contains(out, `PoolAction("route_corp-dns")`) {
		t.Fatalf("expected a PoolAction targeting the route's own pool, got:\n%s", out)
	}
	if !strings.Contains(out, `newServer({address="10.9.9.9:53", pool="route_corp-dns", name="apdns_route_corp-dns_0"})`) {
		t.Fatalf("expected the route's own upstream server bound to its own pool, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistDomainRoutingExactMatchUsesQNameRule(t *testing.T) {
	in := minimalInput()
	in.DomainRoutes = []DomainRoute{{
		MatchKind: "exact", Domain: "single.example.com", ProfileID: "single-dns",
		Profile: UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []UpstreamEndpoint{{Address: "10.9.9.8:53"}}},
	}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `QNameRule("single.example.com.")`) {
		t.Fatalf("expected an exact QNameRule match (not a suffix rule that would also match subdomains), got:\n%s", out)
	}
	checkDnsdist(t, out)
}

// TestCompileDnsdistDomainRoutingMostSpecificSuffixWinsRegardlessOfOrder
// is the direct precedence proof: a deeper/longer suffix rule must be
// emitted (and therefore win, PoolAction being terminal) before a
// shorter one that also matches the same query, regardless of the
// order the rules were supplied in -- matching Python's own real fix
// for this exact precedence bug in dnsdist_gen.py/dnsdist_policy_runtime.py.
func TestCompileDnsdistDomainRoutingMostSpecificSuffixWinsRegardlessOfOrder(t *testing.T) {
	broad := DomainRoute{MatchKind: "suffix", Domain: "example.com", ProfileID: "broad", Profile: UpstreamProfile{Transport: "plain", Endpoints: []UpstreamEndpoint{{Address: "10.0.0.1:53"}}}}
	narrow := DomainRoute{MatchKind: "suffix", Domain: "deep.corp.example.com", ProfileID: "narrow", Profile: UpstreamProfile{Transport: "plain", Endpoints: []UpstreamEndpoint{{Address: "10.0.0.2:53"}}}}

	inBroadFirst := minimalInput()
	inBroadFirst.DomainRoutes = []DomainRoute{broad, narrow}
	outBroadFirst, err := CompileDnsdist(inBroadFirst)
	if err != nil {
		t.Fatal(err)
	}

	inNarrowFirst := minimalInput()
	inNarrowFirst.DomainRoutes = []DomainRoute{narrow, broad}
	outNarrowFirst, err := CompileDnsdist(inNarrowFirst)
	if err != nil {
		t.Fatal(err)
	}

	if outBroadFirst != outNarrowFirst {
		t.Fatalf("expected input order not to matter, got two different outputs:\n---broad-first---\n%s\n---narrow-first---\n%s", outBroadFirst, outNarrowFirst)
	}
	narrowIdx := strings.Index(outBroadFirst, `PoolAction("route_narrow")`)
	broadIdx := strings.Index(outBroadFirst, `PoolAction("route_broad")`)
	if narrowIdx < 0 || broadIdx < 0 || narrowIdx > broadIdx {
		t.Fatalf("expected the more specific 'deep.corp.example.com' rule before the broader 'example.com' one, got:\n%s", outBroadFirst)
	}
	checkDnsdist(t, outBroadFirst)
}

func TestCompileDnsdistDomainRoutingRejectsInvalidMatchKind(t *testing.T) {
	in := minimalInput()
	in.DomainRoutes = []DomainRoute{{MatchKind: "wildcard", Domain: "example.com", ProfileID: "x", Profile: UpstreamProfile{Transport: "plain", Endpoints: []UpstreamEndpoint{{Address: "10.0.0.1:53"}}}}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for an unsupported match_kind")
	}
}

func TestCompileDnsdistDomainRoutingRejectsConflictingRulesForTheSameDomain(t *testing.T) {
	in := minimalInput()
	in.DomainRoutes = []DomainRoute{
		{MatchKind: "suffix", Domain: "example.com", ProfileID: "profile-a", Profile: UpstreamProfile{Transport: "plain", Endpoints: []UpstreamEndpoint{{Address: "10.0.0.1:53"}}}},
		{MatchKind: "suffix", Domain: "example.com.", ProfileID: "profile-b", Profile: UpstreamProfile{Transport: "plain", Endpoints: []UpstreamEndpoint{{Address: "10.0.0.2:53"}}}},
	}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for two different profiles claiming the same normalized domain+match_kind")
	}
}

// --- Strong ClientID -----------------------------------------------------

// testCert generates a real throwaway self-signed cert/key pair (same
// openssl invocation pattern used elsewhere in this project's own
// tooling), for the one test below that validates a full DoT+DoH+DoQ+
// Strong ClientID config against the real dnsdist --check-config, not
// just "the directives are emitted".
func testCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")
	out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", "/CN=dnscompile-test").CombinedOutput()
	if err != nil {
		t.Skipf("openssl not usable in this environment: %v: %s", err, out)
	}
	return certPath, keyPath
}

func TestCompileDnsdistClientIdentityBindingAndOverridePrecedence(t *testing.T) {
	certPath, keyPath := testCert(t)
	in := minimalInput()
	in.TLSCertPath, in.TLSKeyPath = certPath, keyPath
	in.Transports = TransportSettings{
		DotEnabled: true, DotPort: 8853,
		DohEnabled: true, DohPort: 8443, DohPath: "/dns-query",
		DoqEnabled: true, DoqPort: 8854,
		Doh3Enabled: true, Doh3Port: 8443,
	}
	hexA := strings.Repeat("a", 48)
	hexB := strings.Repeat("b", 64)
	in.ClientIdentities = []ClientIdentity{
		{ClientKey: "client-1", Hex: hexA},
		{ClientKey: "client-2", Hex: hexB},
	}
	in.ClientOverrides = []ClientOverride{
		{ClientKey: "client-1", Kind: "block", Domain: "Blocked.Example.com"},
		{ClientKey: "client-2", Kind: "allow", Domain: "allowed.example.com"},
	}
	in.BlockedDomains = []string{"allowed.example.com"} // globally blocked, but client-2 explicitly allows it

	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, "addDOQLocal(") {
		t.Fatalf("expected a DoQ listener directive, got:\n%s", out)
	}
	if !strings.Contains(out, "addDOH3Local(") {
		t.Fatalf("expected a DoH3 listener directive, got:\n%s", out)
	}

	wantDoHPath := "/dns-query/cid/" + hexA
	if !strings.Contains(out, `HTTPPathRule("`+wantDoHPath+`")`) {
		t.Fatalf("expected an HTTPPathRule for the full canonical hex DoH path %q, got:\n%s", wantDoHPath, out)
	}
	// Full 64-hex identity must appear verbatim somewhere (never
	// truncated/downgraded) -- check both the DoH path and the SNI
	// encoding losslessly carry it.
	if !strings.Contains(out, hexB) {
		t.Fatalf("expected the full 64-hex identity to appear verbatim, got:\n%s", out)
	}
	if !strings.Contains(out, `SNIRule("`) {
		t.Fatalf("expected an SNIRule for DoT/DoQ identity, got:\n%s", out)
	}
	if !strings.Contains(out, `SetTagAction("apdns_client", "client-1")`) || !strings.Contains(out, `SetTagAction("apdns_client", "client-2")`) {
		t.Fatalf("expected each client's own tag to be set, got:\n%s", out)
	}

	// Precedence: client-1's explicit deny line must appear before the
	// global blocklist section; client-2's explicit allow for a
	// globally-blocked domain must also appear before the global
	// blocklist section (so it's evaluated first and wins).
	denyIdx := strings.Index(out, `TagRule("apdns_client", "client-1")`)
	allowIdx := strings.Index(out, `TagRule("apdns_client", "client-2")`)
	globalBlockIdx := strings.Index(out, "SuffixMatchNodeRule({\"allowed.example.com.\"})")
	if denyIdx == -1 || allowIdx == -1 || globalBlockIdx == -1 {
		t.Fatalf("expected to find all three markers, got:\n%s", out)
	}
	if !(denyIdx < globalBlockIdx && allowIdx < globalBlockIdx) {
		t.Fatalf("expected per-client deny/allow rules to be compiled BEFORE the global blocklist (explicit > default), got:\ndenyIdx=%d allowIdx=%d globalBlockIdx=%d\n%s", denyIdx, allowIdx, globalBlockIdx, out)
	}

	checkDnsdist(t, out)
}

func TestCompileDnsdistClientDenyOrderedBeforeAllowForTheSameClient(t *testing.T) {
	in := minimalInput()
	hex := strings.Repeat("c", 48)
	in.ClientIdentities = []ClientIdentity{{ClientKey: "client-1", Hex: hex}}
	in.ClientOverrides = []ClientOverride{
		{ClientKey: "client-1", Kind: "allow", Domain: "same.example.com"},
		{ClientKey: "client-1", Kind: "block", Domain: "same.example.com"},
	}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	denyIdx := strings.Index(out, "RCodeAction(DNSRCode.NXDOMAIN))")
	allowIdx := strings.Index(out, "AllowAction())")
	if denyIdx == -1 || allowIdx == -1 || denyIdx > allowIdx {
		t.Fatalf("expected the deny rule to be compiled before the allow rule for the same client+domain (explicit deny > explicit allow), got:\ndenyIdx=%d allowIdx=%d\n%s", denyIdx, allowIdx, out)
	}
}

func TestCompileDnsdistClientRulesAreIsolatedByTag(t *testing.T) {
	// Two clients, each with their own deny -- neither's rule must ever
	// reference the other's tag value, structurally proving isolation
	// at the compile level (the real cross-client runtime proof lives
	// in internal/hostagentd's end-to-end test).
	in := minimalInput()
	hexA := strings.Repeat("1", 48)
	hexB := strings.Repeat("2", 48)
	in.ClientIdentities = []ClientIdentity{
		{ClientKey: "client-a", Hex: hexA},
		{ClientKey: "client-b", Hex: hexB},
	}
	in.ClientOverrides = []ClientOverride{
		{ClientKey: "client-a", Kind: "block", Domain: "secret-a.example."},
	}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "secret-a.example.") && strings.Contains(line, "TagRule") {
			if !strings.Contains(line, `"client-a"`) || strings.Contains(line, `"client-b"`) {
				t.Fatalf("expected the deny rule for secret-a.example. to reference only client-a's tag, got: %s", line)
			}
		}
	}
}

func TestCompileDnsdistRejectsAnInvalidClientIDValue(t *testing.T) {
	in := minimalInput()
	in.ClientIdentities = []ClientIdentity{{ClientKey: "client-1", Hex: "not-valid-hex"}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for a malformed ClientID value reaching the compiler")
	}
}

func TestCompileDnsdistClientRulesDeterministic(t *testing.T) {
	in := minimalInput()
	hexA := strings.Repeat("1", 48)
	hexB := strings.Repeat("2", 64)
	in.ClientIdentities = []ClientIdentity{
		{ClientKey: "client-b", Hex: hexB},
		{ClientKey: "client-a", Hex: hexA},
	}
	in.ClientOverrides = []ClientOverride{
		{ClientKey: "client-b", Kind: "allow", Domain: "z.example."},
		{ClientKey: "client-a", Kind: "block", Domain: "y.example."},
	}
	out1, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	in.ClientIdentities[0], in.ClientIdentities[1] = in.ClientIdentities[1], in.ClientIdentities[0]
	in.ClientOverrides[0], in.ClientOverrides[1] = in.ClientOverrides[1], in.ClientOverrides[0]
	out2, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != out2 {
		t.Fatalf("expected byte-identical output regardless of input slice order:\n--- out1 ---\n%s\n--- out2 ---\n%s", out1, out2)
	}
}

func TestCompileDnsdistDoqRequiresTlsPaths(t *testing.T) {
	in := minimalInput()
	in.Transports = TransportSettings{DoqEnabled: true, DoqPort: 8853}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for DoQ enabled with no TLS cert/key configured")
	}
}

func TestCompileDnsdistDnscryptRequiresProvisionedPaths(t *testing.T) {
	in := minimalInput()
	in.Transports = TransportSettings{DNSCryptEnabled: true, DNSCryptPort: 5443, DNSCryptProviderName: "2.dnscrypt-cert.test"}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for DNSCrypt enabled with no provider identity provisioned")
	}
}

// TestCompileDnsdistDnscryptWithRealGeneratedMaterialValidatesAgainstRealDnsdist
// proves DNSCrypt compiles a real addDNSCryptBind directive that the
// real installed dnsdist accepts, using real generated key material
// (internal/dnscryptprovision) -- not just a syntax check with fake
// file paths.
func TestCompileDnsdistDnscryptWithRealGeneratedMaterialValidatesAgainstRealDnsdist(t *testing.T) {
	bin, err := exec.LookPath("dnsdist")
	if err != nil {
		t.Skip("dnsdist not installed, skipping real DNSCrypt validation")
	}
	_, providerPriv, err := dnscryptprovision.GenerateProviderKeypair(bin)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	cert, key, err := dnscryptprovision.GenerateResolverCertificate(bin, providerPriv, 1, now, now+86400)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "resolver.cert")
	keyPath := filepath.Join(dir, "resolver.key")
	if err := os.WriteFile(certPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}

	in := minimalInput()
	in.Transports = TransportSettings{
		DNSCryptEnabled: true, DNSCryptPort: 5443, DNSCryptProviderName: "2.dnscrypt-cert.test",
		DNSCryptCertPath: certPath, DNSCryptKeyPath: keyPath,
	}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "addDNSCryptBind(") {
		t.Fatalf("expected a DNSCrypt bind directive, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistDoh3RequiresTlsPaths(t *testing.T) {
	in := minimalInput()
	in.Transports = TransportSettings{Doh3Enabled: true, Doh3Port: 8443}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for DoH3 enabled with no TLS cert/key configured")
	}
}

// TestCompileDnsdistDoh3AloneValidatesAgainstRealDnsdist proves DoH3 can
// be enabled independent of DoT/DoH/DoQ and still produces a config the
// real installed dnsdist accepts -- addDOH3Local's real option table was
// confirmed live to accept no path/urls key at all (every such key is
// silently ignored with an "Unknown key" warning), so this only ever
// emits reusePort, unlike addDOHLocal's path-table.
func TestCompileDnsdistDoh3AloneValidatesAgainstRealDnsdist(t *testing.T) {
	certPath, keyPath := testCert(t)
	in := minimalInput()
	in.TLSCertPath, in.TLSKeyPath = certPath, keyPath
	in.Transports = TransportSettings{Doh3Enabled: true, Doh3Port: 8443}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "addDOH3Local(") {
		t.Fatalf("expected a DoH3 listener directive, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

// TestCompileDnsdistNetworkOverrideScopesResponseModeToCIDR proves the
// per-network response-mode override is genuinely scoped to its own
// CIDR (via NetmaskGroupRule) and is emitted before the global (unscoped)
// copy of the same blocked-domain rule -- the ordering that makes "more
// specific network wins" actually true for dnsdist's own first-match-
// terminal-action evaluation.
func TestCompileDnsdistNetworkOverrideScopesResponseModeToCIDR(t *testing.T) {
	in := minimalInput()
	in.BlockedDomains = []string{"ads.example.com"}
	in.BlockingResponseMode = "nxdomain"
	in.NetworkOverrides = []NetworkOverride{
		{CIDR: "192.168.50.0/24", BlockingResponseMode: "refused"},
	}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `NetmaskGroupRule({"192.168.50.0/24"})`) {
		t.Fatalf("expected a NetmaskGroupRule scoping the override to its own CIDR, got:\n%s", out)
	}
	scopedIdx := strings.Index(out, `AndRule({NetmaskGroupRule({"192.168.50.0/24"}), SuffixMatchNodeRule({"ads.example.com."})}), RCodeAction(DNSRCode.REFUSED)`)
	globalIdx := strings.Index(out, `addAction(SuffixMatchNodeRule({"ads.example.com."}), RCodeAction(DNSRCode.NXDOMAIN))`)
	if scopedIdx < 0 {
		t.Fatalf("expected the network-scoped REFUSED rule, got:\n%s", out)
	}
	if globalIdx < 0 {
		t.Fatalf("expected the global NXDOMAIN rule to still be present unscoped, got:\n%s", out)
	}
	if scopedIdx > globalIdx {
		t.Fatalf("expected the network-scoped rule BEFORE the global rule (dnsdist evaluates in order, first terminal match wins), got:\n%s", out)
	}
	checkDnsdist(t, out)
}

// TestCompileDnsdistNetworkOverrideMostSpecificFirstRegardlessOfOrder is
// the same precedence proof TestCompileDnsdistDomainRoutingMostSpecific...
// already established for domain routing, applied here: a longer-prefix
// (more specific) network's override must be emitted first regardless of
// input order.
func TestCompileDnsdistNetworkOverrideMostSpecificFirstRegardlessOfOrder(t *testing.T) {
	broad := NetworkOverride{CIDR: "10.0.0.0/8", BlockingResponseMode: "refused"}
	narrow := NetworkOverride{CIDR: "10.1.2.0/24", BlockingResponseMode: "null_ip"}

	in := minimalInput()
	in.BlockedDomains = []string{"ads.example.com"}
	in.NetworkOverrides = []NetworkOverride{broad, narrow}
	out1, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	in.NetworkOverrides = []NetworkOverride{narrow, broad}
	out2, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != out2 {
		t.Fatalf("expected byte-identical output regardless of NetworkOverrides input order:\n--- out1 ---\n%s\n--- out2 ---\n%s", out1, out2)
	}
	narrowIdx := strings.Index(out1, `10.1.2.0/24`)
	broadIdx := strings.Index(out1, `10.0.0.0/8`)
	if narrowIdx < 0 || broadIdx < 0 || narrowIdx > broadIdx {
		t.Fatalf("expected the more specific /24 network emitted before the broader /8, got:\n%s", out1)
	}
	checkDnsdist(t, out1)
}

func TestCompileDnsdistNetworkOverrideRejectsInvalidCIDR(t *testing.T) {
	in := minimalInput()
	in.NetworkOverrides = []NetworkOverride{{CIDR: "not-a-cidr", BlockingResponseMode: "refused"}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for an invalid network override CIDR")
	}
}

func TestCompileDnsdistNetworkOverrideAppliesToRegexBlockToo(t *testing.T) {
	in := minimalInput()
	in.RegexBlock = []string{"^ad[0-9]+\\.example\\.com$"}
	in.NetworkOverrides = []NetworkOverride{{CIDR: "192.168.60.0/24", BlockingResponseMode: "custom_ip", CustomIPv4: "10.10.10.10"}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `AndRule({NetmaskGroupRule({"192.168.60.0/24"}), RegexRule("^ad[0-9]+\\.example\\.com$")}), SpoofAction({"10.10.10.10"})`) {
		t.Fatalf("expected the network-scoped custom_ip response for the regex-block rule, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistWebserverAPIDisabledByDefault(t *testing.T) {
	in := minimalInput()
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "webserver(") {
		t.Fatalf("expected no webserver block when DnsdistAPIKey is unset, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistWebserverAPIEnabled(t *testing.T) {
	in := minimalInput()
	in.DnsdistAPIKey = "test-api-key-value"
	in.DnsdistAPIPassword = "test-password-value"
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `webserver("127.0.0.1:8083")`) {
		t.Fatalf("expected the default port 8083 webserver, got:\n%s", out)
	}
	if !strings.Contains(out, `acl="127.0.0.1/32,::1/128"`) {
		t.Fatalf("expected a loopback-only ACL, got:\n%s", out)
	}
	if !strings.Contains(out, `apiKey="test-api-key-value"`) {
		t.Fatalf("expected the API key to be compiled in, got:\n%s", out)
	}
	if !strings.Contains(out, "setAPIWritable(false)") {
		t.Fatalf("expected the API to be read-only, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistWebserverAPICustomPort(t *testing.T) {
	in := minimalInput()
	in.DnsdistAPIKey = "test-api-key-value"
	in.DnsdistAPIPort = 18083
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `webserver("127.0.0.1:18083")`) {
		t.Fatalf("expected the custom port to be used, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestCompileDnsdistDefaultPoolServerNamedForTelemetry(t *testing.T) {
	in := minimalInput()
	in.DefaultProfile = &UpstreamProfile{Transport: "plain", Strategy: "ordered", Endpoints: []UpstreamEndpoint{{Address: "9.9.9.9:53"}}}
	in.BindBackendAddress = "" // route direct, not through BIND, so the profile's own endpoint is named
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `newServer({address="9.9.9.9:53", pool="", name="apdns_default_0"})`) {
		t.Fatalf("expected a deterministic apdns_-prefixed server name for telemetry attribution, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestEvaluateDomainNoMatch(t *testing.T) {
	res := EvaluateDomain("safe.example.com", nil, nil, nil)
	if res.Blocked || res.Reason != "no_match" {
		t.Fatalf("got %+v, want an unblocked no_match result", res)
	}
}

func TestEvaluateDomainBlocklistSuffixMatch(t *testing.T) {
	res := EvaluateDomain("ads.example.com", []string{"example.com"}, nil, nil)
	if !res.Blocked || res.Reason != "blocklist" || res.Matched != "example.com" {
		t.Fatalf("got %+v, want blocked by the real suffix entry", res)
	}
}

func TestEvaluateDomainSuffixDoesNotFalsePositiveOnSimilarString(t *testing.T) {
	// "evilexample.com" ends with "example.com" as a raw string but is
	// NOT a subdomain of it -- must not match, same as dnsdist's real
	// SuffixMatchNodeRule.
	res := EvaluateDomain("evilexample.com", []string{"example.com"}, nil, nil)
	if res.Blocked {
		t.Fatalf("got %+v, want unblocked (not a real subdomain)", res)
	}
}

func TestEvaluateDomainRegexBlock(t *testing.T) {
	res := EvaluateDomain("ad1.example.com", nil, nil, []string{"^ad[0-9]+\\.example\\.com$"})
	if !res.Blocked || res.Reason != "regex_block" {
		t.Fatalf("got %+v, want blocked by the regex", res)
	}
}

func TestEvaluateDomainRegexAllowWinsOverBlocklist(t *testing.T) {
	res := EvaluateDomain("safe.example.com", []string{"example.com"}, []string{"^safe\\."}, nil)
	if res.Blocked || res.Reason != "regex_allow" {
		t.Fatalf("got %+v, want the regex-allow to win over the blocklist suffix match", res)
	}
}

func TestEvaluateDomainMostSpecificBlocklistEntryReported(t *testing.T) {
	res := EvaluateDomain("deep.corp.example.com", []string{"example.com", "corp.example.com"}, nil, nil)
	if !res.Blocked || res.Matched != "corp.example.com" {
		t.Fatalf("got %+v, want the more specific entry reported as the match", res)
	}
}
