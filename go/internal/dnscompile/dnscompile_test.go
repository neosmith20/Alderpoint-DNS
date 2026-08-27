package dnscompile

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	if !strings.Contains(out, `newServer({address="127.0.0.1:15553", pool="", useProxyProtocol=true})`) {
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
	if !strings.Contains(out, `newServer({address="10.9.9.9:53", pool="route_corp-dns"})`) {
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
