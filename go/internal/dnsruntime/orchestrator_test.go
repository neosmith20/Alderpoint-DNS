package dnsruntime

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/clientid"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/customrules"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/dnstransports"
	"alderpointdns/go-controlplane/internal/domainrouting"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/upstreams"
)

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	// busy_timeout: blocklists.Service.Create spawns a real background
	// goroutine (a real pull attempt against the test's unreachable URL)
	// that writes to this same file concurrently with this test's own
	// subsequent inserts -- without a busy timeout, SQLite's default is
	// to fail immediately with SQLITE_BUSY on any write contention
	// rather than wait, a real race this combined-multi-service test
	// hits that no single service's own isolated test DB would.
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestApplyWithNoHostAgentIsAnHonestNotAttempted(t *testing.T) {
	o := &Orchestrator{}
	res := o.Apply(context.Background())
	if res.Attempted || res.Error == "" {
		t.Fatalf("expected an honest 'not attempted' result, got %+v", res)
	}
}

func TestBuildGathersEveryConfiguredSource(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	localDNS := &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}
	if _, err := localDNS.Create(ctx, localdns.CreateInput{Name: "printer.lan", RecordType: "A", Value: "10.0.0.50", TTL: 300, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	customRules := &customrules.Service{DB: db}
	if _, err := customRules.Create(ctx, "block", "ads.example.com", nil); err != nil {
		t.Fatal(err)
	}
	target := "10.0.0.9"
	if _, err := customRules.Create(ctx, "rewrite", "internal.example.com", &target); err != nil {
		t.Fatal(err)
	}
	if _, err := customRules.Create(ctx, "regex_block", `.*\.tracker\.example$`, nil); err != nil {
		t.Fatal(err)
	}

	bl := &blocklists.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}
	if _, _, err := bl.Create(ctx, "sub1", "Test List", "https://example.invalid/list.txt", "test"); err != nil {
		t.Fatal(err)
	}
	// Simulate a real pulled/promoted subscription runtime file --
	// exactly the shape blocklists.download() itself writes (see its
	// own doc comment).
	if err := os.WriteFile(filepath.Join(bl.RuntimeDir, "sub1.rpz"), []byte("malware.example.com CNAME .\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	up := &upstreams.Service{DB: db}
	if err := up.Create(ctx, "primary", "Primary", "plain", "ordered", []upstreams.Endpoint{{Address: "9.9.9.9:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}

	transports := &dnstransports.Service{DB: db}
	if _, err := transports.Update(ctx, dnstransports.Settings{DotEnabled: true, DotPort: 8853, DohPort: 443, DohPath: "/dns-query", DoqPort: 853, Doh3Port: 443, DNSCryptPort: 5443, DNSCryptProviderName: "2.dnscrypt-cert.test"}); err != nil {
		t.Fatal(err)
	}

	pol := &policy.Service{DB: db}
	refused := "refused"
	if err := pol.Save(ctx, "global", "global", policy.Layer{BlockingResponseMode: &refused}); err != nil {
		t.Fatal(err)
	}

	o := &Orchestrator{
		LocalDNS: localDNS, CustomRules: customRules, Blocklists: bl, Upstreams: up, DNSTransports: transports, Policy: pol,
		DnsdistListenAddress: "127.0.0.1:15353", BindBackendAddress: "127.0.0.1:15553",
	}
	in, bindForwarders, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(in.LocalDNSRecords) != 1 || in.LocalDNSRecords[0].Name != "printer.lan" {
		t.Errorf("expected the local DNS record to be gathered, got %+v", in.LocalDNSRecords)
	}
	foundBlockRule := false
	for _, d := range in.BlockedDomains {
		if d == "ads.example.com" {
			foundBlockRule = true
		}
	}
	if !foundBlockRule {
		t.Errorf("expected the block-type custom rule's domain in BlockedDomains, got %v", in.BlockedDomains)
	}
	foundBlocklistDomain := false
	for _, d := range in.BlockedDomains {
		if d == "malware.example.com" {
			foundBlocklistDomain = true
		}
	}
	if !foundBlocklistDomain {
		t.Errorf("expected the enabled blocklist subscription's compiled domain in BlockedDomains, got %v", in.BlockedDomains)
	}
	if len(in.RewriteRules) != 1 || in.RewriteRules[0].RewriteTarget != "10.0.0.9" {
		t.Errorf("expected the rewrite rule to be gathered, got %+v", in.RewriteRules)
	}
	if len(in.RegexBlock) != 1 {
		t.Errorf("expected the regex_block rule to be gathered, got %v", in.RegexBlock)
	}
	if in.DefaultProfile == nil || in.DefaultProfile.Transport != "plain" {
		t.Errorf("expected the enabled upstream profile to be gathered, got %+v", in.DefaultProfile)
	}
	if len(bindForwarders) != 1 || bindForwarders[0] != "9.9.9.9:53" {
		t.Errorf("expected the plain-transport profile's endpoint as a BIND forwarder, got %v", bindForwarders)
	}
	if !in.Transports.DotEnabled || in.Transports.DotPort != 8853 {
		t.Errorf("expected DNS transport settings to be gathered, got %+v", in.Transports)
	}
	if in.BlockingResponseMode != "refused" {
		t.Errorf("expected the global policy layer's blocking_response_mode to be gathered, got %q", in.BlockingResponseMode)
	}
}

// TestBuildGathersDomainRoutingRules proves the orchestrator resolves a
// stored domain_routing_rules row into a full dnscompile.DomainRoute
// (real endpoints/transport/strategy, not just an unresolved profile
// ID), and skips a rule whose referenced profile no longer exists
// rather than failing the whole compile over it.
func TestBuildGathersDomainRoutingRules(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	up := &upstreams.Service{DB: db}
	if err := up.Create(ctx, "corp-dns", "Corp DNS", "plain", "ordered", []upstreams.Endpoint{{Address: "10.9.9.9:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	dr := &domainrouting.Service{DB: db}
	if _, err := dr.Create(ctx, "suffix", "corp.example.com", "corp-dns"); err != nil {
		t.Fatal(err)
	}
	if _, err := dr.Create(ctx, "suffix", "stale.example.com", "never-created"); err == nil {
		t.Fatal("expected Create itself to reject an unknown upstream_profile_id -- this test relies on that to seed the 'stale reference' case below via direct SQL instead")
	}
	// Seed a rule referencing a profile that existed at creation time but
	// was deleted afterward (Create's own existence check can't produce
	// this state -- a real delete after the fact can).
	if err := up.Create(ctx, "temp-dns", "Temp DNS", "plain", "ordered", []upstreams.Endpoint{{Address: "10.9.9.8:53", Weight: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := dr.Create(ctx, "exact", "gone.example.com", "temp-dns"); err != nil {
		t.Fatal(err)
	}
	if err := up.Delete(ctx, "temp-dns"); err != nil {
		t.Fatal(err)
	}

	o := &Orchestrator{Upstreams: up, DomainRouting: dr, DnsdistListenAddress: "127.0.0.1:15353"}
	in, _, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.DomainRoutes) != 1 {
		t.Fatalf("expected exactly 1 resolvable domain route (the stale-profile one skipped), got %+v", in.DomainRoutes)
	}
	got := in.DomainRoutes[0]
	if got.Domain != "corp.example.com" || got.MatchKind != "suffix" || got.ProfileID != "corp-dns" {
		t.Fatalf("unexpected resolved route: %+v", got)
	}
	if len(got.Profile.Endpoints) != 1 || got.Profile.Endpoints[0].Address != "10.9.9.9:53" {
		t.Fatalf("expected the route's profile to carry its real endpoint, got %+v", got.Profile)
	}
}

func TestBuildExplicitAllowOverridesBlock(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	customRules := &customrules.Service{DB: db}
	if _, err := customRules.Create(ctx, "block", "shared.example.com", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := customRules.Create(ctx, "allow", "shared.example.com", nil); err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{CustomRules: customRules}
	in, _, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range in.BlockedDomains {
		if d == "shared.example.com" {
			t.Fatalf("an explicitly allowed domain must never appear in BlockedDomains, got %v", in.BlockedDomains)
		}
	}
}

// TestApplyEndToEndAgainstARealHostAgent proves the full real chain: a
// row in a real SQLite DB (a Local DNS record) -> this orchestrator's
// own compile -> a real socket call to a real hostagentd test instance
// -> a real dnsdist process -> a real dig answer. Skips if the DNS
// binaries aren't available (matching internal/hostagentd's own tests).
func TestApplyEndToEndAgainstARealHostAgent(t *testing.T) {
	for _, bin := range []string{"named", "rndc", "dnsdist", "dig"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available in this environment", bin)
		}
	}
	db := newTestDB(t)
	ctx := context.Background()
	localDNS := &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}
	if _, err := localDNS.Create(ctx, localdns.CreateInput{Name: "e2e.lan", RecordType: "A", Value: "10.5.5.5", TTL: 300, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	bindDir := filepath.Join("/var/lib/bind", fmt.Sprintf("dnsruntime-e2e-%d", os.Getpid()), t.Name())
	if err := os.MkdirAll(bindDir, 0o755); err != nil {
		t.Skipf("cannot create test dir under /var/lib/bind: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(bindDir) })

	dnsdistPort := freePort(t)
	cfg := hostagentd.DNSRuntimeConfig{
		StagingDir: t.TempDir(), BindLivePath: filepath.Join(bindDir, "named.conf"), BindDirectory: bindDir, BindLogPath: filepath.Join(bindDir, "named.log"),
		DnsdistLivePath: filepath.Join(t.TempDir(), "dnsdist.conf"),
		BindPlainPort:   freePort(t), BindProxyPort: freePort(t), BindStatsPort: freePort(t), BindRNDCPort: freePort(t),
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
	// Otherwise the real named/dnsdist this test's Apply() brings up
	// outlive it, orphaned under init.
	t.Cleanup(stop)
	agentCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go agent.Serve(agentCtx)
	waitForSocket(t, sockPath)

	o := &Orchestrator{
		LocalDNS: localDNS, HostAgent: hostagent.NewClient(sockPath),
		DnsdistListenAddress: cfg.DnsdistListenAddress, BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
	}
	res := o.Apply(context.Background())
	if !res.Attempted || !res.Promoted || res.RolledBack {
		t.Fatalf("expected a real, clean end-to-end promotion, got %+v", res)
	}

	host, port := cfg.DnsdistListenAddress[:strings.LastIndex(cfg.DnsdistListenAddress, ":")], cfg.DnsdistListenAddress[strings.LastIndex(cfg.DnsdistListenAddress, ":")+1:]
	out, err := exec.Command("dig", "+time=2", "+tries=2", "+short", "@"+host, "-p", port, "e2e.lan", "A").Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(out))
	if got != "10.5.5.5" {
		t.Fatalf("expected the real end-to-end answer 10.5.5.5 for a record created only in this test's SQLite DB, got %q", got)
	}
}

// TestBuildGathersActiveClientIdentitiesExcludingDisabledClientsAndRevokedIdentities
// proves the orchestrator's Strong ClientID gathering matches its own
// disclosed contract: every active identity of every enabled client is
// compiled, a revoked identity never is, and a disabled client's
// identities never are either (even though the row itself still
// exists) -- and a client with two identities contributes its
// overrides exactly once, not once per identity.
func TestBuildGathersActiveClientIdentitiesExcludingDisabledClientsAndRevokedIdentities(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	cl := &clients.Service{DB: db}

	enabledID, err := cl.CreateClient(ctx, "Phone", "")
	if err != nil {
		t.Fatal(err)
	}
	first, err := cl.GenerateClientID(ctx, enabledID, clientid.Bits192, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.GenerateClientID(ctx, enabledID, clientid.Bits256, "backup"); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.AddDomainOverride(ctx, enabledID, "block", "blocked.example."); err != nil {
		t.Fatal(err)
	}
	revoked, err := cl.GenerateClientID(ctx, enabledID, clientid.Bits192, "old")
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.RevokeIdentifier(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}

	disabledID, err := cl.CreateClient(ctx, "Guest Tablet", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.GenerateClientID(ctx, disabledID, clientid.Bits192, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE clients SET enabled=0 WHERE id=?`, disabledID); err != nil {
		t.Fatal(err)
	}

	o := &Orchestrator{Clients: cl, DnsdistListenAddress: "127.0.0.1:15353", BindBackendAddress: "127.0.0.1:15553"}
	in, _, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(in.ClientIdentities) != 2 {
		t.Fatalf("expected exactly the 2 active identities of the enabled client (not the revoked one, not the disabled client's), got %+v", in.ClientIdentities)
	}
	seenValues := map[string]bool{}
	for _, id := range in.ClientIdentities {
		seenValues[id.Hex] = true
		if id.ClientKey != fmt.Sprintf("client-%d", enabledID) {
			t.Fatalf("expected every identity to be keyed to the enabled client, got %+v", id)
		}
	}
	if seenValues[revoked.Value] {
		t.Fatal("a revoked identity must never be compiled")
	}
	if !seenValues[first.Value] {
		t.Fatal("expected the first (still-active) identity to be compiled")
	}

	if len(in.ClientOverrides) != 1 {
		t.Fatalf("expected exactly 1 override (added once, not once per identity), got %+v", in.ClientOverrides)
	}
	if in.ClientOverrides[0].Domain != "blocked.example." || in.ClientOverrides[0].Kind != "block" {
		t.Fatalf("unexpected override contents: %+v", in.ClientOverrides[0])
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("agent socket never appeared")
}
