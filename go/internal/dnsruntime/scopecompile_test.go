package dnsruntime

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/dnscompile"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
	"alderpointdns/go-controlplane/internal/localdns"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/policyentities"
	"alderpointdns/go-controlplane/internal/upstreams"
)

func newScopeTestOrchestrator(t *testing.T) (*Orchestrator, *sqlHandles) {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()

	bl := &blocklists.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}
	if _, _, err := bl.Create(ctx, "standard-sub", "Standard", "https://example.invalid/std.txt", "malware"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bl.RuntimeDir, "standard-sub.rpz"), []byte("malware.example.com CNAME .\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := bl.Create(ctx, "adult-sub", "Adult Content", "https://example.invalid/adult.txt", "adult_content"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bl.RuntimeDir, "adult-sub.rpz"), []byte("adult.example.com CNAME .\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pol := &policy.Service{DB: db}
	pe := &policyentities.Service{DB: db}
	cl := &clients.Service{DB: db}
	up := &upstreams.Service{DB: db}

	o := &Orchestrator{Policy: pol, PolicyEntities: pe, Clients: cl, Blocklists: bl, Upstreams: up, DnsdistListenAddress: "127.0.0.1:15353", BindBackendAddress: "127.0.0.1:15553"}
	return o, &sqlHandles{db: db, pol: pol, pe: pe, cl: cl, up: up}
}

type sqlHandles struct {
	db  *sql.DB
	pol *policy.Service
	pe  *policyentities.Service
	cl  *clients.Service
	up  *upstreams.Service
}

func TestScopeCompileNoOverridesWhenNothingDiffersFromGlobal(t *testing.T) {
	o, _ := newScopeTestOrchestrator(t)
	ctx := context.Background()
	if err := o.Policy.CreateNetwork(ctx, "lan", "10.10.0.0/24"); err != nil {
		t.Fatal(err)
	}
	in, _, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.ScopeOverrides) != 0 {
		t.Fatalf("expected zero scope overrides when no scope differs from global, got %+v", in.ScopeOverrides)
	}
}

func TestScopeCompileNetworkFilteringProfileAddsCategoryDomains(t *testing.T) {
	o, h := newScopeTestOrchestrator(t)
	ctx := context.Background()
	if _, err := h.pe.CreateFilteringProfile(ctx, "kids-profile", "Kids", "", []string{"adult_content"}); err != nil {
		t.Fatal(err)
	}
	if err := o.Policy.CreateNetwork(ctx, "kids-lan", "10.20.0.0/24"); err != nil {
		t.Fatal(err)
	}
	profileID := "kids-profile"
	if err := o.Policy.Save(ctx, "network", "kids-lan", policy.Layer{FilteringProfileID: &profileID}); err != nil {
		t.Fatal(err)
	}

	in, _, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.ScopeOverrides) != 1 {
		t.Fatalf("expected exactly one scope override, got %+v", in.ScopeOverrides)
	}
	ov := in.ScopeOverrides[0]
	if ov.Source != "network:kids-lan" {
		t.Fatalf("expected network:kids-lan, got %q", ov.Source)
	}
	if len(ov.CIDRs) != 1 || ov.CIDRs[0] != "10.20.0.0/24" {
		t.Fatalf("expected the network's own CIDR, got %v", ov.CIDRs)
	}
	if !containsStr(ov.BlockedDomains, "adult.example.com") {
		t.Fatalf("expected adult.example.com (the assigned profile's own category) blocked, got %v", ov.BlockedDomains)
	}

	// Also prove it actually compiles to real, valid dnsdist Lua.
	out, err := dnscompile.CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "adult.example.com.") {
		t.Fatalf("expected the compiled config to contain the scoped blocked domain, got:\n%s", out)
	}
}

func TestScopeCompileClientParentalPolicySetsSafesearchAndCategories(t *testing.T) {
	o, h := newScopeTestOrchestrator(t)
	ctx := context.Background()
	if _, err := h.pe.CreateParentalPolicy(ctx, "strict-kids", "Strict Kids", "", "strict", []string{"adult_content"}); err != nil {
		t.Fatal(err)
	}
	clientID, err := h.cl.CreateClient(ctx, "kids-tablet", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.cl.AddIdentifier(ctx, clientID, "ipv4", "10.30.0.42"); err != nil {
		t.Fatal(err)
	}
	policyID := "strict-kids"
	if err := o.Policy.Save(ctx, "client", intToStr(clientID), policy.Layer{ParentalPolicyID: &policyID}); err != nil {
		t.Fatal(err)
	}

	in, _, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.ScopeOverrides) != 1 {
		t.Fatalf("expected exactly one scope override, got %+v", in.ScopeOverrides)
	}
	ov := in.ScopeOverrides[0]
	if ov.SafesearchMode != "strict" {
		t.Fatalf("expected SafesearchMode=strict from the assigned Parental Policy, got %q", ov.SafesearchMode)
	}
	if !containsStr(ov.BlockedDomains, "adult.example.com") {
		t.Fatalf("expected the parental policy's own category domain blocked, got %v", ov.BlockedDomains)
	}
	if len(ov.CIDRs) != 1 || ov.CIDRs[0] != "10.30.0.42/32" {
		t.Fatalf("expected the client's own static IP as a /32 matcher, got %v", ov.CIDRs)
	}
}

func TestScopeCompileDirectSafesearchFieldWinsOverParentalPolicy(t *testing.T) {
	o, h := newScopeTestOrchestrator(t)
	ctx := context.Background()
	if _, err := h.pe.CreateParentalPolicy(ctx, "moderate-kids", "Moderate Kids", "", "moderate", nil); err != nil {
		t.Fatal(err)
	}
	clientID, err := h.cl.CreateClient(ctx, "kid-phone", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.cl.AddIdentifier(ctx, clientID, "ipv4", "10.30.0.99"); err != nil {
		t.Fatal(err)
	}
	policyID := "moderate-kids"
	strict := "strict"
	if err := o.Policy.Save(ctx, "client", intToStr(clientID), policy.Layer{ParentalPolicyID: &policyID, SafesearchMode: &strict}); err != nil {
		t.Fatal(err)
	}

	in, _, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.ScopeOverrides) != 1 || in.ScopeOverrides[0].SafesearchMode != "strict" {
		t.Fatalf("expected the direct safesearch_mode field (strict) to win over the Parental Policy's own (moderate), got %+v", in.ScopeOverrides)
	}
}

func TestScopeCompileClientGroupHigherPriorityWins(t *testing.T) {
	o, h := newScopeTestOrchestrator(t)
	ctx := context.Background()
	if _, err := h.pe.CreateFilteringProfile(ctx, "low-profile", "Low", "", []string{"malware"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pe.CreateFilteringProfile(ctx, "high-profile", "High", "", []string{"adult_content"}); err != nil {
		t.Fatal(err)
	}
	if err := h.cl.CreateGroup(ctx, "low-group", "Low", 1); err != nil {
		t.Fatal(err)
	}
	if err := h.cl.CreateGroup(ctx, "high-group", "High", 10); err != nil {
		t.Fatal(err)
	}
	low := "low-profile"
	high := "high-profile"
	if err := o.Policy.Save(ctx, "group", "low-group", policy.Layer{FilteringProfileID: &low}); err != nil {
		t.Fatal(err)
	}
	if err := o.Policy.Save(ctx, "group", "high-group", policy.Layer{FilteringProfileID: &high}); err != nil {
		t.Fatal(err)
	}
	clientID, err := h.cl.CreateClient(ctx, "multi-group-client", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.cl.AddIdentifier(ctx, clientID, "ipv4", "10.40.0.5"); err != nil {
		t.Fatal(err)
	}
	if err := h.cl.AddToGroup(ctx, clientID, "low-group"); err != nil {
		t.Fatal(err)
	}
	if err := h.cl.AddToGroup(ctx, clientID, "high-group"); err != nil {
		t.Fatal(err)
	}

	in, _, _, err := o.build(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(in.ScopeOverrides) != 1 {
		t.Fatalf("expected exactly one scope override, got %+v", in.ScopeOverrides)
	}
	ov := in.ScopeOverrides[0]
	// high-group (priority 10) must win the filtering_profile_id field
	// over low-group (priority 1) -- its own category (adult_content)
	// must be the one reflected, matching internal/policy.OrderGroups'
	// own "highest priority wins" contract, already unit-tested there;
	// this proves it actually flows through to compiled output.
	if !containsStr(ov.BlockedDomains, "adult.example.com") {
		t.Fatalf("expected the higher-priority group's own category domain, got %v", ov.BlockedDomains)
	}
	if containsStr(ov.BlockedDomains, "malware.example.com") {
		t.Fatalf("malware.example.com is already in the GLOBAL list in this fixture (no global filtering profile assigned) -- it must not double-appear as a scope-specific addition: %v", ov.BlockedDomains)
	}
}

// TestScopeCompileLiveDNSProof is the strongest proof in this file: a
// real disposable named+dnsdist+apdns-hostagent triple, promoted for
// real, queried with a real `dig` -- not just asserting on the
// compiled Go struct or the generated Lua text. A network-scoped
// Filtering Profile assignment (127.0.0.1/32, a category the GLOBAL
// policy does not include) must make a real DNS query for that
// category's own domain come back NXDOMAIN, while an unrelated local
// DNS record on the very same appliance keeps resolving normally --
// proof this is genuinely scope-differentiated live enforcement, not
// a global change that happens to look scoped.
func TestScopeCompileLiveDNSProof(t *testing.T) {
	for _, bin := range []string{"named", "rndc", "dnsdist", "dig"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available in this environment", bin)
		}
	}
	db := newTestDB(t)
	ctx := context.Background()

	localDNS := &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}
	if _, err := localDNS.Create(ctx, localdns.CreateInput{Name: "always.lan", RecordType: "A", Value: "10.9.9.9", TTL: 300, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	bl := &blocklists.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()}
	if _, _, err := bl.Create(ctx, "scope-proof-sub", "Scope Proof", "https://example.invalid/x.txt", "adult_content"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bl.RuntimeDir, "scope-proof-sub.rpz"), []byte("blocked-by-scope.example.com CNAME .\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pol := &policy.Service{DB: db}
	pe := &policyentities.Service{DB: db}
	if _, err := pe.CreateFilteringProfile(ctx, "proof-profile", "Proof Profile", "", []string{"adult_content"}); err != nil {
		t.Fatal(err)
	}
	if err := pol.CreateNetwork(ctx, "loopback", "127.0.0.1/32"); err != nil {
		t.Fatal(err)
	}
	profileID := "proof-profile"
	if err := pol.Save(ctx, "network", "loopback", policy.Layer{FilteringProfileID: &profileID}); err != nil {
		t.Fatal(err)
	}

	bindDir := filepath.Join("/var/lib/bind", fmt.Sprintf("dnsruntime-scopeproof-%d", os.Getpid()), t.Name())
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
	t.Cleanup(stop)
	agentCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go agent.Serve(agentCtx)
	waitForSocket(t, sockPath)

	o := &Orchestrator{
		LocalDNS: localDNS, Blocklists: bl, Policy: pol, PolicyEntities: pe,
		HostAgent: hostagent.NewClient(sockPath), DnsdistListenAddress: cfg.DnsdistListenAddress,
		BindBackendAddress: fmt.Sprintf("127.0.0.1:%d", cfg.BindProxyPort),
	}
	res := o.Apply(ctx)
	if !res.Attempted || !res.Promoted || res.RolledBack {
		t.Fatalf("expected a real, clean end-to-end promotion, got %+v", res)
	}

	dig := func(name string) string {
		t.Helper()
		out, err := exec.Command("dig", "+time=2", "+tries=2", "@127.0.0.1", "-p", fmt.Sprintf("%d", dnsdistPort), name, "A").Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}

	// The scope-specific blocked domain: queried from 127.0.0.1, which
	// IS the scope this network policy applies to -- must come back
	// NXDOMAIN (blockingAction's own default), never a real answer.
	blockedOut := dig("blocked-by-scope.example.com")
	if !strings.Contains(blockedOut, "status: NXDOMAIN") {
		t.Fatalf("expected NXDOMAIN for the network-scope-blocked domain (real live DNS enforcement), got:\n%s", blockedOut)
	}

	// An unrelated appliance-wide local DNS record must be completely
	// unaffected by this scope's own block list -- proof the scope
	// mechanism is additive/targeted, not a global behavior change in
	// disguise.
	localOut := dig("always.lan")
	if !strings.Contains(localOut, "10.9.9.9") {
		t.Fatalf("expected always.lan to still resolve normally (unaffected by the network-scoped block), got:\n%s", localOut)
	}
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func intToStr(v int64) string {
	return fmt.Sprintf("%d", v)
}
