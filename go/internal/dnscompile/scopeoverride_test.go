package dnscompile

import (
	"strings"
	"testing"
)

func TestScopeOverrideBlockedDomainsCompilesAndMatchesCIDR(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{
		{Source: "network:kids-lan", CIDRs: []string{"10.20.0.0/24"}, BlockedDomains: []string{"social.example.com"}},
	}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `NetmaskGroupRule({"10.20.0.0/24"})`) {
		t.Fatalf("expected a NetmaskGroupRule for the scope CIDR, got:\n%s", out)
	}
	if !strings.Contains(out, `social.example.com.`) {
		t.Fatalf("expected the scope-specific blocked domain compiled, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestScopeOverrideClientKeyMatcherUsesTagRule(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{
		{Source: "client-7", ClientKey: "client-7", BlockedDomains: []string{"games.example.com"}},
	}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `TagRule("apdns_client", "client-7")`) {
		t.Fatalf("expected a TagRule matcher for the client-key scope, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestScopeOverrideBothMatchersCompileAsOrRule(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{
		{Source: "client-7", CIDRs: []string{"10.20.0.5/32"}, ClientKey: "client-7", BlockedDomains: []string{"games.example.com"}},
	}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "OrRule({NetmaskGroupRule") || !strings.Contains(out, `TagRule("apdns_client", "client-7")})`) {
		t.Fatalf("expected an OrRule combining both matchers, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestScopeOverrideRejectsInvalidCIDR(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{{Source: "bad", CIDRs: []string{"not-a-cidr"}, BlockedDomains: []string{"x.example.com"}}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for an invalid scope CIDR")
	}
}

func TestScopeOverrideRejectsEmptyMatcher(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{{Source: "no-matcher", BlockedDomains: []string{"x.example.com"}}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error for a scope override with no CIDR or ClientKey")
	}
}

func TestScopeOverrideSafesearchModerateRewritesYoutubeDifferentlyThanStrict(t *testing.T) {
	inModerate := minimalInput()
	inModerate.ScopeOverrides = []ScopeOverride{{Source: "network:kids", CIDRs: []string{"10.30.0.0/24"}, SafesearchMode: "moderate"}}
	outModerate, err := CompileDnsdist(inModerate)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(outModerate, "restrictmoderate.youtube.com.") {
		t.Fatalf("expected moderate YouTube SafeSearch CNAME, got:\n%s", outModerate)
	}
	if !strings.Contains(outModerate, "forcesafesearch.google.com.") {
		t.Fatalf("expected Google SafeSearch CNAME, got:\n%s", outModerate)
	}
	checkDnsdist(t, outModerate)

	inStrict := minimalInput()
	inStrict.ScopeOverrides = []ScopeOverride{{Source: "network:kids", CIDRs: []string{"10.30.0.0/24"}, SafesearchMode: "strict"}}
	outStrict, err := CompileDnsdist(inStrict)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(outStrict, "restrictmoderate.youtube.com.") {
		t.Fatalf("strict mode must not use the moderate YouTube target, got:\n%s", outStrict)
	}
	if !strings.Contains(outStrict, "restrict.youtube.com.") {
		t.Fatalf("expected strict YouTube SafeSearch CNAME, got:\n%s", outStrict)
	}
	checkDnsdist(t, outStrict)
}

func TestScopeOverrideSafesearchOffCompilesNothing(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{{Source: "network:trusted", CIDRs: []string{"10.40.0.0/24"}, SafesearchMode: "off"}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "forcesafesearch") {
		t.Fatalf("safesearch_mode=off must not compile any rewrite, got:\n%s", out)
	}
}

func TestScopeOverrideQueryLogAndStatsTags(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{{Source: "client-9", ClientKey: "client-9", QueryLoggingDisabled: true, StatisticsDisabled: true}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `SetTagAction("apdns_querylog", "off")`) {
		t.Fatalf("expected a query-log-disabled tag, got:\n%s", out)
	}
	if !strings.Contains(out, `SetTagAction("apdns_stats", "off")`) {
		t.Fatalf("expected a statistics-disabled tag, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestScopeOverrideUpstreamProfileCompilesDedicatedPool(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{{
		Source: "network:iot", CIDRs: []string{"10.50.0.0/24"},
		UpstreamProfileID: "iot-resolvers",
		UpstreamProfile:   &UpstreamProfile{Transport: "plain", Strategy: "first", Endpoints: []UpstreamEndpoint{{Address: "9.9.9.9:53"}}},
	}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `pool="scope_iot-resolvers"`) {
		t.Fatalf("expected a dedicated scope pool, got:\n%s", out)
	}
	if !strings.Contains(out, `PoolAction("scope_iot-resolvers")`) {
		t.Fatalf("expected a PoolAction routing the scope to its pool, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestScopeOverrideECSEnabledCompilesUseClientSubnet(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{{
		Source: "client-3", ClientKey: "client-3",
		UpstreamProfileID: "geo-aware",
		UpstreamProfile:   &UpstreamProfile{Transport: "plain", Strategy: "first", Endpoints: []UpstreamEndpoint{{Address: "1.1.1.1:53"}}},
		ECSEnabled:        true,
	}}
	out, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "useClientSubnet=true") {
		t.Fatalf("expected useClientSubnet=true on the ECS-enabled scope pool, got:\n%s", out)
	}
	checkDnsdist(t, out)
}

func TestScopeOverrideECSEnabledWithoutProfileErrors(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{{Source: "bad", ClientKey: "client-x", ECSEnabled: true}}
	if _, err := CompileDnsdist(in); err == nil {
		t.Fatal("expected an error: ecs_mode=enabled with no upstream profile to attach it to")
	}
}

func TestScopeOverrideIsDeterministicUnderReordering(t *testing.T) {
	in := minimalInput()
	in.ScopeOverrides = []ScopeOverride{
		{Source: "network:b", CIDRs: []string{"10.60.1.0/24"}, BlockedDomains: []string{"b.example.com"}},
		{Source: "network:a", CIDRs: []string{"10.60.0.0/24"}, BlockedDomains: []string{"a.example.com"}},
	}
	out1, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	in.ScopeOverrides[0], in.ScopeOverrides[1] = in.ScopeOverrides[1], in.ScopeOverrides[0]
	out2, err := CompileDnsdist(in)
	if err != nil {
		t.Fatal(err)
	}
	if out1 != out2 {
		t.Fatalf("scope override compile is not deterministic under input reordering:\n--- out1 ---\n%s\n--- out2 ---\n%s", out1, out2)
	}
}

