package policy

import (
	"context"
	"testing"
)

func TestMergeLayersLastNonNilLayerWins(t *testing.T) {
	layers := []NamedLayer{
		{Source: "global", Layer: Layer{SafesearchMode: strp("moderate"), BlockingResponseMode: strp("nxdomain")}},
		{Source: "group:kids", Layer: Layer{SafesearchMode: strp("strict")}},
		{Source: "client", Layer: Layer{}}, // sets nothing -- must not override the group's value
	}
	result := MergeLayers(layers)
	if result.Values["safesearch_mode"] != "strict" {
		t.Fatalf("expected the group layer's 'strict' to win over global's 'moderate', got %v", result.Values["safesearch_mode"])
	}
	if result.Values["blocking_response_mode"] != "nxdomain" {
		t.Fatalf("expected global's blocking_response_mode to survive since nothing above it set it, got %v", result.Values["blocking_response_mode"])
	}
}

func TestMergeLayersFallsBackToDocumentedDefaults(t *testing.T) {
	result := MergeLayers([]NamedLayer{{Source: "global", Layer: Layer{}}})
	want := map[string]any{
		"filtering_profile_id": "default", "safesearch_mode": "off", "parental_policy_id": "none",
		"security_policy_id": "none", "service_blocking_ruleset_id": "none", "blocking_response_mode": "nxdomain",
		"custom_ipv4": "", "custom_ipv6": "", "upstream_profile_id": "default", "fallback_strategy": "none",
		"fallback_upstream_profile_id": "none", "ecs_mode": "disabled", "domain_routing_ruleset_id": "none",
		"query_log_enabled": true, "statistics_enabled": true,
	}
	for field, expected := range want {
		if result.Values[field] != expected {
			t.Errorf("field %q: expected default %v, got %v", field, expected, result.Values[field])
		}
	}
	for _, e := range result.Explain {
		if e.Source != "default" {
			t.Errorf("field %q: expected source \"default\" when nothing set it, got %q", e.Field, e.Source)
		}
	}
}

func TestMergeLayersExplainTraceNamesTheWinningSource(t *testing.T) {
	layers := []NamedLayer{
		{Source: "global", Layer: Layer{}},
		{Source: "network:corp-lan", Layer: Layer{UpstreamProfileID: strp("corp")}},
		{Source: "client", Layer: Layer{}},
	}
	result := MergeLayers(layers)
	var got *ExplainEntry
	for i := range result.Explain {
		if result.Explain[i].Field == "upstream_profile_id" {
			got = &result.Explain[i]
		}
	}
	if got == nil || got.Source != "network:corp-lan" || got.Value != "corp" {
		t.Fatalf("expected the explain trace to name network:corp-lan as the source, got %+v", got)
	}
}

func TestOrderGroupsAscendingPriorityThenGroupIDTieBreak(t *testing.T) {
	groups := []GroupMembership{
		{GroupID: "zzz", Priority: 5},
		{GroupID: "aaa", Priority: 5}, // same priority as zzz -- group_id tie-break, "zzz" > "aaa" so zzz applied last (wins)
		{GroupID: "kids", Priority: 1},
	}
	ordered := OrderGroups(groups)
	if len(ordered) != 3 || ordered[len(ordered)-1].GroupID != "zzz" {
		t.Fatalf("expected 'zzz' (priority 5, lexicographically greatest tie) applied last (wins), got %+v", ordered)
	}
	if ordered[0].GroupID != "kids" {
		t.Fatalf("expected the lowest-priority group first, got %+v", ordered)
	}
}

func TestMatchNetworkMostSpecificPrefixWins(t *testing.T) {
	networks := []Network{
		{NetworkID: "broad", CIDR: "10.0.0.0/8"},
		{NetworkID: "narrow", CIDR: "10.0.1.0/24"},
	}
	match, ok, err := MatchNetwork(networks, "10.0.1.42")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || match.NetworkID != "narrow" {
		t.Fatalf("expected the more specific /24 network to win over the /8, got %+v (ok=%v)", match, ok)
	}
}

func TestMatchNetworkNoMatchReturnsFalse(t *testing.T) {
	_, ok, err := MatchNetwork([]Network{{NetworkID: "a", CIDR: "10.0.0.0/8"}}, "192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected no match for an IP outside every configured network")
	}
}

func TestMatchNetworkRejectsAnInvalidClientIP(t *testing.T) {
	if _, _, err := MatchNetwork(nil, "not-an-ip"); err == nil {
		t.Fatal("expected an error for an invalid client IP")
	}
}

func TestMatchNetworkNeverCrossMatchesIPv4AndIPv6(t *testing.T) {
	_, ok, err := MatchNetwork([]Network{{NetworkID: "v6", CIDR: "2001:db8::/32"}}, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected an IPv4 address never to match an IPv6 network")
	}
}

// TestMergeLayersForClientRealPrecedenceStack is the real, storage-backed
// end-to-end proof: global < network < groups < client, with a client
// layer field overriding everything below it, and an unset client field
// falling through to the matched network's own value -- against a real
// Service.Load, not a fixture double.
func TestMergeLayersForClientRealPrecedenceStack(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	mustSave := func(scope, ref string, l Layer) {
		t.Helper()
		if err := s.Save(ctx, scope, ref, l); err != nil {
			t.Fatal(err)
		}
	}
	mustSave("global", "global", Layer{SafesearchMode: strp("off"), BlockingResponseMode: strp("nxdomain")})
	mustSave("network", "corp-lan", Layer{SafesearchMode: strp("moderate")})
	mustSave("group", "kids", Layer{SafesearchMode: strp("strict")})
	mustSave("client", "42", Layer{BlockingResponseMode: strp("refused")}) // overrides global's blocking mode; leaves safesearch alone

	networks := []Network{{NetworkID: "corp-lan", CIDR: "10.1.0.0/16"}}
	groups := []GroupMembership{{GroupID: "kids", Priority: 1}}

	explanation, err := MergeLayersForClient(ctx, s, networks, "42", "10.1.5.5", groups)
	if err != nil {
		t.Fatal(err)
	}
	result := explanation.Policy
	if result.Values["safesearch_mode"] != "strict" {
		t.Fatalf("expected the group's 'strict' (higher precedence than network) to win, got %v", result.Values["safesearch_mode"])
	}
	if result.Values["blocking_response_mode"] != "refused" {
		t.Fatalf("expected the client layer's own override to win, got %v", result.Values["blocking_response_mode"])
	}
	if explanation.NetworkMatch != "network:corp-lan" {
		t.Fatalf("expected the matched network to be reported, got %q", explanation.NetworkMatch)
	}
	if len(explanation.GroupContributions) != 1 || explanation.GroupContributions[0] != "group:kids" {
		t.Fatalf("expected the client's group to be reported as a real contribution, got %v", explanation.GroupContributions)
	}
}

func TestMergeLayersForClientWithNoNetworkMatchSkipsNetworkLayer(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.Save(ctx, "global", "global", Layer{SafesearchMode: strp("off")}); err != nil {
		t.Fatal(err)
	}
	explanation, err := MergeLayersForClient(ctx, s, nil, "1", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if explanation.Policy.Values["safesearch_mode"] != "off" {
		t.Fatalf("expected the global value with no other layers, got %v", explanation.Policy.Values["safesearch_mode"])
	}
	if explanation.NetworkMatch != "" || len(explanation.GroupContributions) != 0 {
		t.Fatalf("expected no contributions with no client IP and no groups, got network=%q groups=%v", explanation.NetworkMatch, explanation.GroupContributions)
	}
}
