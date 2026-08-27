// Effective-policy resolution ("Explain") -- a direct, field-for-field
// port of app/v2/policy_compiler.py's compile_effective_policy /
// app/v2/policy_service.py's explain_policy_for_client (read directly,
// not guessed). Storage for every layer already exists in this package
// (Load/Save per scope) and in internal/clients (group membership); what
// was missing was the pure merge algorithm and the network-CIDR match,
// both ported here.
//
// Deterministic contract (mirrored from Python): given identical layer
// inputs in identical order, MergeLayers always produces byte-identical
// output, including the explain trace -- this is what makes the trace
// trustworthy for an operator to actually debug "why is this client's
// policy what it is", not a guess.
//
// Deliberately narrower than Python's real design, disclosed rather than
// hidden: no policy_schedules support yet (Go has no schedule-layer
// storage/worker at all), so the merge stack here is exactly
// global -> network -> groups -> client, never a schedule override.
package policy

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
)

// NamedLayer is one layer in precedence order (lowest first) plus the
// source label MergeLayers/ExplainEntry report it under -- e.g.
// "global", "network:corp-lan", "group:kids", "client".
type NamedLayer struct {
	Source string
	Layer  Layer
}

// ExplainEntry mirrors policy_compiler.ExplainEntry.
type ExplainEntry struct {
	Field  string `json:"field"`
	Value  any    `json:"value"`
	Source string `json:"source"`
}

// EffectivePolicy mirrors policy_compiler.EffectivePolicy: the resolved
// value of every field plus which layer/source won it.
type EffectivePolicy struct {
	Values  map[string]any `json:"values"`
	Explain []ExplainEntry `json:"explain"`
}

// fieldSpec is one of the 15 policy_layers columns -- get returns nil
// (as any) when this layer doesn't set the field, matching Python's own
// "None means unset, fall through to the next layer" contract exactly.
type fieldSpec struct {
	name    string
	get     func(Layer) any
	fallback any
}

func derefStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
func derefBool(p *bool) any {
	if p == nil {
		return nil
	}
	return *p
}

// fieldSpecs and each field's fallback are a direct port of
// policy_model.py's ALL_FIELDS/_ANSWER_DEFAULTS/_NON_ANSWER_DEFAULTS,
// same order, same default values.
var fieldSpecs = []fieldSpec{
	{"filtering_profile_id", func(l Layer) any { return derefStr(l.FilteringProfileID) }, "default"},
	{"safesearch_mode", func(l Layer) any { return derefStr(l.SafesearchMode) }, "off"},
	{"parental_policy_id", func(l Layer) any { return derefStr(l.ParentalPolicyID) }, "none"},
	{"security_policy_id", func(l Layer) any { return derefStr(l.SecurityPolicyID) }, "none"},
	{"service_blocking_ruleset_id", func(l Layer) any { return derefStr(l.ServiceBlockingRulesetID) }, "none"},
	{"blocking_response_mode", func(l Layer) any { return derefStr(l.BlockingResponseMode) }, "nxdomain"},
	{"custom_ipv4", func(l Layer) any { return derefStr(l.CustomIPv4) }, ""},
	{"custom_ipv6", func(l Layer) any { return derefStr(l.CustomIPv6) }, ""},
	{"upstream_profile_id", func(l Layer) any { return derefStr(l.UpstreamProfileID) }, "default"},
	{"fallback_strategy", func(l Layer) any { return derefStr(l.FallbackStrategy) }, "none"},
	{"fallback_upstream_profile_id", func(l Layer) any { return derefStr(l.FallbackUpstreamProfileID) }, "none"},
	{"ecs_mode", func(l Layer) any { return derefStr(l.ECSMode) }, "disabled"},
	{"domain_routing_ruleset_id", func(l Layer) any { return derefStr(l.DomainRoutingRulesetID) }, "none"},
	{"query_log_enabled", func(l Layer) any { return derefBool(l.QueryLogEnabled) }, true},
	{"statistics_enabled", func(l Layer) any { return derefBool(l.StatisticsEnabled) }, true},
}

// MergeLayers is a direct port of compile_effective_policy/_merge_field:
// for each field, the LAST layer in the given order that sets it
// (non-nil) wins; if none do, the field's own documented default wins
// with source "default". layers must already be in final precedence
// order (lowest first) -- this function has no opinion on how they got
// there (see OrderGroups/MatchNetwork below for the two non-trivial
// ordering decisions).
func MergeLayers(layers []NamedLayer) EffectivePolicy {
	values := make(map[string]any, len(fieldSpecs))
	explain := make([]ExplainEntry, 0, len(fieldSpecs))
	for _, spec := range fieldSpecs {
		value := spec.fallback
		source := "default"
		for _, nl := range layers {
			if v := spec.get(nl.Layer); v != nil {
				value = v
				source = nl.Source
			}
		}
		values[spec.name] = value
		explain = append(explain, ExplainEntry{Field: spec.name, Value: value, Source: source})
	}
	return EffectivePolicy{Values: values, Explain: explain}
}

// GroupMembership is the minimal shape MergeLayersForClient needs from
// internal/clients.GroupRef, kept here to avoid this package importing
// internal/clients (Go's usual acyclic-dependency direction: clients
// stays independent of policy, callers wire the two together).
type GroupMembership struct {
	GroupID  string
	Priority int
}

// OrderGroups is a direct port of policy_model.order_groups:
// deterministic application order is ascending priority, then group_id
// as a stable tie-break -- so the LAST one in the returned slice wins
// any direct field conflict (highest priority, lexicographically
// greatest group_id among ties).
func OrderGroups(groups []GroupMembership) []GroupMembership {
	ordered := append([]GroupMembership(nil), groups...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		return ordered[i].GroupID < ordered[j].GroupID
	})
	return ordered
}

// MatchNetwork is a direct port of network_match.py's
// CompiledNetworkTable.match: the most specific (longest prefix) match
// wins when networks overlap. Deterministic and dependency-free -- no
// I/O, matching Python's own "compiled once, matched in memory" design
// (the caller, MergeLayersForClient below, is what actually loads
// networks from storage).
func MatchNetwork(networks []Network, clientIP string) (Network, bool, error) {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return Network{}, false, fmt.Errorf("invalid client IP %q: %w", clientIP, err)
	}
	var best Network
	bestBits := -1
	found := false
	for _, n := range networks {
		prefix, err := netip.ParsePrefix(n.CIDR)
		if err != nil {
			continue // a malformed stored CIDR is skipped, not a hard error for every other network's match
		}
		if prefix.Addr().Is4() != addr.Is4() {
			continue // never cross-match an IPv4 address against an IPv6 network or vice versa
		}
		if prefix.Contains(addr) && prefix.Bits() > bestBits {
			best, bestBits, found = n, prefix.Bits(), true
		}
	}
	return best, found, nil
}

// LayerLoader is the minimal surface MergeLayersForClient needs to load
// a scoped layer -- satisfied by *Service.Load itself; a separate
// interface only so this file's own tests can inject a fixture without
// a real DB.
type LayerLoader interface {
	Load(ctx context.Context, scope, scopeRef string) (Layer, error)
}

// ClientExplanation is MergeLayersForClient's full result: the resolved
// policy plus which network/groups actually applied -- independent of
// whether any of their fields happened to override a value, distinct
// from EffectivePolicy.Explain's per-field "source" (which only names a
// scope when it actually won a field). Mirrors
// policy_service.explain_policy_for_client's own network_match/
// group_contributions split.
type ClientExplanation struct {
	Policy             EffectivePolicy
	NetworkMatch       string // "" if clientIP was empty or matched nothing
	GroupContributions []string
}

// MergeLayersForClient assembles the real global -> network -> groups ->
// client precedence stack for one client and resolves it -- the
// control.db/service-backed half of compile_effective_policy_from_store.
// clientIP is optional ("" skips network matching, same as Python's own
// Optional[str] contract); groups must already be this client's real
// membership (internal/clients.Service.GroupsForClient), converted to
// GroupMembership by the caller to avoid an import cycle.
func MergeLayersForClient(ctx context.Context, loader LayerLoader, networks []Network, clientIDStr, clientIP string, groups []GroupMembership) (ClientExplanation, error) {
	global, err := loader.Load(ctx, "global", "global")
	if err != nil {
		return ClientExplanation{}, fmt.Errorf("loading global policy: %w", err)
	}
	layers := []NamedLayer{{Source: "global", Layer: global}}

	var networkMatch string
	if clientIP != "" {
		match, ok, err := MatchNetwork(networks, clientIP)
		if err != nil {
			return ClientExplanation{}, err
		}
		if ok {
			l, err := loader.Load(ctx, "network", match.NetworkID)
			if err != nil {
				return ClientExplanation{}, fmt.Errorf("loading network policy %q: %w", match.NetworkID, err)
			}
			networkMatch = "network:" + match.NetworkID
			layers = append(layers, NamedLayer{Source: networkMatch, Layer: l})
		}
	}

	groupSources := make([]string, 0, len(groups))
	for _, g := range OrderGroups(groups) {
		l, err := loader.Load(ctx, "group", g.GroupID)
		if err != nil {
			return ClientExplanation{}, fmt.Errorf("loading group policy %q: %w", g.GroupID, err)
		}
		source := "group:" + g.GroupID
		layers = append(layers, NamedLayer{Source: source, Layer: l})
		groupSources = append(groupSources, source)
	}

	clientLayer, err := loader.Load(ctx, "client", clientIDStr)
	if err != nil {
		return ClientExplanation{}, fmt.Errorf("loading client policy: %w", err)
	}
	layers = append(layers, NamedLayer{Source: "client", Layer: clientLayer})

	return ClientExplanation{Policy: MergeLayers(layers), NetworkMatch: networkMatch, GroupContributions: groupSources}, nil
}
