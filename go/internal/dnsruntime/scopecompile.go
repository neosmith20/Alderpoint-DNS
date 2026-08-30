// Per-scope (network/group/client) policy compilation -- the real
// wiring between internal/policy's stored Layer fields and
// internal/dnscompile.ScopeOverride's real DNS-runtime effect. See
// internal/dnscompile/scopeoverride.go's own doc comment for what gets
// compiled and internal/policyentities' for what the four
// filtering_profile_id/parental_policy_id/security_policy_id/
// service_blocking_ruleset_id fields resolve to.
//
// V1.1.1 evidence (2026-08-30 owner-directed parity remediation,
// blocker 1): every field this file resolves --
// filtering_profile_id/parental_policy_id/security_policy_id/
// service_blocking_ruleset_id/safesearch_mode/ecs_mode/
// domain_routing_ruleset_id -- has zero occurrences anywhere in the
// real shipped V1.1.1 package (/root/alderpointdns_1.1.1-1_all.deb's
// app/*.py, grepped directly). V1.1.1's own `network_policies`/
// `policy_profiles`/`profile_categories` tables existed but were only
// ever created, listed in CLI output, and replicated -- never read to
// compile BIND/dnsdist config. This is real V2 release functionality
// built at the owner's explicit direction, not a V1 parity
// requirement.
//
// Deliberately additive-only, disclosed here rather than silently
// narrower: assigning a Filtering/Parental/Security profile to a
// scope ADDS that profile's own category-derived domains to what
// global already blocks for that scope -- it can never make a scope
// see FEWER blocked domains than global (no per-scope "allow" of a
// globally-blocked domain). This is the safe-by-default choice for a
// DNS-filtering appliance (a misconfigured "trusted" profile fails
// closed, never accidentally permits something global already
// blocks) -- narrowing below global is a real, separate feature not
// attempted in this pass.
package dnsruntime

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"alderpointdns/go-controlplane/internal/blocklists"
	"alderpointdns/go-controlplane/internal/clients"
	"alderpointdns/go-controlplane/internal/dnscompile"
	"alderpointdns/go-controlplane/internal/domainrouting"
	"alderpointdns/go-controlplane/internal/policy"
	"alderpointdns/go-controlplane/internal/upstreams"
)

// entityCatalog is every already-loaded piece of state
// computeScopeOverrides needs to resolve a merged policy.Layer's ID
// fields into real, concrete DNS-compiler input -- loaded once per
// build() call (not once per scope), matching every other Input
// field's "load once, resolve many times" shape in this file.
type entityCatalog struct {
	blocklistSubs   []blocklists.Subscription
	blocklistDir    string
	filteringByID   map[string][]string // profile id -> categories
	parentalByID    map[string]parentalEntry
	securityByID    map[string][]string
	serviceByID     map[string][]string // ruleset id -> domains
	upstreamsByID   map[string]upstreams.Profile
	routesByRuleset map[string][]domainrouting.Rule
}

type parentalEntry struct {
	categories     []string
	safesearchMode string
}

func (o *Orchestrator) loadEntityCatalog(ctx context.Context, subs []blocklists.Subscription, allProfiles []upstreams.Profile) (*entityCatalog, error) {
	cat := &entityCatalog{
		blocklistSubs: subs,
		upstreamsByID: map[string]upstreams.Profile{},
	}
	if o.Blocklists != nil {
		cat.blocklistDir = o.Blocklists.RuntimeDir
	}
	for _, p := range allProfiles {
		cat.upstreamsByID[p.UpstreamProfileID] = p
	}
	if o.PolicyEntities != nil {
		filtering, err := o.PolicyEntities.ListFilteringProfiles(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading filtering profiles: %w", err)
		}
		cat.filteringByID = map[string][]string{}
		for _, p := range filtering {
			cat.filteringByID[p.ID] = p.Categories
		}
		parental, err := o.PolicyEntities.ListParentalPolicies(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading parental policies: %w", err)
		}
		cat.parentalByID = map[string]parentalEntry{}
		for _, p := range parental {
			cat.parentalByID[p.ID] = parentalEntry{categories: p.Categories, safesearchMode: p.SafesearchMode}
		}
		security, err := o.PolicyEntities.ListSecurityPolicies(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading security policies: %w", err)
		}
		cat.securityByID = map[string][]string{}
		for _, p := range security {
			cat.securityByID[p.ID] = p.Categories
		}
		serviceRulesets, err := o.PolicyEntities.ListServiceBlockingRulesets(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading service blocking rulesets: %w", err)
		}
		cat.serviceByID = map[string][]string{}
		for _, r := range serviceRulesets {
			cat.serviceByID[r.ID] = r.Domains
		}
	}
	if o.DomainRouting != nil {
		rulesets, err := o.DomainRouting.ListRulesets(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading domain routing rulesets: %w", err)
		}
		cat.routesByRuleset = map[string][]domainrouting.Rule{}
		for _, rs := range rulesets {
			rules, err := o.DomainRouting.ListForRuleset(ctx, rs.ID)
			if err != nil {
				return nil, fmt.Errorf("loading domain routing rules for ruleset %q: %w", rs.ID, err)
			}
			cat.routesByRuleset[rs.ID] = rules
		}
	}
	return cat, nil
}

// resolved is one scope's fully-resolved policy dimensions, ready to
// diff against global's own resolved dimensions.
type resolved struct {
	blockingResponseMode                                  string
	customIPv4, customIPv6                                string
	categories                                            map[string]bool // union of filtering+parental+security profile categories
	filteringID, parentalID, securityID, serviceRulesetID string
	safesearchMode                                        string
	ecsEnabled                                            bool
	upstreamProfileID                                     string
	domainRoutingRulesetID                                string
	queryLogEnabled, statsEnabled                         bool
}

func resolveLayerValues(ep policy.EffectivePolicy, cat *entityCatalog) resolved {
	str := func(field string) string { s, _ := ep.Values[field].(string); return s }
	explainSource := func(field string) string {
		for _, e := range ep.Explain {
			if e.Field == field {
				return e.Source
			}
		}
		return "default"
	}

	r := resolved{
		blockingResponseMode:   str("blocking_response_mode"),
		customIPv4:             str("custom_ipv4"),
		customIPv6:             str("custom_ipv6"),
		filteringID:            str("filtering_profile_id"),
		parentalID:             str("parental_policy_id"),
		securityID:             str("security_policy_id"),
		serviceRulesetID:       str("service_blocking_ruleset_id"),
		upstreamProfileID:      str("upstream_profile_id"),
		domainRoutingRulesetID: str("domain_routing_ruleset_id"),
		ecsEnabled:             str("ecs_mode") == "enabled",
		queryLogEnabled:        true,
		statsEnabled:           true,
	}
	if v, ok := ep.Values["query_log_enabled"].(bool); ok {
		r.queryLogEnabled = v
	}
	if v, ok := ep.Values["statistics_enabled"].(bool); ok {
		r.statsEnabled = v
	}

	r.categories = map[string]bool{}
	if cat != nil {
		if r.filteringID != "" && r.filteringID != "default" {
			for _, c := range cat.filteringByID[r.filteringID] {
				r.categories[c] = true
			}
		}
		if r.securityID != "" && r.securityID != "none" {
			for _, c := range cat.securityByID[r.securityID] {
				r.categories[c] = true
			}
		}
	}

	// safesearch_mode: the direct Layer field wins whenever any layer
	// in the merge stack set it explicitly; only when it fell all the
	// way through to the field's own "off" default does an assigned
	// Parental Policy's own SafesearchMode apply -- matching
	// internal/policyentities.ParentalPolicy's own doc comment on this
	// exact precedence.
	r.safesearchMode = str("safesearch_mode")
	if explainSource("safesearch_mode") == "default" && cat != nil {
		if r.parentalID != "" && r.parentalID != "none" {
			if p, ok := cat.parentalByID[r.parentalID]; ok {
				r.safesearchMode = p.safesearchMode
				for _, c := range p.categories {
					r.categories[c] = true
				}
			}
		}
	} else if cat != nil && r.parentalID != "" && r.parentalID != "none" {
		// Direct field won the safesearch value, but the assigned
		// Parental Policy's own category set (adult content etc.) still
		// contributes to blocking regardless of which value won
		// safesearch_mode specifically -- these are independent
		// dimensions of the same entity.
		if p, ok := cat.parentalByID[r.parentalID]; ok {
			for _, c := range p.categories {
				r.categories[c] = true
			}
		}
	}
	return r
}

// blockedDomainsForCategories reads every enabled blocklist
// subscription whose own Category is in categories and unions their
// already-pulled RPZ domain lists -- the exact same
// read-the-subscription's-RPZ-file mechanism build() already uses for
// the global list, just filtered to a category subset.
func blockedDomainsForCategories(cat *entityCatalog, categories map[string]bool) []string {
	if len(categories) == 0 || cat.blocklistDir == "" {
		return nil
	}
	set := map[string]bool{}
	for _, sub := range cat.blocklistSubs {
		if !sub.Enabled || !categories[sub.Category] {
			continue
		}
		path := filepath.Join(cat.blocklistDir, sub.SubscriptionID+".rpz")
		domains, err := readRPZDomains(path)
		if err != nil {
			continue // not yet pulled -- same "not a hard error" honesty as the global loop
		}
		for _, d := range domains {
			set[d] = true
		}
	}
	out := make([]string, 0, len(set))
	for d := range set {
		out = append(out, d)
	}
	return out
}

// buildScopeOverride resolves one scope's merged EffectivePolicy
// against global's own resolved dimensions and returns a
// dnscompile.ScopeOverride (matcher fields left empty -- the caller
// fills CIDRs/ClientKey) plus whether anything actually differs from
// global (an override with nothing different must never be emitted --
// same discipline NetworkOverride's own build()-site comment already
// documents).
func buildScopeOverride(source string, r, global resolved, cat *entityCatalog) (dnscompile.ScopeOverride, bool) {
	ov := dnscompile.ScopeOverride{Source: source}
	changed := false

	if !sameStringSet(r.categories, global.categories) || r.serviceRulesetID != global.serviceRulesetID {
		domains := blockedDomainsForCategories(cat, r.categories)
		if r.serviceRulesetID != "" && r.serviceRulesetID != "none" && cat != nil {
			domains = append(domains, cat.serviceByID[r.serviceRulesetID]...)
		}
		if len(domains) > 0 {
			ov.BlockedDomains = domains
			ov.BlockingResponseMode = r.blockingResponseMode
			ov.CustomIPv4, ov.CustomIPv6 = r.customIPv4, r.customIPv6
			changed = true
		}
	}

	if r.safesearchMode != global.safesearchMode && (r.safesearchMode == "moderate" || r.safesearchMode == "strict") {
		ov.SafesearchMode = r.safesearchMode
		changed = true
	}

	if r.upstreamProfileID != global.upstreamProfileID && r.upstreamProfileID != "" && r.upstreamProfileID != "default" {
		if p, ok := cat.upstreamsByID[r.upstreamProfileID]; ok && len(p.Endpoints) > 0 {
			profile := upstreamProfileToCompile(p)
			ov.UpstreamProfileID = r.upstreamProfileID
			ov.UpstreamProfile = &profile
			changed = true
		}
	}
	if r.ecsEnabled && !global.ecsEnabled {
		ov.ECSEnabled = true
		if ov.UpstreamProfileID == "" {
			// ECS needs a real profile to attach useClientSubnet to --
			// fall back to whatever this scope's own upstream_profile_id
			// resolves to (even if identical to global's), or to global's
			// own default profile as a last resort, so an owner enabling
			// "ECS: enabled" alone (no separate upstream override) still
			// gets a real compiled effect instead of being silently
			// dropped for lack of a profile to carry it.
			id := r.upstreamProfileID
			if id == "" || id == "default" {
				id = global.upstreamProfileID
			}
			if p, ok := cat.upstreamsByID[id]; ok && len(p.Endpoints) > 0 {
				profile := upstreamProfileToCompile(p)
				ov.UpstreamProfileID = id
				ov.UpstreamProfile = &profile
			}
		}
		if ov.UpstreamProfileID != "" {
			changed = true
		}
	}

	if r.domainRoutingRulesetID != global.domainRoutingRulesetID && r.domainRoutingRulesetID != "" && r.domainRoutingRulesetID != "none" && cat != nil {
		if rules, ok := cat.routesByRuleset[r.domainRoutingRulesetID]; ok && len(rules) > 0 {
			for _, rule := range rules {
				p, ok := cat.upstreamsByID[rule.UpstreamProfileID]
				if !ok || len(p.Endpoints) == 0 {
					continue
				}
				ov.DomainRoutes = append(ov.DomainRoutes, dnscompile.DomainRoute{
					MatchKind: rule.MatchKind, Domain: rule.Domain, ProfileID: rule.UpstreamProfileID,
					Profile: upstreamProfileToCompile(p),
				})
			}
			if len(ov.DomainRoutes) > 0 {
				changed = true
			}
		}
	}

	if r.queryLogEnabled != global.queryLogEnabled && !r.queryLogEnabled {
		ov.QueryLoggingDisabled = true
		changed = true
	}
	if r.statsEnabled != global.statsEnabled && !r.statsEnabled {
		ov.StatisticsDisabled = true
		changed = true
	}

	return ov, changed
}

func upstreamProfileToCompile(p upstreams.Profile) dnscompile.UpstreamProfile {
	endpoints := make([]dnscompile.UpstreamEndpoint, len(p.Endpoints))
	for i, ep := range p.Endpoints {
		var tlsHost, dohPath string
		if ep.TLSHostname != nil {
			tlsHost = *ep.TLSHostname
		}
		if ep.DohPath != nil {
			dohPath = *ep.DohPath
		}
		endpoints[i] = dnscompile.UpstreamEndpoint{Address: ep.Address, TLSHostname: tlsHost, DohPath: dohPath}
	}
	return dnscompile.UpstreamProfile{Transport: p.Transport, Strategy: p.Strategy, Endpoints: endpoints}
}

func sameStringSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// computeScopeOverrides is the top-level entry point build() calls:
// resolves every network's own effective policy (global merged with
// its own layer) and every registered, enabled client's own effective
// policy (global -> matched network -> groups, in priority order ->
// client, via the exact same policy.MergeLayersForClient this
// package's own Explain endpoint already uses and already tests),
// emitting a dnscompile.ScopeOverride only for a scope that genuinely
// differs from global.
func (o *Orchestrator) computeScopeOverrides(ctx context.Context, globalLayer policy.Layer, subs []blocklists.Subscription, allProfiles []upstreams.Profile) ([]dnscompile.ScopeOverride, error) {
	cat, err := o.loadEntityCatalog(ctx, subs, allProfiles)
	if err != nil {
		return nil, err
	}
	globalResolved := resolveLayerValues(policy.MergeLayers([]policy.NamedLayer{{Source: "global", Layer: globalLayer}}), cat)

	networks, err := o.Policy.ListNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading networks: %w", err)
	}

	var overrides []dnscompile.ScopeOverride

	for _, netw := range networks {
		netLayer, err := o.Policy.Load(ctx, "network", netw.NetworkID)
		if err != nil {
			continue
		}
		merged := policy.MergeLayers([]policy.NamedLayer{{Source: "global", Layer: globalLayer}, {Source: "network:" + netw.NetworkID, Layer: netLayer}})
		r := resolveLayerValues(merged, cat)
		ov, changed := buildScopeOverride("network:"+netw.NetworkID, r, globalResolved, cat)
		if changed {
			ov.CIDRs = []string{netw.CIDR}
			overrides = append(overrides, ov)
		}
	}

	if o.Clients != nil {
		allClients, err := o.Clients.ListClients(ctx)
		if err != nil {
			return nil, fmt.Errorf("loading clients: %w", err)
		}
		for _, c := range allClients {
			if !c.Enabled {
				continue
			}
			groups := make([]policy.GroupMembership, len(c.Groups))
			for i, g := range c.Groups {
				groups[i] = policy.GroupMembership{GroupID: g.GroupID, Priority: g.Priority}
			}
			clientIP := firstActiveIP(c.Identifiers)
			clientIDStr := fmt.Sprintf("%d", c.ID)
			explanation, err := policy.MergeLayersForClient(ctx, o.Policy, networks, clientIDStr, clientIP, groups)
			if err != nil {
				continue // matches every other per-item "skip, don't fail the whole compile" convention in build()
			}
			r := resolveLayerValues(explanation.Policy, cat)
			ov, changed := buildScopeOverride("client-"+clientIDStr, r, globalResolved, cat)
			if !changed {
				continue
			}
			ov.CIDRs = activeCIDRs(c.Identifiers)
			if hasActiveClientID(c.Identifiers) {
				ov.ClientKey = "client-" + clientIDStr
			}
			if len(ov.CIDRs) == 0 && ov.ClientKey == "" {
				continue // no real, stable way to match this client's traffic (no IP identifier, no Strong ClientID) -- nothing to compile
			}
			overrides = append(overrides, ov)
		}
	}

	sort.Slice(overrides, func(i, j int) bool { return overrides[i].Source < overrides[j].Source })
	return overrides, nil
}

func firstActiveIP(ids []clients.Identifier) string {
	for _, id := range ids {
		if id.RevokedAt != "" {
			continue
		}
		if id.Kind == "ipv4" || id.Kind == "ipv6" {
			return id.Value
		}
	}
	return ""
}

func activeCIDRs(ids []clients.Identifier) []string {
	var out []string
	for _, id := range ids {
		if id.RevokedAt != "" {
			continue
		}
		switch id.Kind {
		case "ipv4":
			out = append(out, id.Value+"/32")
		case "ipv6":
			out = append(out, id.Value+"/128")
		case "ipv4_cidr", "ipv6_cidr":
			out = append(out, id.Value)
		}
	}
	return out
}

func hasActiveClientID(ids []clients.Identifier) bool {
	for _, id := range ids {
		if id.Kind == "clientid" && id.RevokedAt == "" {
			return true
		}
	}
	return false
}
