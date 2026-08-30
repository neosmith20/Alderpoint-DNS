// Per-scope (network/group/client) DNS policy enforcement -- the real
// runtime compilation for internal/policy's own Layer fields that
// previously were only ever stored and explained, never compiled (see
// internal/policycompile's own doc comment for the full V1.1.1
// evidence trail establishing that these fields have no V1 ancestor,
// and the 2026-08-30 owner decision to build them as real V2 release
// functionality regardless).
//
// ScopeOverride is additive to, and independent of, NetworkOverride
// above: NetworkOverride only ever varies the blocking-RESPONSE for
// the one global blocked-domain list; ScopeOverride carries a scope's
// own fully-resolved BLOCKED-DOMAIN SET (different categories/
// profiles per scope), SafeSearch, ECS, per-scope upstream routing,
// and query-log/statistics participation -- fields NetworkOverride has
// no concept of. Both can compile for the same network CIDR
// simultaneously with no conflict: NetworkOverride's rules only ever
// match against the GLOBAL blocked-domain list (governing the
// response for domains blocked at every scope), while ScopeOverride's
// own BlockedDomains rules run first and only ever match this scope's
// OWN additional/different domains.
package dnscompile

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// ScopeOverride is one network or client scope whose own effective
// policy (global merged through network/group/client via
// internal/policy.MergeLayers/MergeLayersForClient) differs from plain
// global for at least one field this compiler now knows how to act on.
// The caller (internal/dnsruntime's orchestrator, via
// internal/policycompile) is responsible for computing every resolved
// value here and for only including a scope when it genuinely differs
// from global -- this package trusts every field as given and does no
// policy merging or entity lookup of its own, matching every other
// Input field's "pure value, not a reference" contract.
type ScopeOverride struct {
	Source string // e.g. "network:kids-lan" / "client-42" -- comment/debug only, never matched on

	// Matcher: at least one of CIDRs/ClientKey must be non-empty.
	// Both may be set for a client with both a static IP/CIDR identity
	// and a Strong ClientID -- either matching is sufficient (OrRule).
	CIDRs     []string
	ClientKey string // matches ClientIdentity.ClientKey (already tagged via writeClientRules above)

	BlockingResponseMode string // blockingAction() input for this scope's OWN BlockedDomains below; "" defaults to nxdomain, same as every other unset response mode
	CustomIPv4, CustomIPv6 string

	// BlockedDomains is this scope's own fully-resolved blocked-domain
	// set (custom-rule blocks ∪ category-resolved blocklist domains for
	// this scope's own filtering/parental/security profile assignments
	// ∪ its own service-blocking-ruleset domains, already set-
	// subtracted by global allow rules) -- nil/empty means this scope
	// has no additional/different domains blocked beyond the global
	// list (it may still differ in SafeSearch/ECS/upstream/logging).
	BlockedDomains []string

	SafesearchMode string // "moderate" | "strict"; "" or "off" = no rewriting for this scope

	// ECSEnabled: true attaches this scope's real client subnet to
	// upstream queries (a per-scope opt-in -- global default is no ECS
	// at all, matching V1.1.1 exactly, which never sent ECS anywhere).
	ECSEnabled bool

	// UpstreamProfile/UpstreamProfileID: when UpstreamProfileID is
	// non-empty, this scope's queries (any not already claimed by a
	// domain-routing rule, which always wins regardless of scope) are
	// routed to this profile's own servers instead of the default
	// pool. UpstreamProfile must be non-nil whenever UpstreamProfileID
	// is non-empty.
	UpstreamProfileID string
	UpstreamProfile    *UpstreamProfile

	QueryLoggingDisabled bool
	StatisticsDisabled   bool
}

func (o ScopeOverride) matcherExpr() (string, error) {
	var parts []string
	if len(o.CIDRs) > 0 {
		cidrs := append([]string(nil), o.CIDRs...)
		sort.Strings(cidrs)
		for _, c := range cidrs {
			if _, _, err := net.ParseCIDR(c); err != nil {
				return "", errf("scope override %q has an invalid CIDR %q: %v", o.Source, c, err)
			}
		}
		quoted := make([]string, len(cidrs))
		for i, c := range cidrs {
			quoted[i] = luaString(c)
		}
		parts = append(parts, fmt.Sprintf("NetmaskGroupRule({%s})", strings.Join(quoted, ", ")))
	}
	if o.ClientKey != "" {
		parts = append(parts, fmt.Sprintf("TagRule(%s, %s)", luaString(clientTag), luaString(o.ClientKey)))
	}
	if len(parts) == 0 {
		return "", errf("scope override %q has no CIDR or ClientKey to match on", o.Source)
	}
	if len(parts) == 1 {
		return parts[0], nil
	}
	return fmt.Sprintf("OrRule({%s})", strings.Join(parts, ", ")), nil
}

// safesearchRewrite is one known search-engine QNAME pattern -> the
// CNAME a client asking with SafeSearch enabled should be redirected
// to. Deliberately scoped to the well-known major engines with a real,
// documented forced-safe-mode CNAME target, not "every search engine"
// -- Google/Bing/DuckDuckGo have one target regardless of moderate vs
// strict; YouTube is the one real moderate/strict distinction
// (restrictmoderate.youtube.com vs restrict.youtube.com, Google's own
// documented values).
type safesearchRewrite struct {
	pattern        string // RegexRule pattern, already anchored
	moderateTarget string
	strictTarget   string // "" = moderateTarget also covers strict
}

// Patterns are deliberately lowercase-only, no inline case-insensitive
// flag: dnsdist's own RegexRule uses std::regex (ECMAScript grammar,
// confirmed live against the real installed dnsdist -- it rejects a
// leading "(?i)" outright as an "Invalid preceding regular
// expression"), which has no inline-flag syntax at all; a case-
// insensitive match would need an explicit "[Gg][Oo][Oo]..." expansion
// per letter, and real DNS resolver clients overwhelmingly send
// lowercase query names in practice, so that expansion is skipped as
// not worth the unreadability -- an upper/mixed-case query for one of
// these domains simply falls through to whatever this scope's normal
// (non-SafeSearch) resolution would have done, never a broken/blocked
// answer.
var safesearchRewrites = []safesearchRewrite{
	{`^(www\.)?google\.[a-z.]+\.$`, "forcesafesearch.google.com.", ""},
	{`^(www\.)?bing\.com\.$`, "strict.bing.com.", ""},
	{`^(www\.|m\.)?youtube\.com\.$`, "restrictmoderate.youtube.com.", "restrict.youtube.com."},
	{`^(www\.)?youtube-nocookie\.com\.$`, "restrictmoderate.youtube.com.", "restrict.youtube.com."},
	{`^(www\.)?duckduckgo\.com\.$`, "safe.duckduckgo.com.", ""},
}

func writeScopeOverrides(w func(string, ...any), overrides []ScopeOverride) error {
	ordered := append([]ScopeOverride(nil), overrides...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Source < ordered[j].Source })

	// --- 1. query-log/statistics participation tags -----------------
	// Non-terminal, safe to emit first: a later matching rule below can
	// still block/allow/route the same query normally, these only ever
	// affect whether internal/dnsanalytics.Writer retains/counts it
	// (see internal/dnsanalytics.Writer's own dnstap-tag parsing).
	for _, o := range ordered {
		if !o.QueryLoggingDisabled && !o.StatisticsDisabled {
			continue
		}
		matcher, err := o.matcherExpr()
		if err != nil {
			return err
		}
		if o.QueryLoggingDisabled {
			w(`addAction(%s, SetTagAction("apdns_querylog", "off"))`, matcher)
		}
		if o.StatisticsDisabled {
			w(`addAction(%s, SetTagAction("apdns_stats", "off"))`, matcher)
		}
	}
	w("")

	// --- 2. SafeSearch (terminal CNAME rewrite, must win over any
	// blocking rule below for these specific QNAMEs) ------------------
	for _, o := range ordered {
		if o.SafesearchMode != "moderate" && o.SafesearchMode != "strict" {
			continue
		}
		matcher, err := o.matcherExpr()
		if err != nil {
			return err
		}
		w("-- SafeSearch (%s): %s", o.SafesearchMode, o.Source)
		for _, rw := range safesearchRewrites {
			target := rw.moderateTarget
			if o.SafesearchMode == "strict" && rw.strictTarget != "" {
				target = rw.strictTarget
			}
			w("addAction(AndRule({%s, RegexRule(%s)}), SpoofCNAMEAction(%s))", matcher, luaString(rw.pattern), luaString(target))
		}
		w("")
	}

	// --- 3. scope-specific blocked-domain set ------------------------
	for _, o := range ordered {
		if len(o.BlockedDomains) == 0 {
			continue
		}
		matcher, err := o.matcherExpr()
		if err != nil {
			return err
		}
		action, err := blockingAction(o.BlockingResponseMode, o.CustomIPv4, o.CustomIPv6)
		if err != nil {
			return errf("scope override %q: %v", o.Source, err)
		}
		normalized := map[string]bool{}
		for _, d := range o.BlockedDomains {
			if n := normalizeDomain(d); n != "" {
				normalized[n] = true
			}
		}
		domains := make([]string, 0, len(normalized))
		for d := range normalized {
			domains = append(domains, d+".")
		}
		sort.Strings(domains)
		if len(domains) == 0 {
			continue
		}
		quoted := make([]string, len(domains))
		for i, d := range domains {
			quoted[i] = luaString(d)
		}
		w("-- scope-specific blocked domains: %s", o.Source)
		w(`addAction(AndRule({%s, SuffixMatchNodeRule({%s})}), SetTagAction("apdns_outcome", "blocked"))`, matcher, strings.Join(quoted, ", "))
		w("addAction(AndRule({%s, SuffixMatchNodeRule({%s})}), %s)", matcher, strings.Join(quoted, ", "), action)
		w("")
	}

	return nil
}

// writeScopePools emits one named pool per distinct (UpstreamProfileID,
// ECSEnabled) combination actually used by any override, then a
// terminal PoolAction per scope routing its own (non-domain-routed --
// domain routing, compiled separately, always wins for its own
// specific domains regardless of which scope asks) traffic there.
// Emitted AFTER domain routing and BEFORE the default pool, matching
// dnsdist's own "first matching terminal action wins" evaluation
// order.
func writeScopePools(w func(string, ...any), overrides []ScopeOverride) error {
	type poolKey struct {
		profileID string
		ecs       bool
	}
	pools := map[poolKey]*UpstreamProfile{}
	ordered := append([]ScopeOverride(nil), overrides...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Source < ordered[j].Source })
	for _, o := range ordered {
		if o.UpstreamProfileID == "" && !o.ECSEnabled {
			continue
		}
		profileID := o.UpstreamProfileID
		profile := o.UpstreamProfile
		if profileID == "" {
			// ECS-only override with no explicit upstream profile of its
			// own -- there is nothing here to route through a variant
			// pool with a real profile attached; a caller must always
			// supply UpstreamProfile alongside ECSEnabled (see
			// internal/policycompile), so this is a defensive error, not
			// a silently-ignored case.
			return errf("scope override %q has ecs_mode=enabled but no upstream profile to compile an ECS-aware pool from", o.Source)
		}
		if profile == nil || len(profile.Endpoints) == 0 {
			continue // the referenced profile has no endpoints (deleted/disabled since the scope was assigned) -- skip this one override rather than fail the whole compile, matching writeDomainRoutes' own stale-reference handling
		}
		key := poolKey{profileID, o.ECSEnabled}
		if _, exists := pools[key]; !exists {
			pools[key] = profile
		}
	}
	if len(pools) == 0 {
		return nil
	}
	w("-- per-scope upstream pools (upstream_profile_id / ecs_mode overrides)")
	poolName := func(k poolKey) string {
		n := "scope_" + sanitizePoolName(k.profileID)
		if k.ecs {
			n += "_ecs"
		}
		return n
	}
	keys := make([]poolKey, 0, len(pools))
	for k := range pools {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return poolName(keys[i]) < poolName(keys[j]) })
	for _, k := range keys {
		p := pools[k]
		name := poolName(k)
		for i, ep := range p.Endpoints {
			epName := fmt.Sprintf("%s%s_%d", UpstreamServerNamePrefix, name, i)
			line, err := endpointServerLineECS(ep, p.Transport, name, epName, k.ecs)
			if err != nil {
				return err
			}
			w(line)
		}
	}
	w("")
	for _, o := range ordered {
		if o.UpstreamProfileID == "" && !o.ECSEnabled {
			continue
		}
		if o.UpstreamProfileID == "" {
			continue
		}
		key := poolKey{o.UpstreamProfileID, o.ECSEnabled}
		if _, ok := pools[key]; !ok {
			continue
		}
		matcher, err := o.matcherExpr()
		if err != nil {
			return err
		}
		w("addAction(%s, PoolAction(%s))", matcher, luaString(poolName(key)))
	}
	w("")
	return nil
}

// endpointServerLineECS mirrors endpointServerLine but additionally
// compiles useClientSubnet -- kept as a separate small wrapper rather
// than adding an ecs bool parameter to the widely-called
// endpointServerLine (every other caller wants dnsdist's real default
// of no ECS, matching V1.1.1's own behavior exactly; only a scope that
// explicitly opted in via ecs_mode="enabled" should ever get this).
func endpointServerLineECS(ep UpstreamEndpoint, transport, pool, name string, ecs bool) (string, error) {
	line, err := endpointServerLine(ep, transport, pool, name)
	if err != nil {
		return "", err
	}
	if !ecs {
		return line, nil
	}
	// endpointServerLine always emits `newServer({...})` -- splice
	// useClientSubnet=true into the same kwargs table rather than
	// duplicating its whole kwargs-building switch here.
	const suffix = "})"
	if !strings.HasSuffix(line, suffix) {
		return "", errf("internal error: unexpected newServer() line shape for ECS splice: %q", line)
	}
	return strings.TrimSuffix(line, suffix) + ", useClientSubnet=true})", nil
}
