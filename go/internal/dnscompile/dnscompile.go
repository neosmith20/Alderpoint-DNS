// Package dnscompile is the native Go DNS runtime compiler: it turns
// Go-owned control-plane state (Local DNS, custom rules, blocklists,
// upstream profiles, DNS transport settings) into real BIND named.conf
// and dnsdist Lua configuration text, matching the architecture already
// proven live in Python's app/v2/dnsdist_policy_runtime.py and
// app/v2/bind_gen.py (read directly, not guessed): dnsdist is the
// primary policy-enforcement layer (blocking, local DNS, upstream
// routing, packet cache); BIND is wired underneath it purely as a
// shared recursive-cache backend for the plain-transport default
// upstream, exactly matching the locked hot path in
// docs/v2/architecture-map.md ("client -> dnsdist packet cache ->
// compiled policy/routing -> BIND RAM recursive cache -> upstream only
// on miss").
//
// Deliberately narrower than Python's real compiler, disclosed rather
// than hidden, matching where this migration's own policy engine
// currently is (see internal/policy's own doc comment: no per-network
// "effective policy" resolution engine exists yet):
//
//   - Global scope only. One compiled policy applies to every client --
//     not per-network/group/client differentiated the way Python's real
//     ClientPolicyBinding compiler is. SafeSearch and ECS are not
//     compiled here (internal/policy stores those fields, but nothing
//     in Go resolves them into an effective per-client value yet).
//   - Domain routing IS compiled (added 2026-08-27), but at this same
//     global-only scope: a single flat list of exact/suffix -> upstream
//     profile rules applied to every client, not Python's real
//     per-network ClientPolicyBinding.domain_routes (see
//     internal/domainrouting's own doc comment for the exact narrowing).
//   - regex_block/regex_allow custom rules ARE compiled (dnsdist's real
//     RegexRule), but domains are only ever literal-matched, never
//     wildcarded beyond what SuffixMatchNodeRule already does.
//   - DoT and DoH transports are compiled (reusing the appliance's own
//     management TLS cert/key, the same real pattern Python's
//     DotConfig/DohConfig already use); DoQ/DoH3/DNSCrypt are not --
//     each needs its own listener wiring this pass didn't have scope
//     for, and DNSCrypt specifically has no Go-native secrets store yet
//     to hold its provider identity (same disclosed gap as elsewhere).
//   - No multi-context BIND allocation (Python's allocate_bind_contexts
//     for distinct upstream selections/domain routes) -- one BIND
//     context only, since there is only ever one default profile here.
package dnscompile

import (
	"fmt"
	"sort"
	"strings"
)

// --- inputs -----------------------------------------------------------

type LocalDNSRecord struct {
	Name       string
	RecordType string // A, AAAA, CNAME (PTR intentionally skipped, matching Python's own documented gap)
	Value      string
	TTL        int
}

type UpstreamEndpoint struct {
	Address     string
	TLSHostname string // "" = none
	DohPath     string // "" = default /dns-query
}

type UpstreamProfile struct {
	Transport string // plain, dot, doh
	Strategy  string // ordered, failover, load_balanced
	Endpoints []UpstreamEndpoint
}

// DomainRoute is one resolved domain-routing rule: a domain matched
// exactly or by suffix, routed to a specific upstream profile instead of
// the default pool. ProfileID is used only for the generated pool's
// name (so two rules pointing at the same profile share one pool and
// one set of newServer() calls) -- Profile itself carries the actual
// endpoints/transport/strategy the caller already resolved (this
// package never looks anything up by ID itself, matching every other
// input here being a pure value, not a reference).
type DomainRoute struct {
	MatchKind string // "exact" | "suffix"
	Domain    string
	ProfileID string
	Profile   UpstreamProfile
}

// CustomRule mirrors internal/customrules.Rule's own shape (this
// package never imports that package directly, to keep dnscompile a
// pure, dependency-free compiler its own tests can exercise without a
// database).
type CustomRule struct {
	RuleType      string // block, allow, regex_block, regex_allow, rewrite
	Pattern       string
	RewriteTarget string // only for rewrite
}

type TransportSettings struct {
	DotEnabled bool
	DotPort    int
	DohEnabled bool
	DohPort    int
	DohPath    string // "" = /dns-query
}

// Input is every piece of already-loaded, already-validated Go state
// this compiler needs. Building it (querying SQLite, applying defaults)
// is the caller's job -- this package does no I/O and no DB access, so
// its own tests can prove "same input -> byte-identical output"
// directly, the same determinism guarantee Python's own generators make.
type Input struct {
	ListenAddress string // dnsdist's own listener, e.g. "0.0.0.0:53"

	// DefaultProfile is the sole managed upstream. Nil (or Transport ==
	// "" ) means no managed upstream is enabled -- both BIND and
	// dnsdist's default pool fall back to native/root-hints recursion,
	// matching the locked "Zero Managed Upstreams" product decision
	// Python's own bind_gen.py documents.
	DefaultProfile *UpstreamProfile

	LocalDNSRecords []LocalDNSRecord

	// DomainRoutes: a flat, global list of exact/suffix domain-routing
	// rules, each sending matching queries to a different upstream pool
	// instead of the default one. Terminal and higher precedence than
	// the default pool, lower than local DNS/rewrites/blocking (matching
	// Python's own real precedence in dnsdist_policy_runtime.py: local
	// DNS/rewrites/regex-allow/blocking always win first). Most-specific
	// match wins regardless of input order -- see writeDomainRoutes.
	DomainRoutes []DomainRoute

	// BlockedDomains: literal domains to block (from enabled blocklist
	// subscriptions' compiled domain lists plus rule_type=="block"
	// custom rules). AllowedDomains always wins over a same-named entry
	// here, applied by the caller before this struct is built (set
	// difference, matching Python's own "explicit allow always
	// overrides a block" precedence) -- this package does not
	// re-derive that itself.
	BlockedDomains []string
	RegexBlock     []string // rule_type=="regex_block" patterns (dnsdist RegexRule syntax)
	RegexAllow     []string // rule_type=="regex_allow" -- always wins, evaluated first
	RewriteRules   []CustomRule

	// BlockingResponseMode: "nxdomain" (default), "refused", "null_ip",
	// or "custom_ip" (uses CustomIPv4/CustomIPv6). Matches
	// policy_layers' global row -- see internal/policy.Layer.
	BlockingResponseMode string
	CustomIPv4           string
	CustomIPv6           string

	Transports  TransportSettings
	TLSCertPath string // the appliance's own management TLS cert -- reused for DoT/DoH, never Python's
	TLSKeyPath  string

	CacheMaxEntries    int
	CacheMaxTTLSeconds int

	// BindBackendAddress is where dnsdist's default pool forwards
	// plain-transport traffic -- BIND's own PROXYv2 listener address
	// (see NamedConfInput.ProxyPort). Empty means route direct to the
	// upstream endpoints instead of through BIND (only used by tests
	// that don't want to also stand up a BIND instance).
	BindBackendAddress string

}

// HealthMarkerDomain/IP are a fixed, compile-time-constant marker record
// -- never user-controlled -- compiled into every dnsdist config ahead
// of every other rule (see CompileDnsdist). internal/hostagentd's own
// promotion health check queries for exactly this name after a
// (re)start to prove the *just-promoted* config is actually the one
// live and answering, not merely that the old dnsdist process is still
// up. 203.0.113.0/24 is TEST-NET-3 (RFC 5737): reserved for
// documentation/testing, guaranteed never a real routable answer.
const (
	HealthMarkerDomain = "health-marker.apdns-go-dns-runtime.internal"
	HealthMarkerIP     = "203.0.113.77"
)

type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }
func errf(format string, args ...any) error {
	return &Error{fmt.Sprintf(format, args...)}
}

func luaString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// --- dnsdist ------------------------------------------------------------

// CompileDnsdist renders a complete dnsdist Lua config. Deterministic:
// every set-derived piece of input is sorted before it's emitted, so
// two calls with the same Input in different slice orders produce
// byte-identical output.
func CompileDnsdist(in Input) (string, error) {
	if in.ListenAddress == "" {
		return "", errf("listen address is required")
	}

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...); b.WriteByte('\n') }

	w("-- Generated by internal/dnscompile -- Go-native DNS runtime compiler.")
	w("-- Do not hand-edit; regenerate from the effective Go control-plane state.")
	w("setLocal(%s)", luaString(in.ListenAddress))
	w("")

	if in.Transports.DotEnabled {
		if in.TLSCertPath == "" || in.TLSKeyPath == "" {
			return "", errf("DoT is enabled but no TLS cert/key path is configured")
		}
		host := hostOf(in.ListenAddress)
		w(`addTLSLocal(%s, {%s}, {%s}, {`, luaString(fmt.Sprintf("%s:%d", host, in.Transports.DotPort)), luaString(in.TLSCertPath), luaString(in.TLSKeyPath))
		w("  reusePort=true,")
		w(`  minTLSVersion="tls1.2",`)
		w(`  ciphers="HIGH:!aNULL:!MD5:!RC4"`)
		w("})")
		w("")
	}
	if in.Transports.DohEnabled {
		if in.TLSCertPath == "" || in.TLSKeyPath == "" {
			return "", errf("DoH is enabled but no TLS cert/key path is configured")
		}
		host := hostOf(in.ListenAddress)
		path := in.Transports.DohPath
		if path == "" {
			path = "/dns-query"
		}
		w(`addDOHLocal(%s, {%s}, {%s}, {%s}, {`, luaString(fmt.Sprintf("%s:%d", host, in.Transports.DohPort)), luaString(in.TLSCertPath), luaString(in.TLSKeyPath), luaString(path))
		w("  reusePort=true,")
		w(`  minTLSVersion="tls1.2",`)
		w(`  ciphers="HIGH:!aNULL:!MD5:!RC4"`)
		w("})")
		w("")
	}

	w("-- health-check marker (proves this exact promotion is live, not a stale process)")
	w("addAction(QNameRule(%s), SpoofAction({%s}))", luaString(HealthMarkerDomain+"."), luaString(HealthMarkerIP))
	w("")

	// Local DNS records: appliance-wide, highest precedence, terminal.
	if len(in.LocalDNSRecords) > 0 {
		w("-- local DNS records (appliance-wide, highest precedence)")
		recs := append([]LocalDNSRecord(nil), in.LocalDNSRecords...)
		sort.Slice(recs, func(i, j int) bool {
			if recs[i].Name != recs[j].Name {
				return recs[i].Name < recs[j].Name
			}
			return recs[i].RecordType < recs[j].RecordType
		})
		for _, r := range recs {
			name := normalizeDomain(r.Name)
			matcher := fmt.Sprintf("QNameRule(%s)", luaString(name+"."))
			switch r.RecordType {
			case "A", "AAAA":
				w("addAction(%s, SpoofAction({%s}))", matcher, luaString(r.Value))
			case "CNAME":
				target := strings.TrimSuffix(r.Value, ".") + "."
				w("addAction(%s, SpoofCNAMEAction(%s))", matcher, luaString(target))
			case "PTR":
				continue // not compiled, matching Python's own documented gap
			default:
				return "", errf("unsupported local DNS record_type: %q", r.RecordType)
			}
		}
		w("")
	}

	// Rewrite custom rules -- same shape as a local CNAME record.
	if len(in.RewriteRules) > 0 {
		w("-- custom rewrite rules")
		rules := append([]CustomRule(nil), in.RewriteRules...)
		sort.Slice(rules, func(i, j int) bool { return rules[i].Pattern < rules[j].Pattern })
		for _, r := range rules {
			if r.RewriteTarget == "" {
				return "", errf("rewrite rule for %q has no target", r.Pattern)
			}
			matcher := fmt.Sprintf("QNameRule(%s)", luaString(normalizeDomain(r.Pattern)+"."))
			target := strings.TrimSuffix(r.RewriteTarget, ".") + "."
			w("addAction(%s, SpoofCNAMEAction(%s))", matcher, luaString(target))
		}
		w("")
	}

	// Regex-allow: terminal AllowAction, evaluated before every block
	// rule below so it always wins, real dnsdist behavior (AllowAction
	// stops further rule processing and lets the query through) rather
	// than something this package has to reimplement by set-difference
	// the way literal-domain allow/block already is.
	if len(in.RegexAllow) > 0 {
		w("-- regex allow rules (always win over a block rule below)")
		patterns := append([]string(nil), in.RegexAllow...)
		sort.Strings(patterns)
		for _, p := range patterns {
			w("addAction(RegexRule(%s), AllowAction())", luaString(p))
		}
		w("")
	}

	blockAction, err := blockingAction(in.BlockingResponseMode, in.CustomIPv4, in.CustomIPv6)
	if err != nil {
		return "", err
	}

	if len(in.RegexBlock) > 0 {
		w("-- regex block rules")
		patterns := append([]string(nil), in.RegexBlock...)
		sort.Strings(patterns)
		for _, p := range patterns {
			w("addAction(RegexRule(%s), %s)", luaString(p), blockAction)
		}
		w("")
	}

	if len(in.BlockedDomains) > 0 {
		normalized := map[string]bool{}
		for _, d := range in.BlockedDomains {
			n := normalizeDomain(d)
			if n != "" {
				normalized[n] = true
			}
		}
		domains := make([]string, 0, len(normalized))
		for d := range normalized {
			domains = append(domains, d+".")
		}
		sort.Strings(domains)
		if len(domains) > 0 {
			w("-- blocked domains (blocklist subscriptions + block-type custom rules)")
			quoted := make([]string, len(domains))
			for i, d := range domains {
				quoted[i] = luaString(d)
			}
			w("addAction(SuffixMatchNodeRule({%s}), %s)", strings.Join(quoted, ", "), blockAction)
			w("")
		}
	}

	// Domain routing: terminal PoolAction per rule, most-specific match
	// first -- must be emitted before the default pool's own servers so
	// a route's pool name can never collide with the unnamed default
	// pool, but ordering relative to "default upstream pool" below
	// doesn't affect precedence at runtime (there is no catch-all
	// addAction for the default pool -- dnsdist sends anything no rule
	// matched to it automatically).
	if len(in.DomainRoutes) > 0 {
		if err := writeDomainRoutes(w, in.DomainRoutes); err != nil {
			return "", err
		}
	}

	// Default pool: the sole managed upstream (or BIND/native-recursion
	// fallback if none).
	w("-- default upstream pool")
	if err := writeDefaultPool(w, in); err != nil {
		return "", err
	}

	if in.CacheMaxEntries > 0 {
		w("-- packet cache (dnsdist RAM hot-path tier)")
		w("pc_default = newPacketCache(%d, {maxTTL=%d})", in.CacheMaxEntries, cacheTTLOrDefault(in.CacheMaxTTLSeconds))
		w(`getPool(""):setCache(pc_default)`)
		w("")
	}

	return b.String(), nil
}

func cacheTTLOrDefault(v int) int {
	if v <= 0 {
		return 86400
	}
	return v
}

func hostOf(listenAddress string) string {
	if i := strings.LastIndex(listenAddress, ":"); i >= 0 {
		return listenAddress[:i]
	}
	return listenAddress
}

func blockingAction(mode, customIPv4, customIPv6 string) (string, error) {
	switch mode {
	case "", "nxdomain":
		return "RCodeAction(DNSRCode.NXDOMAIN)", nil
	case "refused":
		return "RCodeAction(DNSRCode.REFUSED)", nil
	case "null_ip":
		return `SpoofAction({"0.0.0.0", "::"})`, nil
	case "custom_ip":
		var addrs []string
		if customIPv4 != "" {
			addrs = append(addrs, luaString(customIPv4))
		}
		if customIPv6 != "" {
			addrs = append(addrs, luaString(customIPv6))
		}
		if len(addrs) == 0 {
			return "", errf("blocking_response_mode is custom_ip but no custom IP is configured")
		}
		return fmt.Sprintf("SpoofAction({%s})", strings.Join(addrs, ", ")), nil
	default:
		return "", errf("unsupported blocking_response_mode: %q", mode)
	}
}

// endpointServerLine renders one newServer({...}) call for a given
// endpoint/transport/pool -- shared between the default pool
// (pool="") and every domain-routing pool, so DoT/DoH kwargs handling
// (including the "DoH needs tls_hostname" refusal) is defined exactly
// once.
func endpointServerLine(ep UpstreamEndpoint, transport, pool string) (string, error) {
	kwargs := fmt.Sprintf("address=%s, pool=%s", luaString(ep.Address), luaString(pool))
	switch transport {
	case "dot":
		kwargs += `, tls="openssl"`
		if ep.TLSHostname != "" {
			kwargs += fmt.Sprintf(", subjectName=%s", luaString(ep.TLSHostname))
		}
	case "doh":
		if ep.TLSHostname == "" {
			return "", errf("DoH endpoint %q has no tls_hostname -- refusing to generate an unverifiable DoH backend", ep.Address)
		}
		path := ep.DohPath
		if path == "" {
			path = "/dns-query"
		}
		kwargs += fmt.Sprintf(`, tls="openssl", dohPath=%s, subjectName=%s`, luaString(path), luaString(ep.TLSHostname))
	case "plain":
		// no extra kwargs
	default:
		return "", errf("unsupported upstream transport: %q", transport)
	}
	return fmt.Sprintf("newServer({%s})", kwargs), nil
}

// writeDomainRoutes emits one named pool + terminal routing rule per
// domain-routing rule, most-specific match first (deterministic
// regardless of input order): longest normalized domain first, tied-
// broken by the domain string itself -- matches Python's own real
// precedence fix in dnsdist_policy_runtime.py/dnsdist_gen.py (a suffix
// rule for "a.b.example." must win over one for "example." when both
// match). Two rules resolving to the same profile share one pool name
// and get their servers declared once each they're referenced (a small,
// harmless duplication if reused, never a correctness issue -- dnsdist
// happily accepts repeated identical newServer() calls into the same
// named pool).
func writeDomainRoutes(w func(string, ...any), routes []DomainRoute) error {
	type route struct {
		matchKind, domain, profileID string
		profile                      UpstreamProfile
	}
	normalized := make(map[string]route, len(routes))
	for _, r := range routes {
		if r.MatchKind != "exact" && r.MatchKind != "suffix" {
			return errf("domain route %q: unsupported match_kind %q (must be exact or suffix)", r.Domain, r.MatchKind)
		}
		domain := normalizeDomain(r.Domain)
		if domain == "" {
			return errf("domain route has an empty domain")
		}
		key := r.MatchKind + ":" + domain
		if existing, ok := normalized[key]; ok && existing.profileID != r.ProfileID {
			return errf("conflicting domain routing rule for %s %q: both %q and %q were specified", r.MatchKind, domain, existing.profileID, r.ProfileID)
		}
		normalized[key] = route{matchKind: r.MatchKind, domain: domain, profileID: r.ProfileID, profile: r.Profile}
	}

	ordered := make([]route, 0, len(normalized))
	for _, r := range normalized {
		ordered = append(ordered, r)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if len(ordered[i].domain) != len(ordered[j].domain) {
			return len(ordered[i].domain) > len(ordered[j].domain) // longer (more specific) first
		}
		if ordered[i].domain != ordered[j].domain {
			return ordered[i].domain < ordered[j].domain
		}
		return ordered[i].matchKind < ordered[j].matchKind
	})

	w("-- domain-specific routing (most-specific match wins, terminal)")
	for _, r := range ordered {
		if len(r.profile.Endpoints) == 0 {
			return errf("domain route %q: upstream profile %q has no endpoints", r.domain, r.profileID)
		}
		poolName := "route_" + sanitizePoolName(r.profileID)
		for _, ep := range r.profile.Endpoints {
			line, err := endpointServerLine(ep, r.profile.Transport, poolName)
			if err != nil {
				return err
			}
			w("%s", line)
		}
		if policy, ok := map[string]string{"ordered": "firstAvailable", "failover": "firstAvailable", "load_balanced": "wrandom"}[strategyOrDefault(&r.profile)]; ok {
			w(`setPoolServerPolicy(%s, %s)`, policy, luaString(poolName))
		}
		trigger := r.domain + "."
		matcher := fmt.Sprintf("QNameRule(%s)", luaString(trigger))
		if r.matchKind == "suffix" {
			matcher = fmt.Sprintf("SuffixMatchNodeRule({%s})", luaString(trigger))
		}
		w("addAction(%s, PoolAction(%s))", matcher, luaString(poolName))
	}
	w("")
	return nil
}

// sanitizePoolName makes a profile ID safe as a bare Lua-string pool
// name fragment -- profile IDs are operator-chosen slugs (see
// internal/upstreams), not free text, but this is defense in depth, not
// the only validation.
func sanitizePoolName(id string) string {
	var b strings.Builder
	for _, r := range id {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func writeDefaultPool(w func(string, ...any), in Input) error {
	profile := in.DefaultProfile
	hasManaged := profile != nil && len(profile.Endpoints) > 0
	switch {
	case hasManaged && profile.Transport == "plain" && in.BindBackendAddress != "":
		w("-- ordinary recursion: routed through the BIND recursive-cache backend")
		w(`newServer({address=%s, pool="", useProxyProtocol=true})`, luaString(in.BindBackendAddress))
	case hasManaged:
		for _, ep := range profile.Endpoints {
			line, err := endpointServerLine(ep, profile.Transport, "")
			if err != nil {
				return err
			}
			w("%s", line)
		}
	case in.BindBackendAddress != "":
		// No managed upstream at all -- still route through BIND, which
		// with zero forwarders configured performs genuine iterative
		// root-hints recursion (BIND's real unmodified default
		// behavior), never a silently substituted third-party resolver,
		// and never a serverless pool that would make dnsdist hang.
		w("-- no managed upstream: routed through BIND for native root-hints recursion")
		w(`newServer({address=%s, pool="", useProxyProtocol=true})`, luaString(in.BindBackendAddress))
	default:
		return errf("no managed upstream and no BIND backend configured -- refusing to generate a serverless pool")
	}

	policy := map[string]string{"ordered": "firstAvailable", "failover": "firstAvailable", "load_balanced": "wrandom"}[strategyOrDefault(profile)]
	if policy != "" {
		w(`setPoolServerPolicy(%s, "")`, policy)
	}
	return nil
}

func strategyOrDefault(p *UpstreamProfile) string {
	if p == nil || p.Strategy == "" {
		return "ordered"
	}
	return p.Strategy
}

// --- BIND ---------------------------------------------------------------

type NamedConfInput struct {
	Forwarders  []string // "host:port"; empty = native root-hints recursion
	TLSHostname string   // "" = plain forwarding
	PlainPort   int
	ProxyPort   int
	StatsPort   int
	RNDCPort    int    // 0 = no rndc controls block
	RNDCKey     string // base64 HMAC secret, required if RNDCPort != 0
	Directory   string
	LogPath     string
}

// CompileNamedConf renders one self-contained BIND named.conf -- a pure
// recursive-cache backend for the default upstream profile's
// plain/DoT-transport endpoints, matching bind_gen.py's own single-
// context render_named_conf shape (no RPZ zone: real per-domain
// blocking enforcement lives entirely in the dnsdist config compiled
// above, matching the real, current Python architecture documented in
// dnsdist_policy_runtime.py's own module doc comment).
func CompileNamedConf(in NamedConfInput) (string, error) {
	if in.PlainPort == 0 || in.ProxyPort == 0 {
		return "", errf("PlainPort and ProxyPort are required")
	}
	if in.PlainPort == in.ProxyPort {
		return "", errf("PlainPort and ProxyPort must differ")
	}
	if (in.RNDCPort != 0) != (in.RNDCKey != "") {
		return "", errf("RNDCPort and RNDCKey must be given together")
	}

	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...); b.WriteByte('\n') }

	var tlsBlock, forwardLines []string
	if len(in.Forwarders) > 0 {
		hosts := make([]string, len(in.Forwarders))
		ports := make([]string, len(in.Forwarders))
		for i, f := range in.Forwarders {
			idx := strings.LastIndex(f, ":")
			if idx < 0 {
				return "", errf("invalid forwarder address: %q", f)
			}
			hosts[i], ports[i] = f[:idx], f[idx+1:]
		}
		var clause string
		if in.TLSHostname != "" {
			tlsBlock = []string{
				"tls dot_upstream {",
				fmt.Sprintf("\tremote-hostname %q;", in.TLSHostname),
				"};",
				"",
			}
			parts := make([]string, len(hosts))
			for i := range hosts {
				parts[i] = fmt.Sprintf("%s port %s tls dot_upstream", hosts[i], ports[i])
			}
			clause = strings.Join(parts, "; ")
		} else {
			parts := make([]string, len(hosts))
			for i := range hosts {
				parts[i] = fmt.Sprintf("%s port %s", hosts[i], ports[i])
			}
			clause = strings.Join(parts, "; ")
		}
		forwardLines = []string{"\tforward only;", "\tforwarders { " + clause + "; };"}
	}

	w("// Generated by internal/dnscompile -- Go-native BIND recursive-cache backend.")
	w("// Do not hand-edit; regenerate from the effective Go control-plane state.")
	for _, l := range tlsBlock {
		w("%s", l)
	}
	w(`acl "apdns_go_clients" {`)
	for _, net := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"} {
		w("\t%s;", net)
	}
	w("};")
	w("")
	w("options {")
	w("\tdirectory %q;", in.Directory)
	w("\tlisten-on port %d { 127.0.0.1; };", in.PlainPort)
	w("\tlisten-on port %d proxy plain { 127.0.0.1; };", in.ProxyPort)
	w("\tlisten-on-v6 port %d { ::1; };", in.PlainPort)
	w("\tallow-proxy { 127.0.0.1; };")
	w("\tallow-proxy-on { 127.0.0.1; };")
	w("\tallow-query { \"apdns_go_clients\"; };")
	w("\tallow-query-cache { \"apdns_go_clients\"; };")
	w("\tallow-recursion { \"apdns_go_clients\"; };")
	w("\trecursion yes;")
	for _, l := range forwardLines {
		w("%s", l)
	}
	w("\tdnssec-validation auto;")
	w("\tauth-nxdomain no;")
	w("\tminimal-responses yes;")
	w("\tempty-zones-enable yes;")
	w("\tversion \"not disclosed\";")
	w("\tquerylog no;")
	w("\tstatistics-file %q;", in.Directory+"/named.stats")
	w("\tmemstatistics-file %q;", in.Directory+"/named.memstats")
	w("};")
	w("")
	w("statistics-channels {")
	w("\tinet 127.0.0.1 port %d allow { 127.0.0.1; };", in.StatsPort)
	w("};")
	w("")
	if in.RNDCPort != 0 {
		w(`key "apdns-go-rndc-key" {`)
		w("\talgorithm hmac-sha256;")
		w("\tsecret %q;", in.RNDCKey)
		w("};")
		w("")
		w("controls {")
		w("\tinet 127.0.0.1 port %d allow { 127.0.0.1; } keys { \"apdns-go-rndc-key\"; };", in.RNDCPort)
		w("};")
		w("")
	}
	w("logging {")
	w("\tchannel apdns_go_default {")
	w("\t\tfile %q versions 5 size 10m;", in.LogPath)
	w("\t\tseverity info;")
	w("\t\tprint-time yes;")
	w("\t\tprint-severity yes;")
	w("\t\tprint-category yes;")
	w("\t};")
	w("\tcategory default { apdns_go_default; };")
	w("\tcategory general { apdns_go_default; };")
	w("\tcategory security { apdns_go_default; };")
	w("};")

	return b.String(), nil
}
