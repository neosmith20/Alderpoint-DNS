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
//   - DoT, DoH, and DoQ transports are compiled (reusing the
//     appliance's own management TLS cert/key, the same real pattern
//     Python's DotConfig/DohConfig already use; DoQ added 2026-08-27
//     for Strong ClientID's DoT/DoQ SNI identity). DoH3/DNSCrypt are
//     not -- DNSCrypt specifically has no Go-native secrets store yet
//     to hold its provider identity (same disclosed gap as elsewhere).
//   - Strong ClientID (added 2026-08-27): every active identity of
//     every enabled managed client is compiled to a real
//     HTTPPathRule (DoH, full canonical hex path) and SNIRule (DoT/DoQ,
//     internal/clientid's lossless DNS-label-safe encoding), each
//     tagging the query; each client's own explicit domain block/allow
//     overrides are compiled ahead of the global blocklist/regex chain
//     -- see the Input.ClientIdentities/ClientOverrides field doc
//     comment and writeClientRules for the exact precedence/isolation
//     guarantee.
//   - No multi-context BIND allocation (Python's allocate_bind_contexts
//     for distinct upstream selections/domain routes) -- one BIND
//     context only, since there is only ever one default profile here.
package dnscompile

import (
	"fmt"
	"sort"
	"strings"

	"alderpointdns/go-controlplane/internal/clientid"
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
	DoqEnabled bool
	DoqPort    int
}

// ClientIdentity is one active Strong ClientID binding: a stable
// per-managed-client tag value plus one of that client's canonical
// hex identities (internal/clientid) -- a client with multiple active
// ClientIDs (multiple DoH/DoT/DoQ identities) appears as multiple
// entries sharing the same ClientKey, each compiled to its own
// HTTPPathRule/SNIRule -> SetTagAction pair, so any of that client's
// identities tags the query the same way.
type ClientIdentity struct {
	ClientKey string
	Hex       string
}

// ClientOverride is one explicit per-client domain block/allow entry
// (internal/clients.DomainOverride), keyed by the same ClientKey a
// ClientIdentity above sets via SetTagAction -- see writeClientRules
// for the compiled precedence (explicit deny > explicit allow >
// default policy).
type ClientOverride struct {
	ClientKey string
	Kind      string // "block" | "allow"
	Domain    string
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

	// ClientIdentities/ClientOverrides: Strong ClientID identity binding
	// (DoH path / DoT-DoQ SNI -> per-client tag) and each tagged
	// client's own explicit domain block/allow list. Compiled
	// immediately after the health marker -- ahead of every other rule
	// in this function, including the global blocklist/regex chain --
	// so a client's explicit deny/allow always outranks the default
	// (global) policy, and isolation is structural: a rule only ever
	// matches on one exact identity's own path/SNI or the tag only that
	// match sets, so an unrelated client's query can never carry
	// another client's tag or trigger another client's override. See
	// writeClientRules.
	ClientIdentities []ClientIdentity
	ClientOverrides  []ClientOverride

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

	// DnstapSocketPath: when non-empty, every real client response is
	// logged as a dnstap message to a FrameStreamUnixLogger at this
	// path (see internal/dnsanalytics.Writer, the real receiver on the
	// other end). Fully asynchronous and best-effort on dnsdist's side
	// -- a missing/unreachable/slow receiver never delays or drops a
	// DNS answer, only analytics completeness. Empty (the default in
	// every existing test) compiles no logging at all, matching prior
	// behavior exactly.
	//
	// Each query is tagged "apdns_outcome" = "blocked" by the exact
	// same rule that decided to block it (see blockingAction call
	// sites below), defaulting to "allowed" otherwise; the response
	// logger reads that tag and carries it as the dnstap message's
	// Extra field, so the receiver learns dnsdist's own real
	// disposition rather than inferring "blocked" from rcode alone
	// (a genuine NXDOMAIN for a non-blocked domain must never be
	// miscounted as a block).
	DnstapSocketPath string
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
		// dnsdist only ever answers HTTP requests on paths explicitly
		// registered here (a request on any other path gets a plain 404
		// before any addAction rule -- including HTTPPathRule -- ever
		// runs, confirmed directly against the real installed dnsdist).
		// Every active ClientID's own DoH path (internal/clientid.
		// DoHPath, full canonical hex) must therefore be registered as
		// a real endpoint on this SAME listener, not just matched by a
		// rule -- HTTPPathRule below is what then tells apart WHICH of
		// these registered paths a request landed on, to tag it
		// correctly.
		paths := map[string]bool{path: true}
		for _, id := range in.ClientIdentities {
			if err := clientid.ValidateHex(id.Hex); err != nil {
				return "", errf("client %q has an invalid Strong ClientID value: %v", id.ClientKey, err)
			}
			paths[clientid.DoHPath(id.Hex)] = true
		}
		orderedPaths := make([]string, 0, len(paths))
		for p := range paths {
			orderedPaths = append(orderedPaths, p)
		}
		sort.Strings(orderedPaths)
		quotedPaths := make([]string, len(orderedPaths))
		for i, p := range orderedPaths {
			quotedPaths[i] = luaString(p)
		}
		w(`addDOHLocal(%s, {%s}, {%s}, {%s}, {`, luaString(fmt.Sprintf("%s:%d", host, in.Transports.DohPort)), luaString(in.TLSCertPath), luaString(in.TLSKeyPath), strings.Join(quotedPaths, ", "))
		w("  reusePort=true,")
		w(`  minTLSVersion="tls1.2",`)
		w(`  ciphers="HIGH:!aNULL:!MD5:!RC4"`)
		w("})")
		w("")
	}
	if in.Transports.DoqEnabled {
		if in.TLSCertPath == "" || in.TLSKeyPath == "" {
			return "", errf("DoQ is enabled but no TLS cert/key path is configured")
		}
		host := hostOf(in.ListenAddress)
		w(`addDOQLocal(%s, {%s}, {%s}, {`, luaString(fmt.Sprintf("%s:%d", host, in.Transports.DoqPort)), luaString(in.TLSCertPath), luaString(in.TLSKeyPath))
		w("  reusePort=true,")
		w(`  minTLSVersion="tls1.2"`)
		w("})")
		w("")
	}

	w("-- health-check marker (proves this exact promotion is live, not a stale process)")
	w("addAction(QNameRule(%s), SpoofAction({%s}))", luaString(HealthMarkerDomain+"."), luaString(HealthMarkerIP))
	w("")

	// Default every query to "allowed" for dnstap analytics tagging
	// before any rule below can mark it "blocked" -- SetTagAction is
	// non-terminal (dnsdist keeps evaluating rules after it), so this
	// is always overwritten by the matching addAction just ahead of
	// each real blocking action below. A no-op when DnstapSocketPath
	// is unset (still compiled either way -- cheap, and keeps this
	// function's output independent of whether logging is wired up,
	// same as every other unconditionally-emitted marker rule here).
	w(`addAction(AllRule(), SetTagAction("apdns_outcome", "allowed"))`)
	w("")

	// Computed early (not just before the global blocklist section
	// below, where Python's own shape would put it) because Strong
	// ClientID's own per-client deny rules, compiled next, use this
	// exact same configured blocking response -- an operator who sets
	// blocking_response_mode="refused" gets REFUSED from both the
	// global blocklist AND a per-client explicit deny, never two
	// different behaviors for what's conceptually the same "blocked"
	// outcome.
	blockAction, err := blockingAction(in.BlockingResponseMode, in.CustomIPv4, in.CustomIPv6)
	if err != nil {
		return "", err
	}

	// Strong ClientID: identity binding + per-client explicit deny/allow,
	// compiled ahead of every other rule below (including the global
	// blocklist/regex chain) -- see the Input.ClientIdentities/
	// ClientOverrides field doc comment for the precedence/isolation
	// reasoning.
	if len(in.ClientIdentities) > 0 || len(in.ClientOverrides) > 0 {
		if err := writeClientRules(w, in.ClientIdentities, in.ClientOverrides, blockAction); err != nil {
			return "", err
		}
	}

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

	if len(in.RegexBlock) > 0 {
		w("-- regex block rules")
		patterns := append([]string(nil), in.RegexBlock...)
		sort.Strings(patterns)
		for _, p := range patterns {
			w(`addAction(RegexRule(%s), SetTagAction("apdns_outcome", "blocked"))`, luaString(p))
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
			w(`addAction(SuffixMatchNodeRule({%s}), SetTagAction("apdns_outcome", "blocked"))`, strings.Join(quoted, ", "))
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

	if in.DnstapSocketPath != "" {
		w("-- dnstap query-event logging (see internal/dnsanalytics.Writer, the receiver)")
		w("apdnsDnstapLogger = newFrameStreamUnixLogger(%s)", luaString(in.DnstapSocketPath))
		w("addResponseAction(AllRule(), DnstapLogResponseAction(%s, apdnsDnstapLogger, function(dr, dm)", luaString("apdns"))
		w(`  local outcome = dr:getTag("apdns_outcome")`)
		w(`  if outcome == nil then outcome = "allowed" end`)
		w("  dm:setExtra(outcome)")
		w("end))")
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

// clientTag names the dnsdist tag key this package sets/
// checks for Strong ClientID -- a fixed, compile-time constant, never
// derived from any operator input, so it can never collide with a tag
// name some other rule might use.
const clientTag = "apdns_client"

// writeClientRules compiles Strong ClientID's two real dnsdist
// enforcement pieces:
//
//  1. Identity binding: one addAction(HTTPPathRule(doHPath), ...) per
//     active ClientID (full canonical hex path, no encoding) and one
//     addAction(SNIRule(sniHostname), ...) per active ClientID (the
//     lossless DNS-label-safe encoding, DoT and DoQ both match on TLS
//     SNI so one rule covers both transports), each SetTagAction'ing
//     the query with that identity's own ClientKey. Non-terminal (see
//     dnsdist's own semantics for SetTagAction): processing continues
//     to the rules below, so an untagged query (no matching path/SNI --
//     including every plain-UDP/TCP query, which has no ClientID
//     concept at all) simply never gets a tag and therefore can never
//     match any client-scoped rule that follows -- this is what makes
//     isolation structural rather than a property this package has to
//     separately verify at runtime.
//  2. Per-client explicit deny (terminal block action) THEN explicit
//     allow (terminal AllowAction), each guarded by
//     AndRule({TagRule(clientTag, key), SuffixMatchNodeRule({domain})})
//     -- deny is emitted first so it wins over an allow for the exact
//     same domain+client (matches the "explicit deny > explicit allow"
//     requirement literally), and both are emitted here, before this
//     function returns to CompileDnsdist's own global block/allow/
//     regex chain below, so an explicit per-client entry always
//     outranks the default (global) policy for that one client.
//
// Sorted by (ClientKey, then Hex or domain) throughout for the same
// deterministic-output guarantee every other compiled section in this
// package already provides.
func writeClientRules(w func(string, ...any), identities []ClientIdentity, overrides []ClientOverride, blockAction string) error {
	idents := append([]ClientIdentity(nil), identities...)
	sort.Slice(idents, func(i, j int) bool {
		if idents[i].ClientKey != idents[j].ClientKey {
			return idents[i].ClientKey < idents[j].ClientKey
		}
		return idents[i].Hex < idents[j].Hex
	})
	if len(idents) > 0 {
		w("-- Strong ClientID: identity binding (DoH path / DoT+DoQ SNI -> per-client tag)")
		for _, id := range idents {
			if err := clientid.ValidateHex(id.Hex); err != nil {
				return errf("client %q has an invalid Strong ClientID value: %v", id.ClientKey, err)
			}
			if id.ClientKey == "" {
				return errf("Strong ClientID %q has no client key to tag with", id.Hex)
			}
			path := clientid.DoHPath(id.Hex)
			sni := clientid.EncodeSNILabel(id.Hex)
			w("addAction(HTTPPathRule(%s), SetTagAction(%s, %s))", luaString(path), luaString(clientTag), luaString(id.ClientKey))
			w("addAction(SNIRule(%s), SetTagAction(%s, %s))", luaString(sni), luaString(clientTag), luaString(id.ClientKey))
		}
		w("")
	}

	type override struct{ key, domain string }
	normalize := func(list []ClientOverride, kind string) []override {
		seen := map[override]bool{}
		var out []override
		for _, o := range list {
			if o.Kind != kind {
				continue
			}
			d := normalizeDomain(o.Domain)
			if d == "" || o.ClientKey == "" {
				continue
			}
			ov := override{o.ClientKey, d}
			if !seen[ov] {
				seen[ov] = true
				out = append(out, ov)
			}
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].key != out[j].key {
				return out[i].key < out[j].key
			}
			return out[i].domain < out[j].domain
		})
		return out
	}

	denies := normalize(overrides, "block")
	allows := normalize(overrides, "allow")
	if len(denies) > 0 || len(allows) > 0 {
		w("-- Strong ClientID: per-client explicit deny (wins over allow and over default/global policy)")
		for _, o := range denies {
			w(`addAction(AndRule({TagRule(%s, %s), SuffixMatchNodeRule({%s})}), SetTagAction("apdns_outcome", "blocked"))`,
				luaString(clientTag), luaString(o.key), luaString(o.domain+"."))
			w("addAction(AndRule({TagRule(%s, %s), SuffixMatchNodeRule({%s})}), %s)",
				luaString(clientTag), luaString(o.key), luaString(o.domain+"."), blockAction)
		}
		w("")
		w("-- Strong ClientID: per-client explicit allow (wins over default/global policy, loses to that client's own deny above)")
		for _, o := range allows {
			w("addAction(AndRule({TagRule(%s, %s), SuffixMatchNodeRule({%s})}), AllowAction())",
				luaString(clientTag), luaString(o.key), luaString(o.domain+"."))
		}
		w("")
	}
	return nil
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
