// AdGuard Home YAML import -- a direct, bounded port of
// app/importer.py's _translate_adguard_config() (read directly). Covers
// the three real translation targets that carry over cleanly: `filters`
// -> blocklist subscriptions (with the same name/URL keyword category
// mapping), `user_rules` -> custom filter rules (common AdBlock syntax:
// ||domain^, |domain^, bare domain, @@ allow prefix, /regex/), and
// `filtering.rewrites` -> Local DNS records (non-wildcard A/AAAA/CNAME)
// or a rewrite-type custom rule (wildcard IP rewrites, via Go's own
// rewrite_target column -- not the Python-only $dnsrewrite modifier
// syntax, which Go's own Custom Rules feature already represents this
// way). NOT attempted, disclosed rather than hidden: whitelist_filters
// (Alderpoint DNS has no allowlist-subscription object -- reported as
// an unsupported finding, matching Python's own posture), client/group
// settings (`clients.persistent`) and per-client policy translation (a
// separate, much larger undertaking spanning Clients & Access, not this
// feature), and the live AdGuard Home API source (fetch_adguard_api --
// reaching a real third-party device on the operator's network, which
// this environment cannot exercise or prove against; only the YAML
// file upload path is built).
package filterimport

import (
	"fmt"
	"net"
	"strings"

	"gopkg.in/yaml.v3"
)

type adguardConfig struct {
	Filters          []adguardFilterEntry  `yaml:"filters"`
	WhitelistFilters []adguardFilterEntry  `yaml:"whitelist_filters"`
	UserRules        []string              `yaml:"user_rules"`
	Filtering        adguardFilteringBlock `yaml:"filtering"`
}

type adguardFilteringBlock struct {
	Filters          []adguardFilterEntry `yaml:"filters"`
	WhitelistFilters []adguardFilterEntry `yaml:"whitelist_filters"`
	UserRules        []string             `yaml:"user_rules"`
	Rewrites         []adguardRewrite     `yaml:"rewrites"`
	RewritesEnabled  *bool                `yaml:"rewrites_enabled"`
}

type adguardFilterEntry struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	Enabled *bool  `yaml:"enabled"`
}

type adguardRewrite struct {
	Domain  string `yaml:"domain"`
	Answer  string `yaml:"answer"`
	Enabled *bool  `yaml:"enabled"`
}

var sourceCategoryKeywords = []struct {
	category string
	keywords []string
}{
	{"malware", []string{"malware", "phishing", "scam", "threat", "badware", "crypto", "security", "safe browsing", "safebrowsing"}},
	{"adult_content", []string{"adult", "porn", "nsfw", "gambling", "explicit"}},
	{"iot_telemetry", []string{"telemetry", "iot", "smart-tv", "smarttv", "vendor tracking"}},
}

func mapSourceCategory(name, url string) string {
	haystack := strings.ToLower(name + " " + url)
	for _, kw := range sourceCategoryKeywords {
		for _, k := range kw.keywords {
			if strings.Contains(haystack, k) {
				return kw.category
			}
		}
	}
	return "ads_trackers"
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// AdguardParsed mirrors PiholeParsed's shape plus a RewriteRules field
// for the one construct Pi-hole never produces: a wildcard-IP DNS
// rewrite, which needs a rewrite_target, not just a pattern.
type AdguardParsed struct {
	Blocklists   []BlocklistCandidate
	Rules        []RuleCandidate
	RewriteRules []RewriteCandidate
	LocalDNS     []LocalDNSCandidate
	Unsupported  []string
}

// RewriteCandidate is a rewrite-type custom rule: pattern (subdomain-
// matched, like every Go block/allow pattern) rewritten to
// RewriteTarget.
type RewriteCandidate struct {
	Pattern       string
	RewriteTarget string
	Text          string
}

// ParseAdGuardYAML parses a real AdGuard Home YAML configuration
// (either its on-disk AdGuardHome.yaml, or the same shape assembled
// from a live instance's own JSON API -- both share this translation).
func ParseAdGuardYAML(text string) (AdguardParsed, error) {
	var cfg adguardConfig
	if err := yaml.Unmarshal([]byte(text), &cfg); err != nil {
		return AdguardParsed{}, fmt.Errorf("not a valid AdGuard Home YAML configuration: %w", err)
	}

	var out AdguardParsed

	filters := cfg.Filters
	if len(filters) == 0 {
		filters = cfg.Filtering.Filters
	}
	for _, f := range filters {
		name := f.Name
		if name == "" {
			name = f.URL
		}
		if name == "" {
			name = "imported-filter"
		}
		out.Blocklists = append(out.Blocklists, BlocklistCandidate{Name: name, URL: f.URL, Category: mapSourceCategory(name, f.URL)})
	}

	whitelistFilters := cfg.WhitelistFilters
	if len(whitelistFilters) == 0 {
		whitelistFilters = cfg.Filtering.WhitelistFilters
	}
	for _, f := range whitelistFilters {
		name := f.Name
		if name == "" {
			name = f.URL
		}
		out.Unsupported = append(out.Unsupported, fmt.Sprintf(
			"allowlist filter %q: Alderpoint DNS has no allowlist-subscription object; add matching custom allow rules manually if needed", name))
	}

	userRules := cfg.UserRules
	if len(userRules) == 0 {
		userRules = cfg.Filtering.UserRules
	}
	for i, raw := range userRules {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") {
			continue // comments -- Go's customrules schema has no comment rule_type to preserve them as
		}
		rc, ok := parseAdblockRule(line, true /* AdGuard: plain domain matches subdomains */)
		if !ok {
			out.Unsupported = append(out.Unsupported, fmt.Sprintf("user rule %d: %s", i+1, line))
			continue
		}
		out.Rules = append(out.Rules, rc)
	}

	rewrites := cfg.Filtering.Rewrites
	rewritesEnabledGlobally := boolOr(cfg.Filtering.RewritesEnabled, true)
	for _, rw := range rewrites {
		domain := strings.TrimSuffix(strings.TrimSpace(rw.Domain), ".")
		answer := strings.TrimSpace(rw.Answer)
		if domain == "" || answer == "" {
			out.Unsupported = append(out.Unsupported, fmt.Sprintf("DNS rewrite is missing a domain or answer: %s -> %s", rw.Domain, rw.Answer))
			continue
		}
		if strings.EqualFold(answer, "A") || strings.EqualFold(answer, "AAAA") {
			out.Unsupported = append(out.Unsupported, fmt.Sprintf(
				"DNS rewrite %s -> %s: AdGuard's %q pass-through/exclusion value has no Alderpoint DNS equivalent and was not imported", domain, answer, strings.ToUpper(answer)))
			continue
		}
		effectiveEnabled := rewritesEnabledGlobally && boolOr(rw.Enabled, true)
		wildcard := strings.HasPrefix(domain, "*.")
		base := domain
		if wildcard {
			base = strings.TrimPrefix(domain, "*.")
		}

		if ip := net.ParseIP(answer); ip != nil {
			if wildcard {
				if !effectiveEnabled {
					out.Unsupported = append(out.Unsupported, fmt.Sprintf(
						"DNS rewrite %s -> %s: disabled in AdGuard Home; disabled wildcard rewrites are reported rather than imported as an active custom rule", domain, answer))
					continue
				}
				out.RewriteRules = append(out.RewriteRules, RewriteCandidate{Pattern: base, RewriteTarget: answer, Text: fmt.Sprintf("%s -> %s", domain, answer)})
				continue
			}
			rtype := "A"
			if ip.To4() == nil {
				rtype = "AAAA"
			}
			out.LocalDNS = append(out.LocalDNS, LocalDNSCandidate{Name: strings.ToLower(base), RecordType: rtype, Value: answer, TTL: 300, Origin: "dns_rewrites"})
			continue
		}
		if wildcard {
			out.Unsupported = append(out.Unsupported, fmt.Sprintf("DNS rewrite %s -> %s: wildcard CNAME-style rewrites are not supported", domain, answer))
			continue
		}
		out.LocalDNS = append(out.LocalDNS, LocalDNSCandidate{
			Name: strings.ToLower(base), RecordType: "CNAME", Value: strings.ToLower(strings.TrimSuffix(answer, ".")), TTL: 300, Origin: "dns_rewrites",
		})
	}

	return out, nil
}

// parseAdblockRule classifies one AdBlock-syntax line into a block/allow
// rule (||domain^, |domain^, bare domain, with an optional @@ allow
// prefix) or a regex rule (/regex/, @@/regex/). Modifiers ($important,
// $dnsrewrite, etc.) and cosmetic/scriptlet rules (##, #@#) are not
// supported -- ok=false, matching this feature's own bounded scope
// rather than Python's much larger modifier-aware classifier.
func parseAdblockRule(raw string, plainDomainSubdomains bool) (RuleCandidate, bool) {
	if strings.Contains(raw, "##") || strings.Contains(raw, "#@#") || strings.Contains(raw, "#%#") || strings.Contains(raw, "#$#") {
		return RuleCandidate{}, false
	}
	isAllow := strings.HasPrefix(raw, "@@")
	body := raw
	if isAllow {
		body = raw[2:]
	}

	if strings.HasPrefix(body, "/") {
		if !strings.HasSuffix(body, "/") || len(body) < 3 {
			return RuleCandidate{}, false
		}
		pattern := body[1 : len(body)-1]
		rt := "regex_block"
		if isAllow {
			rt = "regex_allow"
		}
		return RuleCandidate{RuleType: rt, Pattern: pattern, Text: raw}, true
	}

	base, _, hasModifiers := strings.Cut(body, "$")
	base = strings.TrimSpace(base)
	if hasModifiers {
		return RuleCandidate{}, false // modifier rules ($important, $dnsrewrite on a raw user rule, $client, etc.) not supported
	}
	candidate := base
	if strings.HasPrefix(base, "||") {
		candidate = base[2:]
	} else if strings.HasPrefix(base, "|") {
		candidate = base[1:]
	}
	for _, terminator := range []string{"^", "|"} {
		if idx := strings.IndexByte(candidate, terminator[0]); idx != -1 {
			if idx+1 < len(candidate) {
				return RuleCandidate{}, false // a path/anchor after the domain has no DNS-filtering equivalent
			}
			candidate = candidate[:idx]
		}
	}
	domain := strings.ToLower(strings.TrimSuffix(candidate, "."))
	if domain == "" || !isPlausibleDomain(domain) {
		return RuleCandidate{}, false
	}
	rt := "block"
	if isAllow {
		rt = "allow"
	}
	return RuleCandidate{RuleType: rt, Pattern: domain, Text: raw}, true
}

func isPlausibleDomain(s string) bool {
	if s == "" || strings.ContainsAny(s, " \t/\\") {
		return false
	}
	for _, r := range s {
		if !(r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z')) {
			return false
		}
	}
	return true
}
