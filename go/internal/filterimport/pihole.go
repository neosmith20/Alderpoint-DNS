// Package filterimport ports V1.1.1's Pi-hole and AdGuard Home import
// sources (app/importer.py, read directly) -- a different shape from
// internal/importer's job model because a single source translates into
// THREE different subsystems at once (blocklist subscriptions, Local
// DNS records, and custom filter rules), not just local_dns_records.
// Like internal/legacyimport, this gets its own dry-run/apply Report
// rather than the selective per-row Plan/Job workflow.
package filterimport

import (
	"regexp"
	"strconv"
	"strings"
)

// piholeSections maps every real V1.1.1 section-header spelling (both
// `[name]` and `# name #` comment-marker forms) to a normalized section
// key -- copied verbatim from app/importer.py's own _PIHOLE_SECTIONS.
var piholeSections = map[string]string{
	"adlist": "adlists", "adlists": "adlists", "adlists.list": "adlists",
	"whitelist": "whitelist", "whitelist.txt": "whitelist", "exact whitelist": "whitelist",
	"blacklist": "blacklist", "blacklist.txt": "blacklist", "exact blacklist": "blacklist",
	"regex": "regex_black", "regex.list": "regex_black", "regex blacklist": "regex_black", "blacklist regex": "regex_black",
	"regex whitelist": "regex_white", "whitelist regex": "regex_white",
	"custom.list": "hosts", "custom list": "hosts", "hosts": "hosts", "local dns": "hosts",
	"cname": "cname", "cnames": "cname", "custom cname": "cname",
	"group": "groups", "groups": "groups",
}

var (
	piholeSectionBracketRE = regexp.MustCompile(`^\[([^\]]+)\]$`)
	piholeSectionCommentRE = regexp.MustCompile(`^#+\s*(.+?)\s*#*\s*$`)
	// Pi-hole's wildcard-blocking idiom: `pihole -wild domain.tld` stores
	// the regex (\.|^)domain\.tld$ (also seen as (^|\.)domain\.tld$).
	piholeWildcardRE = regexp.MustCompile(`^\((?:\\\.\|\^|\^\|\\\.)\)((?:[A-Za-z0-9_-]+\\\.)+[A-Za-z0-9_-]+)\$$`)
	piholeDomainRE    = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func piholeSectionFor(line string) string {
	stripped := strings.TrimSpace(line)
	m := piholeSectionBracketRE.FindStringSubmatch(stripped)
	if m == nil {
		m = piholeSectionCommentRE.FindStringSubmatch(stripped)
	}
	if m == nil {
		return ""
	}
	return piholeSections[strings.ToLower(strings.TrimSpace(m[1]))]
}

// RuleCandidate is one custom-filter-rule outcome from a source parser --
// already classified into the exact rule_type/pattern shape
// internal/customrules.Service.Create expects, so Apply never has to
// re-derive it.
type RuleCandidate struct {
	RuleType string // "block" | "allow" | "regex_block" | "regex_allow"
	Pattern  string
	Text     string // the original source line, for display/audit only
}

// piholeRegexEntry translates one Pi-hole regex line, recognizing the
// wildcard-blocking idiom as a plain domain rule (not a regex) --
// mirroring app/importer.py's _pihole_regex_entry exactly.
func piholeRegexEntry(pattern string, allow bool, original string) RuleCandidate {
	if m := piholeWildcardRE.FindStringSubmatch(pattern); m != nil {
		domain := strings.ReplaceAll(m[1], `\.`, ".")
		rt := "block"
		if allow {
			rt = "allow"
		}
		return RuleCandidate{RuleType: rt, Pattern: domain, Text: original}
	}
	rt := "regex_block"
	if allow {
		rt = "regex_allow"
	}
	return RuleCandidate{RuleType: rt, Pattern: pattern, Text: original}
}

// LocalDNSCandidate is one real Local DNS record outcome.
type LocalDNSCandidate struct {
	Name       string
	RecordType string
	Value      string
	TTL        int
	Origin     string // which Pi-hole construct produced this, for display only
}

// BlocklistCandidate is one real blocklist-subscription outcome.
type BlocklistCandidate struct {
	Name     string
	URL      string
	Category string
}

// PiholeParsed is the structured result of parsing a Pi-hole export --
// field-matched against app/importer.py's parse_pihole_text() return
// shape, minus the fields that were always empty in the real
// implementation (allowlist_unsupported, custom_allow/custom_block --
// legacy JSON-only fields, upstream_resolvers, untranslatable).
type PiholeParsed struct {
	Blocklists  []BlocklistCandidate
	Rules       []RuleCandidate
	LocalDNS    []LocalDNSCandidate
	Unsupported []string // includes client/group-assignment findings -- Alderpoint DNS has no client-group equivalent
}

func normalizeFQDN(name, defaultDomain string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if strings.Contains(name, ".") || defaultDomain == "" {
		return name
	}
	return name + "." + strings.ToLower(strings.TrimSuffix(strings.TrimSpace(defaultDomain), "."))
}

// ParsePihole is a direct line-for-line port of app/importer.py's real
// parse_pihole_text(): adlists.list URLs, exact/section-scoped
// whitelist/blacklist domains, regex block/allow lines (including the
// wildcard idiom), dnsmasq cname=alias,target[,ttl] lines, custom.list
// hosts-style A/AAAA records, and group-assignment lines (reported as
// explicit unsupported findings -- Alderpoint DNS has no client-group
// concept). Anything unrecognized becomes an explicit unsupported
// finding, never a silent drop.
func ParsePihole(text, defaultDomain string) PiholeParsed {
	var out PiholeParsed
	section := ""
	for lineNo, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if newSection := piholeSectionFor(line); newSection != "" {
			section = newSection
			continue
		}
		if strings.HasPrefix(line, "#") {
			continue // a bare comment -- Go's customrules schema has no comment rule_type to preserve it as
		}
		lower := strings.ToLower(line)

		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			name := line
			if i := strings.LastIndex(line, "/"); i >= 0 {
				name = line[i+1:]
			}
			if i := strings.Index(name, "?"); i >= 0 {
				name = name[:i]
			}
			if name == "" {
				name = "Pi-hole list"
			}
			out.Blocklists = append(out.Blocklists, BlocklistCandidate{Name: name, URL: line, Category: "ads_trackers"})
			continue
		}

		if strings.HasPrefix(lower, "cname=") {
			parts := strings.Split(line[len("cname="):], ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				ttl := 300
				if len(parts) >= 3 && parts[2] != "" {
					if n, err := strconv.Atoi(parts[2]); err == nil {
						ttl = n
					}
				}
				out.LocalDNS = append(out.LocalDNS, LocalDNSCandidate{
					Name: normalizeFQDN(parts[0], defaultDomain), RecordType: "CNAME",
					Value: normalizeFQDN(parts[1], defaultDomain), TTL: ttl, Origin: "cname",
				})
			} else {
				out.Unsupported = append(out.Unsupported, lineErr(lineNo, "invalid cname entry (need cname=alias,target)", line))
			}
			continue
		}

		if strings.HasPrefix(lower, "whitelist ") || strings.HasPrefix(lower, "allow ") {
			domain := strings.TrimSuffix(strings.TrimSpace(strings.SplitN(line, " ", 2)[1]), ".")
			out.Rules = append(out.Rules, RuleCandidate{RuleType: "allow", Pattern: domain, Text: line})
			continue
		}
		if strings.HasPrefix(lower, "blacklist ") || strings.HasPrefix(lower, "block ") || strings.HasPrefix(lower, "deny ") {
			domain := strings.TrimSuffix(strings.TrimSpace(strings.SplitN(line, " ", 2)[1]), ".")
			out.Rules = append(out.Rules, RuleCandidate{RuleType: "block", Pattern: domain, Text: line})
			continue
		}
		if strings.HasPrefix(lower, "regex whitelist ") {
			out.Rules = append(out.Rules, piholeRegexEntry(strings.TrimSpace(line[len("regex whitelist "):]), true, line))
			continue
		}
		if strings.HasPrefix(lower, "regex ") {
			out.Rules = append(out.Rules, piholeRegexEntry(strings.TrimSpace(line[len("regex "):]), false, line))
			continue
		}
		if strings.HasPrefix(lower, "group ") || section == "groups" {
			out.Unsupported = append(out.Unsupported, lineErr(lineNo, "Pi-hole group assignments have no Alderpoint DNS equivalent and were not imported", line))
			continue
		}
		if section == "regex_black" {
			out.Rules = append(out.Rules, piholeRegexEntry(line, false, line))
			continue
		}
		if section == "regex_white" {
			out.Rules = append(out.Rules, piholeRegexEntry(line, true, line))
			continue
		}

		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if rtype, val, ok := parseIP(fields[0]); ok {
				for _, host := range fields[1:] {
					out.LocalDNS = append(out.LocalDNS, LocalDNSCandidate{
						Name: normalizeFQDN(host, defaultDomain), RecordType: rtype, Value: val, TTL: 300, Origin: "custom.list",
					})
				}
				continue
			}
		}

		commaSplit := splitCommaOrTab(line)
		if len(commaSplit) > 1 && piholeDomainRE.MatchString(commaSplit[0]) && allDigitsOrEmpty(commaSplit[1:]) {
			out.Unsupported = append(out.Unsupported, lineErr(lineNo, "Pi-hole group-assignment columns have no Alderpoint DNS equivalent; the row was not imported", line))
			continue
		}

		if piholeDomainRE.MatchString(line) {
			domain := strings.TrimSuffix(line, ".")
			if section == "whitelist" {
				out.Rules = append(out.Rules, RuleCandidate{RuleType: "allow", Pattern: domain, Text: line})
			} else {
				out.Rules = append(out.Rules, RuleCandidate{RuleType: "block", Pattern: domain, Text: line})
			}
			continue
		}
		out.Unsupported = append(out.Unsupported, lineErr(lineNo, "unrecognized Pi-hole line", line))
	}
	return out
}

func lineErr(lineNo int, reason, line string) string {
	return "line " + strconv.Itoa(lineNo+1) + ": " + reason + ": " + line
}

func parseIP(s string) (recordType, value string, ok bool) {
	if strings.Count(s, ":") >= 2 {
		return "AAAA", s, looksLikeIPv6(s)
	}
	if isIPv4(s) {
		return "A", s, true
	}
	return "", "", false
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 || (len(p) > 1 && p[0] == '0') {
			return false
		}
	}
	return true
}

func looksLikeIPv6(s string) bool {
	// A pragmatic check, not a full RFC validator -- sufficient to tell
	// "this is an IPv6-shaped first field" apart from a bare hostname in
	// a custom.list line, matching this parser's own practical scope.
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF:", c) {
			return false
		}
	}
	return strings.Contains(s, ":")
}

func splitCommaOrTab(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\t' })
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	return fields
}

func allDigitsOrEmpty(parts []string) bool {
	for _, p := range parts {
		if p == "" {
			continue
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}
