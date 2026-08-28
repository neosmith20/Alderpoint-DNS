// Package blocklists implements the blocklist-subscription vertical:
// CRUD against SQLite, an interval scheduler, bounded-concurrency
// background pull jobs (download -> parse -> stage -> promote), and the
// consecutive-failure "attention" tracking from
// app/v2/policy_store.py (BLOCKLIST_ATTENTION_THRESHOLD = 3).
package blocklists

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
)

var hostLabelRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

type ParseResult struct {
	Domains   []string
	Invalid   int
	Duplicate int
}

func validDomain(d string) bool {
	d = strings.TrimSpace(d)
	if d == "" || len(d) > 253 {
		return false
	}
	if net.ParseIP(d) != nil {
		// An IP literal is never a domain, even though a bare IPv4
		// address happens to satisfy the label regex below (its
		// dotted octets are all-digit labels).
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !hostLabelRe.MatchString(l) {
			return false
		}
	}
	return true
}

// stripInlineComment drops a trailing "# ..." comment (hosts-file style)
// from an already-non-comment line, e.g. "0.0.0.0 ads.example.com # ad".
func stripInlineComment(s string) string {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// extractDomains pulls every domain candidate out of one non-blank,
// non-comment line. It recognizes:
//   - Adblock rules: "||domain^" (optionally with trailing "$modifiers").
//   - hosts-file rules: "<address> host1 [host2 ...] [# comment]", where
//     <address> is any valid IPv4 *or* IPv6 literal -- including
//     abbreviated/compressed forms such as "::" or "::1", and not just
//     the literal "0.0.0.0"/"127.0.0.1" prefixes -- per RFC 952/1123
//     hosts-file syntax, which allows multiple hostname aliases per line.
//   - bare-domain rules: "domain [# comment]".
func extractDomains(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return nil
	}
	if strings.HasPrefix(line, "||") {
		d := strings.TrimPrefix(line, "||")
		d = strings.TrimSuffix(d, "^")
		if i := strings.IndexByte(d, '^'); i >= 0 {
			// "||domain^$important" etc: drop the "$modifiers" tail.
			d = d[:i]
		}
		return []string{d}
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	if net.ParseIP(fields[0]) != nil {
		var out []string
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "#") {
				break
			}
			out = append(out, f)
		}
		return out
	}
	d := stripInlineComment(line)
	if d == "" {
		return nil
	}
	return []string{d}
}

// Parse accepts plain-host ("0.0.0.0 domain" / "127.0.0.1 domain" /
// "<any IPv4 or IPv6 literal> domain[ domain2 ...]"), Adblock
// ("||domain^"), and bare-domain lines; "#"/"!" comments (leading or
// trailing), blank lines, and IP literals are ignored; anything else
// counts as invalid.
func Parse(r io.Reader) ParseResult {
	seen := make(map[string]struct{}, 1<<16)
	var invalid, dup int
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "!") {
			continue
		}
		candidates := extractDomains(line)
		if len(candidates) == 0 {
			invalid++
			continue
		}
		foundValid := false
		for _, d := range candidates {
			d = strings.ToLower(strings.TrimSpace(d))
			if !validDomain(d) {
				continue
			}
			foundValid = true
			if _, exists := seen[d]; exists {
				dup++
				continue
			}
			seen[d] = struct{}{}
		}
		if !foundValid {
			invalid++
		}
	}
	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return ParseResult{Domains: domains, Invalid: invalid, Duplicate: dup}
}
