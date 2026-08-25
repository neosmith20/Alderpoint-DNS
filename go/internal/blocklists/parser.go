// Package blocklists implements the blocklist-subscription vertical:
// CRUD against SQLite, an interval scheduler, bounded-concurrency
// background pull jobs (download -> parse -> stage -> promote), and the
// consecutive-failure "attention" tracking from
// app/v2/policy_store.py (BLOCKLIST_ATTENTION_THRESHOLD = 3).
package blocklists

import (
	"bufio"
	"io"
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

func extractDomain(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
		return "", false
	}
	if strings.HasPrefix(line, "||") {
		d := strings.TrimPrefix(line, "||")
		return strings.TrimSuffix(d, "^"), true
	}
	if strings.HasPrefix(line, "0.0.0.0 ") {
		return strings.TrimSpace(strings.TrimPrefix(line, "0.0.0.0 ")), true
	}
	if strings.HasPrefix(line, "127.0.0.1 ") {
		return strings.TrimSpace(strings.TrimPrefix(line, "127.0.0.1 ")), true
	}
	return line, true
}

// Parse accepts plain-host ("0.0.0.0 domain" / "127.0.0.1 domain"),
// Adblock ("||domain^"), and bare-domain lines; "#"/"!" comments and
// blank lines are ignored; anything else counts as invalid.
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
		d, ok := extractDomain(line)
		if !ok || !validDomain(d) {
			invalid++
			continue
		}
		d = strings.ToLower(d)
		if _, exists := seen[d]; exists {
			dup++
			continue
		}
		seen[d] = struct{}{}
	}
	domains := make([]string, 0, len(seen))
	for d := range seen {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	return ParseResult{Domains: domains, Invalid: invalid, Duplicate: dup}
}
