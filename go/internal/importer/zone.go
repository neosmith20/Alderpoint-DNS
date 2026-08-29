// BIND zone-file import -- the second real Import source type (after
// hosts), matching app/importer.py's parse_zone_text semantics: a
// practical subset of zone-file syntax, `name [ttl] [IN] TYPE data`
// lines for A/AAAA/CNAME/PTR records only. $ORIGIN is honored (changes
// the base domain bare/relative names are qualified against for the
// rest of the file); $TTL, SOA/NS/MX records, and multi-line
// parenthesized records are NOT supported, matching Python's own
// disclosed subset exactly -- an unsupported line is simply skipped
// (not an error), the same "don't abort the rest of the file" standard
// this package's ImportHosts already uses.
package importer

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"alderpointdns/go-controlplane/internal/localdns"
)

const zoneImportDefaultTTL = 300

// zoneLineRE mirrors Python's ZONE_LINE_RE exactly: name, optional TTL,
// optional "IN" class, one of A/AAAA/CNAME/PTR, then the data field.
var zoneLineRE = regexp.MustCompile(`(?i)^(\S+)\s+(?:(\d+)\s+)?(?:IN\s+)?(A|AAAA|CNAME|PTR)\s+(\S+)\s*$`)

// ImportZone parses BIND zone-file text and creates one local DNS
// record per recognized line via the existing internal/localdns.Service.
// defaultDomain is both the initial $ORIGIN and what a bare/relative
// name (no trailing ".") is qualified against; "@" means "the current
// origin itself".
func ImportZone(ctx context.Context, svc *localdns.Service, text string, defaultDomain string) (Result, error) {
	res := Result{Errors: []string{}}
	origin := normalizeZoneDomain(defaultDomain)

	for lineNo, raw := range strings.Split(text, "\n") {
		line := raw
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimRight(line, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(strings.ToUpper(trimmed), "$ORIGIN") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				origin = normalizeZoneDomain(strings.TrimSuffix(fields[1], "."))
			}
			continue
		}
		if strings.HasPrefix(trimmed, "$") {
			continue // $TTL and any other directive: not supported, skipped not fatal
		}

		m := zoneLineRE.FindStringSubmatch(trimmed)
		if m == nil {
			continue // SOA/NS/MX/multi-line records and anything else unsupported: skipped
		}
		name, ttlStr, recordType, data := m[1], m[2], strings.ToUpper(m[3]), strings.TrimSuffix(m[4], ".")

		var fqdn string
		if name == "@" || name == "" {
			fqdn = origin
		} else {
			fqdn = normalizeFQDN(name, origin)
		}
		ttl := zoneImportDefaultTTL
		if ttlStr != "" {
			if v, err := strconv.Atoi(ttlStr); err == nil {
				ttl = v
			}
		}

		_, err := svc.Create(ctx, localdns.CreateInput{
			Name: fqdn, RecordType: recordType, Value: data, TTL: ttl, Enabled: true,
		})
		if err != nil {
			res.Skipped++
			res.Errors = append(res.Errors, fmt.Sprintf("line %d: %q %s %q: %v", lineNo+1, fqdn, recordType, data, err))
			continue
		}
		res.Imported++
	}
	return res, nil
}

func normalizeZoneDomain(d string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
}

// normalizeFQDN mirrors Python's local_dns.normalize_fqdn: an
// already-absolute name (ends in ".") is used as-is (minus the trailing
// dot); otherwise it's qualified as "<name>.<origin>".
func normalizeFQDN(name, origin string) string {
	if strings.HasSuffix(name, ".") {
		return strings.ToLower(strings.TrimSuffix(name, "."))
	}
	if origin == "" {
		return strings.ToLower(name)
	}
	return strings.ToLower(name + "." + origin)
}
