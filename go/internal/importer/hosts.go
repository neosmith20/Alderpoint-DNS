// Package importer is a native Go implementation of the Import page's
// hosts-file source type, matching app/importer.py's parse_hosts_text
// semantics (IP first, one or more hostnames per line, "#" starts a
// comment, blank/malformed lines skipped rather than aborting the whole
// import) and writing directly into the existing internal/localdns
// store -- no new schema, no duplicated validation logic.
//
// Deliberately narrow, disclosed rather than hidden: this is one source
// type out of the six the Import page lists (AdGuard YAML/live API,
// Pi-hole paste, hosts, BIND zone, Alderpoint CSV/XLSX/JSON). The other
// five are real, substantial format-specific parsers (app/importer.py is
// ~1,200 lines covering all of them plus a migration-plan/preview
// system with per-item selection) -- out of scope for this slice, not
// silently assumed equivalent. Hosts was chosen first because it's the
// most common real-world source or a v2 log, and the target
// (local_dns_records) already exists natively with no schema work
// needed. Also simplified from Python's version: no default_domain
// suffixing for bare hostnames (a hostname with no dots is imported
// as-is, not qualified against an appliance-wide default domain).
package importer

import (
	"context"
	"fmt"
	"net"
	"strings"

	"alderpointdns/go-controlplane/internal/localdns"
)

// Result reports what actually happened -- every line's outcome is
// accounted for, matching this session's "never silently drop a row"
// standard already applied to internal/backup/internal/rawquerylog.
type Result struct {
	Imported int      `json:"imported"`
	Skipped  int      `json:"skipped"`
	Errors   []string `json:"errors"`
}

const hostsImportTTL = 300 // matches Python's parse_hosts_text default

// ImportHosts parses hosts-file text and creates one local DNS record
// per (ip, hostname) pair via the existing internal/localdns.Service --
// a malformed or duplicate line is recorded in Result.Errors and
// skipped, never aborting the rest of the import.
func ImportHosts(ctx context.Context, svc *localdns.Service, text string) (Result, error) {
	res := Result{Errors: []string{}}
	for lineNo, raw := range strings.Split(text, "\n") {
		line := raw
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue // an IP with no hostnames at all -- not an error, just nothing to import
		}
		ip := net.ParseIP(fields[0])
		if ip == nil {
			res.Skipped++
			res.Errors = append(res.Errors, fmt.Sprintf("line %d: %q is not a valid IP address", lineNo+1, fields[0]))
			continue
		}
		recordType := "A"
		if ip.To4() == nil {
			recordType = "AAAA"
		}
		for _, host := range fields[1:] {
			_, err := svc.Create(ctx, localdns.CreateInput{
				Name: host, RecordType: recordType, Value: ip.String(), TTL: hostsImportTTL, Enabled: true,
			})
			if err != nil {
				res.Skipped++
				res.Errors = append(res.Errors, fmt.Sprintf("line %d: %q -> %q: %v", lineNo+1, host, ip.String(), err))
				continue
			}
			res.Imported++
		}
	}
	return res, nil
}
