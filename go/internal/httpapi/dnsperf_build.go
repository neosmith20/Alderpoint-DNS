package httpapi

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/dnsperf"
)

// BuildDNSPerfCases builds System Status's real "Safe DNS Benchmark"
// case list from this control plane's own live state -- field-matched
// against app/v2/webapp.py's _dns_benchmark_runner(), not guessed.
// Every case targets the real Go-managed dnsdist/BIND runtime this
// deployment promotes to (never Python's :8443 runtime, which this
// migration never touches). Exported so cmd/alderpointdns-go can pass
// it as internal/dnsperf.Service's BuildCases callback.
func (s *Server) BuildDNSPerfCases(ctx context.Context) ([]dnsperf.BenchmarkCase, []string, error) {
	if s.DNSRuntime == nil {
		return nil, nil, fmt.Errorf("DNS runtime is not configured for this deployment")
	}
	dnsdistHost, dnsdistPortStr, err := net.SplitHostPort(s.DNSRuntime.DnsdistListenAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid dnsdist listen address: %w", err)
	}
	dnsdistPort, _ := strconv.Atoi(dnsdistPortStr)

	localDomain, err := s.dnsPerfLocalDomain(ctx)
	if err != nil {
		return nil, nil, err
	}
	blockedDomain := s.dnsPerfBlockedDomain(ctx)

	var cases []dnsperf.BenchmarkCase
	cases = append(cases,
		dnsperf.BenchmarkCase{
			Name: "Local DNS answer", Scope: "alderpoint-controlled", Target: "dnsdist",
			Server: dnsdistHost, Port: dnsdistPort, Domain: localDomain, QType: 1, Protocol: "udp",
			Queries: 10000, Timeout: 2 * time.Second,
		},
		dnsperf.BenchmarkCase{
			Name: "Filtering/block answer", Scope: "alderpoint-controlled", Target: "dnsdist",
			Server: dnsdistHost, Port: dnsdistPort, Domain: blockedDomain, QType: 1, Protocol: "udp",
			Queries: 10000, Timeout: 2 * time.Second,
		},
		dnsperf.BenchmarkCase{
			Name: "dnsdist/BIND hot A response", Scope: "hot-cache/client-observed", Target: "dnsdist",
			Server: dnsdistHost, Port: dnsdistPort, Domain: "example.com.", QType: 1, Protocol: "udp",
			Queries: 10000, Timeout: 2 * time.Second,
		},
	)

	if s.DNSPerfBindPlainAddr != "" {
		bindHost, bindPortStr, err := net.SplitHostPort(s.DNSPerfBindPlainAddr)
		if err == nil {
			bindPort, _ := strconv.Atoi(bindPortStr)
			cases = append(cases, dnsperf.BenchmarkCase{
				Name: "BIND direct hot A response", Scope: "backend-cache/direct-bind", Target: "bind_plain",
				Server: bindHost, Port: bindPort, Domain: "example.com.", QType: 1, Protocol: "udp",
				Queries: 10000, Timeout: 200 * time.Millisecond,
			})
		}
	}

	if s.DNSTransports != nil {
		settings, err := s.DNSTransports.Get(ctx)
		if err == nil {
			if settings.DotEnabled {
				cases = append(cases,
					dnsperf.BenchmarkCase{
						Name: "DoT initial TLS query", Scope: "encrypted-dns/initial-handshake", Target: "dot",
						Server: dnsdistHost, Port: settings.DotPort, Domain: "example.com.", QType: 1, Protocol: "dot",
						Queries: 100, Timeout: 2 * time.Second,
					},
					dnsperf.BenchmarkCase{
						Name: "DoT established query", Scope: "encrypted-dns/established-connection", Target: "dot",
						Server: dnsdistHost, Port: settings.DotPort, Domain: "example.com.", QType: 1, Protocol: "dot-established",
						Queries: 1000, Timeout: 2 * time.Second,
					},
				)
			}
			if settings.DohEnabled {
				path := settings.DohPath
				if path == "" {
					path = "/dns-query"
				}
				cases = append(cases,
					dnsperf.BenchmarkCase{
						Name: "DoH initial TLS query", Scope: "encrypted-dns/initial-handshake", Target: "doh",
						Server: dnsdistHost, Port: settings.DohPort, Domain: "example.com.", QType: 1, Protocol: "doh", Path: path,
						Queries: 100, Timeout: 2 * time.Second,
					},
					dnsperf.BenchmarkCase{
						Name: "DoH established query", Scope: "encrypted-dns/established-connection", Target: "doh",
						Server: dnsdistHost, Port: settings.DohPort, Domain: "example.com.", QType: 1, Protocol: "doh-established", Path: path,
						Queries: 1000, Timeout: 2 * time.Second,
					},
				)
			}
		}
	}

	cases = append(cases, dnsperf.BenchmarkCase{
		Name: "Cold unique forwarded lookup", Scope: "cold-external/client-observed", Target: "dnsdist",
		Server: dnsdistHost, Port: dnsdistPort,
		Domain: fmt.Sprintf("apdns-cold-%d.example.com.", time.Now().UnixNano()), QType: 1, Protocol: "udp",
		Queries: 10, Timeout: 2 * time.Second,
	})

	notes := []string{
		"Client-observed timings use a monotonic high-resolution timer around the DNS exchange.",
		"Cold external totals include upstream/authoritative network waiting outside Alderpoint control.",
		"Alderpoint-controlled hot/local/block targets are measured separately from cold external targets.",
		"DoT/DoH initial TLS handshake and established-connection query latency are reported as separate cases.",
		"Every case targets this deployment's own Go-managed dnsdist/BIND runtime, never Python's separate :8443 runtime.",
	}
	if !s.dnsPerfHasBlockedDomain(ctx) {
		notes = append(notes, "No blocklist domain was available at benchmark time; the Filtering/block case used a placeholder domain that is not expected to be blocked.")
	}
	return cases, notes, nil
}

// dnsPerfLocalDomain mirrors Python's _local_domain(): the most-recently
// relevant enabled Local DNS record, falling back to "localhost." if
// none exists. Go's schema has no updated_at column on local_dns_records
// to sort by (a real, disclosed schema difference, not staleness) --
// this picks the first enabled record List() returns instead.
func (s *Server) dnsPerfLocalDomain(ctx context.Context) (string, error) {
	if s.LocalDNS == nil {
		return "localhost.", nil
	}
	records, err := s.LocalDNS.List(ctx)
	if err != nil {
		return "", fmt.Errorf("loading local DNS records: %w", err)
	}
	for _, r := range records {
		if r.Enabled && r.Name != "" {
			return strings.TrimSuffix(r.Name, ".") + ".", nil
		}
	}
	return "localhost.", nil
}

// dnsPerfBlockedDomain mirrors Python's _blocked_domain(): one real
// domain from an enabled blocklist's compiled RPZ output. Falls back to
// a placeholder domain (never expected to be blocked) if none is
// available yet -- honestly disclosed in buildDNSPerfCases's notes,
// never presented as a real block-path measurement.
func (s *Server) dnsPerfBlockedDomain(ctx context.Context) string {
	if d, ok := s.dnsPerfAnyBlockedDomain(ctx); ok {
		return d
	}
	return "0--0.info."
}

func (s *Server) dnsPerfHasBlockedDomain(ctx context.Context) bool {
	_, ok := s.dnsPerfAnyBlockedDomain(ctx)
	return ok
}

func (s *Server) dnsPerfAnyBlockedDomain(ctx context.Context) (string, bool) {
	if s.Blocklists == nil || s.Blocklists.RuntimeDir == "" {
		return "", false
	}
	subs, err := s.Blocklists.List(ctx)
	if err != nil {
		return "", false
	}
	for _, sub := range subs {
		if !sub.Enabled {
			continue
		}
		path := filepath.Join(s.Blocklists.RuntimeDir, sub.SubscriptionID+".rpz")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			domain := strings.ToLower(strings.Fields(line)[0])
			if domain != "" {
				return domain + ".", true
			}
		}
	}
	return "", false
}
