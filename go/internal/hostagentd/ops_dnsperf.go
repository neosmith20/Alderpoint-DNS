// DNS Performance benchmark execution, real, via internal/dnsperf's
// packet-level UDP/TCP/DoT/DoH exchange -- run from this agent because
// the web container's isolated bridge network cannot reach
// 127.0.0.1:<dnsdist/BIND port> on the host at all (the same reasoning
// already documented for Cache/Replication/Network Configuration; see
// the deploy script's `podman run`, no --network host).
//
// Safety: the web layer supplies only a domain name, qtype, protocol,
// query count, and timeout per case -- never a server. This op resolves
// every case's actual server/port itself, from its own fixed startup
// config (the real Go-managed dnsdist/BIND addresses this agent's DNS
// Runtime ops already promote to), for two enumerated targets
// ("dnsdist", "bind_plain") plus DoT/DoH ports which stay loopback-only
// (the same host as the dnsdist listener) with a caller-supplied port
// bounded to the valid TCP port range -- so this op can never be
// repurposed to probe an arbitrary remote host, only this appliance's
// own already-loopback-bound DNS listeners. Query counts and timeouts
// are capped server-side to keep a single case bounded on a small VM,
// matching the "safe" in "Safe DNS Benchmark". One request = one case
// (the web layer calls this once per case and does its own
// summarizing with the same internal/dnsperf.Summarize both sides
// share) -- kept simple rather than adding a second batch protocol.
package hostagentd

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"alderpointdns/go-controlplane/internal/dnsperf"
	"alderpointdns/go-controlplane/internal/hostagent"
)

// DNSPerfConfig is this agent's fixed, real DNS-runtime addresses --
// the same values passed to -dns-runtime-* flags at startup, never
// caller-supplied.
type DNSPerfConfig struct {
	// DnsdistHost/DnsdistPort is the real Go-managed dnsdist listener
	// (matches -dns-runtime-dnsdist-listen-addr).
	DnsdistHost string
	DnsdistPort int
	// BindPlainPort is BIND's own unproxied loopback listener (matches
	// -dns-runtime-bind-plain-port) -- "direct BIND" cases bypass
	// dnsdist entirely, same as Python's BenchmarkCase pointed at 5453.
	BindPlainPort int
}

const (
	maxDNSPerfQueriesPerCase = 20000
	maxDNSPerfTimeout        = 5 * time.Second
)

// dnsPerfCaseIn is exactly what the web layer is allowed to specify --
// never a raw server/port, see the package doc comment.
type dnsPerfCaseIn struct {
	Domain         string  `json:"domain"`
	QType          uint16  `json:"qtype"`
	Target         string  `json:"target"` // "dnsdist" | "bind_plain" | "dot" | "doh"
	Protocol       string  `json:"protocol"`
	Queries        int     `json:"queries"`
	TimeoutSeconds float64 `json:"timeout_seconds"`
	Port           int     `json:"port"` // only honored for target in {dot, doh}
	Path           string  `json:"path"`
}

// RegisterDNSPerfOps registers OpDNSPerfBenchmark. A zero-value cfg
// (DnsdistHost=="") means DNS Runtime itself isn't configured on this
// agent -- the op is still registered but every case targeting
// "dnsdist"/"bind_plain" fails honestly rather than silently returning
// fabricated zero-latency samples.
func RegisterDNSPerfOps(s *Server, cfg DNSPerfConfig) {
	s.Register(hostagent.OpDNSPerfBenchmark, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in dnsPerfCaseIn
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		resolved, err := resolveDNSPerfCase(cfg, in)
		if err != nil {
			return nil, err
		}
		samples := dnsperf.LocalQuerier{}.Query(ctx, resolved)
		return map[string]any{"samples": samples}, nil
	})
}

func resolveDNSPerfCase(cfg DNSPerfConfig, in dnsPerfCaseIn) (dnsperf.BenchmarkCase, error) {
	if in.Domain == "" {
		return dnsperf.BenchmarkCase{}, fmt.Errorf("domain is required")
	}
	if in.QType == 0 {
		in.QType = 1
	}
	queries := in.Queries
	if queries < 1 {
		queries = 1
	}
	if queries > maxDNSPerfQueriesPerCase {
		return dnsperf.BenchmarkCase{}, fmt.Errorf("queries %d exceeds max %d", queries, maxDNSPerfQueriesPerCase)
	}
	timeout := time.Duration(in.TimeoutSeconds * float64(time.Second))
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if timeout > maxDNSPerfTimeout {
		timeout = maxDNSPerfTimeout
	}

	out := dnsperf.BenchmarkCase{
		Domain: in.Domain, QType: in.QType,
		Protocol: in.Protocol, Queries: queries, Timeout: timeout, Path: in.Path,
	}

	switch in.Target {
	case "dnsdist":
		if cfg.DnsdistHost == "" {
			return out, fmt.Errorf("DNS runtime is not configured on this agent")
		}
		out.Server, out.Port = cfg.DnsdistHost, cfg.DnsdistPort
	case "bind_plain":
		if cfg.DnsdistHost == "" || cfg.BindPlainPort == 0 {
			return out, fmt.Errorf("DNS runtime is not configured on this agent")
		}
		out.Server, out.Port = cfg.DnsdistHost, cfg.BindPlainPort
	case "dot", "doh":
		if cfg.DnsdistHost == "" {
			return out, fmt.Errorf("DNS runtime is not configured on this agent")
		}
		if in.Port <= 0 || in.Port > 65535 {
			return out, fmt.Errorf("a valid port is required for target %q", in.Target)
		}
		out.Server, out.Port = cfg.DnsdistHost, in.Port
	default:
		return out, fmt.Errorf("unknown target %q", in.Target)
	}
	return out, nil
}
