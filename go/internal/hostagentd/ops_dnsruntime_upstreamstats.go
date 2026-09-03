// Real per-backend dnsdist telemetry, polled from this root-owned
// agent's own loopback network access (see OpDNSRuntimeUpstreamStats's
// doc comment for why the unprivileged web container cannot do this
// itself). Field names and semantics are a direct, evidence-based port
// of V1.1.1's own app/analytics.py (dnsdist_server_state/
// collect_upstream_resolver_aggregate, read directly from the real
// shipped package, not guessed) against dnsdist's real
// /api/v1/servers/localhost REST endpoint -- the same endpoint,
// identically named counter fields (queries, responses, sendErrors,
// healthCheckFailures, healthCheckFailuresTimeout, tcpConnectTimeouts,
// tcpReadTimeouts, tcpWriteTimeouts, tcpGaveUp, latency, state, pools).
//
// V2's own upstream data model differs from V1's (a flat
// upstream_resolvers catalog with stable integer IDs) -- there is no
// equivalent catalog here, only internal/upstreams' Profile/Endpoint
// shape and internal/domainrouting's per-rule profiles. Rather than
// inventing a parallel ID catalog, every backend this deployment's own
// internal/dnscompile compiles is given a stable, self-describing name
// (see dnscompile.UpstreamServerNamePrefix) -- this file identifies
// "ours" by that name prefix and reports the name itself as the
// resolver's stable key, honestly narrower than V1's ID-based identity
// but never fabricated.
package hostagentd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/dnscompile"
)

// UpstreamServerStat is one dnsdist backend's real counters as of this
// poll -- cumulative since dnsdist's own process start, not a delta
// (the caller, internal/dnsanalytics, computes deltas against its own
// last-seen state, exactly matching V1's own two-layer design: this
// agent never keeps counter history, it only ever reports dnsdist's
// current live numbers).
type UpstreamServerStat struct {
	Name                       string   `json:"name"`
	Address                    string   `json:"address"`
	Pools                      []string `json:"pools"`
	Protocol                   string   `json:"protocol"` // dnsdist's own real value, e.g. "Do53 UDP", "DoT", "DoH"
	State                      string   `json:"state"`    // "up", "down", "unknown", ...
	Latency                    float64  `json:"latency_ms"`
	Queries                    int64    `json:"queries"`
	Responses                  int64    `json:"responses"`
	SendErrors                 int64    `json:"send_errors"`
	HealthCheckFailures        int64    `json:"health_check_failures"`
	HealthCheckFailuresTimeout int64    `json:"health_check_failures_timeout"`
	TCPConnectTimeouts         int64    `json:"tcp_connect_timeouts"`
	TCPReadTimeouts            int64    `json:"tcp_read_timeouts"`
	TCPWriteTimeouts           int64    `json:"tcp_write_timeouts"`
	TCPGaveUp                  int64    `json:"tcp_gave_up"`
}

// UpstreamStatsResult is OpDNSRuntimeUpstreamStats's response.
// Available=false (with Reason set) is the honest "cannot report yet"
// case -- no host-agent, no live promotion with an API key yet, or the
// real HTTP call to dnsdist itself failed -- always distinct from
// Available=true with a genuinely empty Servers list (a live dnsdist
// with no apdns_-named backends compiled in, e.g. "Zero Managed
// Upstreams").
type UpstreamStatsResult struct {
	Available bool                 `json:"available"`
	Reason    string               `json:"reason,omitempty"`
	Servers   []UpstreamServerStat `json:"servers,omitempty"`
	PolledAt  string               `json:"polled_at,omitempty"`
}

// dnsdistAPIServer mirrors the subset of dnsdist's real
// /api/v1/servers/localhost per-server JSON object this package reads
// -- field names confirmed against V1.1.1's own real, live-validated
// parsing (opt/alderpointdns/app/analytics.py's SERVER_COUNTER_FIELDS
// and dnsdist_server_state()).
type dnsdistAPIServer struct {
	Name                       string   `json:"name"`
	Address                    string   `json:"address"`
	Pools                      []string `json:"pools"`
	Protocol                   string   `json:"protocol"`
	State                      string   `json:"state"`
	Latency                    float64  `json:"latency"`
	Queries                    int64    `json:"queries"`
	Responses                  int64    `json:"responses"`
	SendErrors                 int64    `json:"sendErrors"`
	HealthCheckFailures        int64    `json:"healthCheckFailures"`
	HealthCheckFailuresTimeout int64    `json:"healthCheckFailuresTimeout"`
	TCPConnectTimeouts         int64    `json:"tcpConnectTimeouts"`
	TCPReadTimeouts            int64    `json:"tcpReadTimeouts"`
	TCPWriteTimeouts           int64    `json:"tcpWriteTimeouts"`
	TCPGaveUp                  int64    `json:"tcpGaveUp"`
}

type dnsdistAPIServersResponse struct {
	Servers []dnsdistAPIServer `json:"servers"`
}

func fetchUpstreamStats(ctx context.Context, apiKey string, apiPort int, timeout time.Duration) (*UpstreamStatsResult, error) {
	if apiKey == "" {
		return &UpstreamStatsResult{Available: false, Reason: "no dnsdist webserver API key is known yet -- either no DNS runtime is configured, or it has not been promoted with the API enabled yet"}, nil
	}
	if apiPort == 0 {
		apiPort = 8083
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/servers/localhost", apiPort)
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building dnsdist API request: %w", err)
	}
	req.Header.Set("X-API-Key", apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return &UpstreamStatsResult{Available: false, Reason: fmt.Sprintf("dnsdist webserver API unreachable: %v", err)}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Non-OK bodies are small (an error page/message), never the huge
		// real payload below -- fine to buffer in full, bounded small.
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return &UpstreamStatsResult{Available: false, Reason: fmt.Sprintf("dnsdist webserver API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))}, nil
	}

	// Real shape confirmed live against the actual installed dnsdist
	// 2.1.1 binary: a single JSON object whose own "servers" key holds
	// the per-backend array, matching dnsdistAPIServersResponse exactly
	// -- but NOT small. A real, previously-undiscovered defect this
	// fixes: this endpoint's real response also inline-dumps dnsdist's
	// entire compiled ruleset (acl/rules/response-rules/etc, alongside
	// the "servers" key this package actually wants) -- on the real
	// live appliance, with 854k+ real blocklist rules compiled in, that
	// is a genuine 26+ MB document, not the few KB a "per-server stats"
	// endpoint name suggests. The previous 4 MiB io.ReadAll(io.LimitReader(...))
	// silently truncated the raw bytes mid-document on every real poll
	// against this scale of ruleset, which json.Unmarshal then failed
	// to parse as "unexpected end of JSON input" -- the exact live
	// symptom that kept Top Upstream Resolvers empty even after the
	// separate API-key-persistence fix landed. Decoding straight from
	// the response stream (json.Decoder, not a ReadAll'd byte slice)
	// avoids ever holding a second full copy of the body in memory;
	// LimitReader here is a defensive cap only (256 MiB -- ~10x today's
	// real size, real headroom against blocklist growth), not the
	// primary parsing boundary the old code mistakenly made it.
	var wrapped dnsdistAPIServersResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&wrapped); err != nil {
		return nil, fmt.Errorf("parsing dnsdist API response: %w", err)
	}

	out := &UpstreamStatsResult{Available: true, PolledAt: time.Now().UTC().Format(time.RFC3339)}
	for _, s := range wrapped.Servers {
		if !strings.HasPrefix(s.Name, dnscompile.UpstreamServerNamePrefix) {
			continue // not one of ours -- see this file's own doc comment
		}
		out.Servers = append(out.Servers, UpstreamServerStat{
			Name: s.Name, Address: s.Address, Pools: s.Pools, Protocol: s.Protocol, State: s.State, Latency: s.Latency,
			Queries: s.Queries, Responses: s.Responses, SendErrors: s.SendErrors,
			HealthCheckFailures: s.HealthCheckFailures, HealthCheckFailuresTimeout: s.HealthCheckFailuresTimeout,
			TCPConnectTimeouts: s.TCPConnectTimeouts, TCPReadTimeouts: s.TCPReadTimeouts,
			TCPWriteTimeouts: s.TCPWriteTimeouts, TCPGaveUp: s.TCPGaveUp,
		})
	}
	return out, nil
}
