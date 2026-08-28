package dnsperf

import (
	"context"

	"alderpointdns/go-controlplane/internal/hostagent"
)

// HostAgentQuerier implements Querier by round-tripping through
// apdns-hostagent's OpDNSPerfBenchmark -- the real query exchange runs
// there (root, real host network namespace), never in this process.
// See internal/hostagentd/ops_dnsperf.go's doc comment for the safety
// design: only Target/Domain/Protocol/Queries/Timeout/Port/Path are
// sent, never a bare server, so this web process can never redirect
// the agent at an arbitrary host.
type HostAgentQuerier struct {
	Client *hostagent.Client
}

func (h HostAgentQuerier) Query(ctx context.Context, c BenchmarkCase) []Sample {
	var out struct {
		Samples []Sample `json:"samples"`
	}
	err := h.Client.Call(ctx, hostagent.OpDNSPerfBenchmark, map[string]any{
		"target": c.Target, "domain": c.Domain, "qtype": c.QType, "protocol": c.Protocol,
		"queries": c.Queries, "timeout_seconds": c.Timeout.Seconds(), "port": c.Port, "path": c.Path,
	}, &out)
	if err != nil {
		// Matches Python's own query_once/query_many_established
		// contract: a connection-setup failure is one honest failed
		// sample, never a crash or a silently-dropped case.
		return []Sample{{OK: false, Timeout: true, Error: err.Error()}}
	}
	return out.Samples
}
