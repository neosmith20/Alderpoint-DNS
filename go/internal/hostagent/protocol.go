// Package hostagent defines the wire protocol and client for talking to
// apdns-hostagent -- a small, root-owned daemon that runs directly on
// the host (never inside a container) and is the *only* thing on this
// appliance with privileged access to host-level and cross-container
// operations the web control plane's own container must never have
// (raw dpkg/package install, host network interface changes, another
// container's journal/private SQLite store).
//
// Design, matching the explicit brief this package was built to satisfy:
//
//   - Unix domain socket only, never TCP -- there is no network path to
//     this daemon at all, from this host or any other.
//   - One request per connection: dial, write one JSON line, read one
//     JSON line, close. No session state, no multiplexing complexity to
//     get wrong.
//   - Every request is authenticated by the kernel-verified peer
//     credentials of the actual connecting process (SO_PEERCRED), not by
//     anything the client can lie about in its request body -- see
//     hostagentd's server.go for the check itself.
//   - Explicit allowlisted operations only (the Op* constants below are
//     the complete set that will ever exist). There is no generic
//     "run a command" or "run this SQL" operation, and there never will
//     be -- every handler in hostagentd is a specific, typed Go function
//     that itself never builds a shell string or SQL string from
//     caller-supplied data.
//   - Every request is audited server-side (hostagentd/audit.go) before
//     and after execution, redacting anything secret-shaped.
package hostagent

import "encoding/json"

// DefaultSocketPath is where the agent listens and where the client
// dials by default. Overridable (both sides) for tests, which use a
// fresh temp-dir socket instead.
const DefaultSocketPath = "/run/apdns-hostagent/agent.sock"

// Operation names -- the complete allowlist. hostagentd's dispatcher
// rejects anything not in this set before it ever reaches a handler.
const (
	OpLogsListUnits = "logs.list_units"
	OpLogsRead      = "logs.read"

	OpCacheStatus = "cache.status"
	OpCacheFlush  = "cache.flush"

	OpReplicationStatus = "replication.status"
	OpReplicationSync   = "replication.sync"

	OpNetworkStatus   = "network.status"
	OpNetworkApply    = "network.apply"
	OpNetworkConfirm  = "network.confirm"
	OpNetworkRollback = "network.rollback"

	OpUpdateCheck = "update.check"
	OpUpdateStage = "update.stage"
	OpUpdateApply = "update.apply"

	OpDNSRuntimeStatus  = "dns_runtime.status"
	OpDNSRuntimePromote = "dns_runtime.promote"

	OpAnalyticsSnapshotStatus  = "analytics_snapshot.status"
	OpAnalyticsSnapshotRefresh = "analytics_snapshot.refresh"
)

// Request is the single JSON line a client writes. RequestID is
// caller-chosen (the web binary uses its own request_id) and is echoed
// back unmodified, purely for correlating audit-log lines across the
// two processes -- it has no authorization meaning.
type Request struct {
	Op        string          `json:"op"`
	Params    json.RawMessage `json:"params,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
}

// Response is the single JSON line the agent writes back.
type Response struct {
	OK        bool            `json:"ok"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     string          `json:"error,omitempty"`
	Code      string          `json:"code,omitempty"` // machine-readable: "unauthorized" | "unknown_op" | "invalid_params" | "denied" | "internal"
	RequestID string          `json:"request_id,omitempty"`
}
