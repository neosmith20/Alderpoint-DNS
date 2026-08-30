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

	// Replication CA: the only part of internal/replication that needs
	// the root-owned agent boundary -- the CA private key is real
	// sensitive key material, sealed via the same secretstore engine
	// notifications/DNSCrypt already use. Generation build/apply, the
	// mTLS listener, and the replica poller are all plain SQLite + Go
	// crypto/tls, no privilege needed, and live entirely in
	// internal/replication inside the unprivileged web process.
	OpReplicationEnsureCA  = "replication.ensure_ca"
	OpReplicationIssueCert = "replication.issue_cert"

	OpNetworkStatus   = "network.status"
	OpNetworkApply    = "network.apply"
	OpNetworkConfirm  = "network.confirm"
	OpNetworkRollback = "network.rollback"

	OpUpdateCheck = "update.check"
	OpUpdateStage = "update.stage"
	OpUpdateApply = "update.apply"

	OpDNSRuntimeStatus  = "dns_runtime.status"
	OpDNSRuntimePromote = "dns_runtime.promote"

	// OpDNSRuntimeUpstreamStats polls the currently-live dnsdist
	// process's own real webserver/REST API (127.0.0.1-only, see
	// internal/dnscompile's DnsdistAPIKey field) for real per-backend
	// counters -- the same real per-resolver telemetry V1.1.1's own
	// analytics.py polled (see its dnsdist_server_state/
	// collect_upstream_resolver_aggregate), just from this side of the
	// same network-isolation boundary OpDNSPerfBenchmark's own doc
	// comment already explains (the unprivileged web container cannot
	// reach 127.0.0.1:<dnsdist port> on the host at all).
	OpDNSRuntimeUpstreamStats = "dns_runtime.upstream_stats"

	OpAnalyticsSnapshotStatus  = "analytics_snapshot.status"
	OpAnalyticsSnapshotRefresh = "analytics_snapshot.refresh"

	// OpAnalyticsClear performs Statistics' real "Clear" action -- a
	// genuine write against Python's live aggregates.db/raw-Parquet
	// tree, run from this already-root agent process (which already has
	// real, unrestricted host-path access to that data for the snapshot
	// publisher above) rather than by opening a second, write-capable
	// mount into the unprivileged web container. See
	// internal/hostagentd/ops_analyticsclear.go's doc comment for why
	// this is safe (a normal SQLite write connection, not the
	// immutable=1 read-side hack that caused a real corruption incident
	// earlier this migration).
	OpAnalyticsClear = "analytics.clear"

	// OpSecretsSeal encrypts a plaintext secret value with this agent's
	// own master key (never exposed to the caller) and returns only the
	// resulting ciphertext/nonce/key_version -- the one and only place
	// a secret's plaintext ever crosses this socket, and it flows in
	// exactly one direction (in, never back out). See
	// internal/hostagentd/ops_secrets.go and internal/secretstore.
	OpSecretsSeal = "secrets.seal"

	// OpSecretsNotifyTest decrypts a stored notification-provider
	// secret internally and immediately sends one real test
	// notification with it -- the plaintext value is never returned to
	// the caller, only the send outcome. A narrow, named operation, not
	// a generic decrypt endpoint.
	OpSecretsNotifyTest = "secrets.notify_test"

	// OpSecretsNotifySend is OpSecretsNotifyTest's real-dispatch sibling
	// -- same decrypt-and-send-immediately contract, but with a caller-
	// supplied message instead of the fixed test string, used by
	// internal/notifications' Dispatch (event-driven notifications, not
	// the "Send Test" button).
	OpSecretsNotifySend = "secrets.notify_send"

	// OpSecretsBackupCreate is the one deliberate, disclosed exception
	// to "a secret's plaintext never crosses this socket outbound": a
	// real disaster-recovery Secret Backup needs every current secret's
	// plaintext at least transiently, exactly like Python's own
	// SecretStore.export_all(). Unlike Python, that transient plaintext
	// never leaves apdns-hostagent at all -- this op decrypts every
	// sealed record the caller identifies internally, bulk-encrypts the
	// whole resulting payload with a second, dedicated backup key (also
	// sealed under the master key, generated once and reused), and
	// returns only that outer ciphertext. The web process holds real
	// secret plaintext at NO point in this flow, stricter than Python's
	// own design.
	OpSecretsBackupCreate = "secrets.backup_create"

	// OpSecretsBackupRestore is OpSecretsBackupCreate's inverse: given a
	// previously-created backup's ciphertext, decrypts it internally
	// with the backup key and RE-SEALS each recovered secret under the
	// current master key version, returning only the new sealed
	// (ciphertext/nonce/key_version) tuples -- never the recovered
	// plaintext itself. The caller writes those sealed tuples into its
	// own `secrets` table rows; it never sees what was inside.
	OpSecretsBackupRestore = "secrets.backup_restore"

	// OpDNSPerfBenchmark runs System Status's real "Safe DNS Benchmark"
	// -- a bounded, sequential set of DNS/DoT/DoH queries against the
	// real Go-managed dnsdist/BIND runtime, executed from this agent
	// because the web container's isolated bridge network cannot reach
	// 127.0.0.1:<dnsdist/BIND port> on the host at all (the same
	// network-isolation reasoning as Cache/Replication/Network
	// Configuration). See internal/hostagentd/ops_dnsperf.go.
	OpDNSPerfBenchmark = "dns_perf.benchmark"
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
