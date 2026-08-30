// Package dnsanalytics is the Go-native replacement for the
// internal/pyanalytics + internal/rawquerylog + internal/analyticssnapshot
// compatibility boundary those packages' own doc comments already
// describe: they exist to read data a separate Python process wrote.
// Python has since been fully decommissioned (see CUTOVER.md) -- there is
// no longer any process on the other side of that boundary. This package
// owns analytics end to end instead: it is both the producer (a dnstap
// Frame Streams receiver fed directly by dnsdist, see Writer) and the
// consumer (Reader, backing every /api/analytics/* and
// /api/statistics/* handler) of one SQLite database this process alone
// writes to.
//
// Design choice, stated plainly: there is exactly one durable table,
// query_events, one row per real DNS response dnsdist observed. Time
// series and top-domain aggregates are computed at read time via SQL
// GROUP BY against that table rather than maintained as separate
// incrementally-updated bucket tables -- simpler, and correct by
// construction (an aggregate can never drift from the raw rows it's
// computed from), at the cost of a full scan of the queried window on
// every read. That trade is fine at this appliance's real scale (a
// human loading a dashboard, not a query-hot-path operation) and is
// bounded further by prune() below.
//
// No pre-cutover history exists or is invented here: this store's
// oldest row is whenever the dnstap pipeline was first wired up and
// started receiving real traffic. See CUTOVER.md.
package dnsanalytics

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS query_events (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        INTEGER NOT NULL, -- unix seconds, response time
	domain    TEXT NOT NULL,    -- lowercase, no trailing dot
	qtype     TEXT NOT NULL DEFAULT '',
	rcode     TEXT NOT NULL DEFAULT '',
	protocol  TEXT NOT NULL DEFAULT '', -- "udp" or "tcp"
	client    TEXT NOT NULL DEFAULT '',
	latency_ms REAL NOT NULL DEFAULT 0,
	outcome   TEXT NOT NULL      -- "allowed" or "blocked", the real policy
	                             -- disposition dnsdist's own rule chain
	                             -- applied to this query (see
	                             -- internal/dnscompile's apdns_outcome
	                             -- tag), never inferred/guessed here from
	                             -- rcode alone.
);
CREATE INDEX IF NOT EXISTS idx_query_events_ts ON query_events(ts);
CREATE INDEX IF NOT EXISTS idx_query_events_domain_ts ON query_events(domain, ts);
CREATE INDEX IF NOT EXISTS idx_query_events_outcome_ts ON query_events(outcome, ts);

-- ingestion_events is Writer's durable diagnostic trail (see
-- writer.go's watchdog): every detected ingestion stall and every
-- forced-reconnect recovery attempt, so a stall's real history survives
-- this process restarting and is inspectable after the fact, not just
-- while a Claude/operator session happens to be tailing live logs.
CREATE TABLE IF NOT EXISTS ingestion_events (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     INTEGER NOT NULL,
	kind   TEXT NOT NULL, -- "stall_detected" | "recovery_attempted"
	detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_ingestion_events_ts ON ingestion_events(ts);

-- upstream_resolver_samples: one row per real-backend per poll, holding
-- the DELTA since the previous poll (see upstream_resolver_counter_state
-- below) -- never a raw cumulative snapshot, so a window query never
-- needs restart-aware clamping of its own; a resolver's activity in any
-- window is simply SUM(...) over its rows in that window, matching
-- query_events' own "aggregate computed at read time from raw rows"
-- design philosophy (see this package's own doc comment) while still
-- surviving a dnsdist restart cleanly (see RecordUpstreamSample).
CREATE TABLE IF NOT EXISTS upstream_resolver_samples (
	id                INTEGER PRIMARY KEY AUTOINCREMENT,
	ts                INTEGER NOT NULL,
	resolver_key      TEXT NOT NULL, -- the compiled dnsdist server name (see internal/dnscompile.UpstreamServerNamePrefix); stable across polls, not across a policy edit that removes/renames the endpoint
	protocol          TEXT NOT NULL DEFAULT '',
	address            TEXT NOT NULL DEFAULT '',
	health_state      TEXT NOT NULL DEFAULT '',
	queries_delta     INTEGER NOT NULL DEFAULT 0,
	responses_delta   INTEGER NOT NULL DEFAULT 0,
	failures_delta    INTEGER NOT NULL DEFAULT 0,
	timeouts_delta    INTEGER NOT NULL DEFAULT 0,
	latency_sum_ms    REAL NOT NULL DEFAULT 0,
	latency_count     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_upstream_resolver_samples_ts ON upstream_resolver_samples(ts);
CREATE INDEX IF NOT EXISTS idx_upstream_resolver_samples_key_ts ON upstream_resolver_samples(resolver_key, ts);

-- upstream_resolver_counter_state: the last-seen CUMULATIVE counters
-- for each resolver_key, purely so the next poll can compute a delta --
-- same role as V1.1.1's own upstream_resolver_counter_state table (read
-- directly from app/analytics.py, not guessed). A dnsdist restart resets
-- its own cumulative counters to zero; RecordUpstreamSample clamps a
-- decrease to a zero delta for that one poll rather than reporting a
-- fabricated negative or huge wrapped value, then resumes normal
-- delta-tracking from the new lower baseline -- identical to V1's own
-- _server_deltas.
CREATE TABLE IF NOT EXISTS upstream_resolver_counter_state (
	resolver_key                    TEXT PRIMARY KEY,
	queries                         INTEGER NOT NULL DEFAULT 0,
	responses                       INTEGER NOT NULL DEFAULT 0,
	send_errors                     INTEGER NOT NULL DEFAULT 0,
	health_check_failures           INTEGER NOT NULL DEFAULT 0,
	health_check_failures_timeout   INTEGER NOT NULL DEFAULT 0,
	tcp_connect_timeouts            INTEGER NOT NULL DEFAULT 0,
	tcp_read_timeouts               INTEGER NOT NULL DEFAULT 0,
	tcp_write_timeouts              INTEGER NOT NULL DEFAULT 0,
	tcp_gave_up                     INTEGER NOT NULL DEFAULT 0,
	updated_at                      TEXT NOT NULL DEFAULT ''
);
`

// Outcome values. Anything else received is stored verbatim (never
// dropped) but Reader queries only ever special-case these two.
const (
	OutcomeAllowed = "allowed"
	OutcomeBlocked = "blocked"
)

// Store opens (creating if needed) the durable analytics database at
// path and applies schema. Fails clearly (a real error, not a silent
// degraded mode) if path's directory doesn't exist or the file can't be
// created/opened -- callers (cmd/alderpointdns-go's "web" startup) are
// expected to treat this as a preflight failure, matching the owner's
// explicit requirement that missing required analytics configuration
// fail startup clearly rather than run degraded indefinitely. This is
// safe to require strictly because the DNS hot path (named/dnsdist,
// supervised by apdns-hostagent) is a wholly separate set of OS
// processes -- this process refusing to start never stops DNS from
// answering.
func Open(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			return nil, fmt.Errorf("analytics-db directory %q does not exist", dir)
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("opening analytics db %q: %w", path, err)
	}
	db.SetMaxOpenConns(1) // modernc.org/sqlite: one writer, avoids SQLITE_BUSY under our own concurrent use
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening analytics db %q: %w", path, err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("applying analytics schema to %q: %w", path, err)
	}
	return db, nil
}
