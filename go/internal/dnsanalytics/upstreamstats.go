// Real "Top Upstream Resolvers" telemetry -- the Go-native counterpart
// to V1.1.1's own app/analytics.py collect_upstream_resolver_aggregate
// (read directly from the real shipped package, not guessed): each
// poll's real per-backend counters (from internal/hostagentd's
// dns_runtime.upstream_stats op, which itself polls dnsdist's own real
// webserver API) are turned into a DELTA against the last-seen
// cumulative value and stored as one row per backend per poll -- see
// store.go's own schema comment for exactly why deltas, not
// cumulative snapshots, are what's stored.
package dnsanalytics

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"alderpointdns/go-controlplane/internal/pyanalytics"
)

// UpstreamServerSample is the minimal shape RecordUpstreamSample needs
// from one polled backend -- deliberately independent of
// internal/dnsruntime.UpstreamServerStat (this package must not import
// the web-process-only dnsruntime package, and dnsruntime must not
// import this one either, to keep the dependency graph a straight
// line: cmd/alderpointdns-go wires the two together).
type UpstreamServerSample struct {
	ResolverKey string // dnsdist's own server "name" -- see internal/dnscompile.UpstreamServerNamePrefix
	Protocol    string
	Address     string
	HealthState string
	Latency     float64 // milliseconds; dnsdist reports this as a live rolling average, not a counter

	Queries                    int64
	Responses                  int64
	SendErrors                 int64
	HealthCheckFailures        int64
	HealthCheckFailuresTimeout int64
	TCPConnectTimeouts         int64
	TCPReadTimeouts            int64
	TCPWriteTimeouts           int64
	TCPGaveUp                  int64
}

const maxPlausibleUpstreamLatencyMS = 60_000 // matches Writer's own MAX_PLAUSIBLE_LATENCY_MS posture: a live rolling average outside this range is a bad reading, not a real one

// RecordUpstreamSample computes and stores one delta row per sample
// against upstream_resolver_counter_state, matching V1.1.1's own
// _server_deltas exactly: a counter that decreased since the last poll
// (a dnsdist restart resets it to near-zero) contributes a zero delta
// for that one poll rather than a fabricated negative/huge value, and
// counter_state is unconditionally advanced to the new cumulative
// value either way so the NEXT poll's delta is correct again.
func RecordUpstreamSample(ctx context.Context, db *sql.DB, samples []UpstreamServerSample, ts time.Time) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	unixTS := ts.Unix()
	for _, s := range samples {
		var prevQueries, prevResponses, prevSendErrors, prevHCF, prevHCFTimeout int64
		var prevTCPConnect, prevTCPRead, prevTCPWrite, prevTCPGaveUp int64
		row := tx.QueryRowContext(ctx, `SELECT queries, responses, send_errors, health_check_failures, health_check_failures_timeout, tcp_connect_timeouts, tcp_read_timeouts, tcp_write_timeouts, tcp_gave_up FROM upstream_resolver_counter_state WHERE resolver_key = ?`, s.ResolverKey)
		hadPrev := row.Scan(&prevQueries, &prevResponses, &prevSendErrors, &prevHCF, &prevHCFTimeout, &prevTCPConnect, &prevTCPRead, &prevTCPWrite, &prevTCPGaveUp) == nil

		delta := func(current, previous int64) int64 {
			if !hadPrev || current < previous {
				return 0
			}
			return current - previous
		}
		queriesDelta := delta(s.Queries, prevQueries)
		responsesDelta := delta(s.Responses, prevResponses)
		if responsesDelta > queriesDelta && queriesDelta > 0 {
			responsesDelta = queriesDelta // matches V1's own min(responses, queries) clamp
		}
		timeoutsDelta := delta(s.HealthCheckFailuresTimeout, prevHCFTimeout) + delta(s.TCPConnectTimeouts, prevTCPConnect) +
			delta(s.TCPReadTimeouts, prevTCPRead) + delta(s.TCPWriteTimeouts, prevTCPWrite) + delta(s.TCPGaveUp, prevTCPGaveUp)
		failuresDelta := int64(0)
		if queriesDelta > responsesDelta {
			failuresDelta = queriesDelta - responsesDelta
		}
		failuresDelta += delta(s.SendErrors, prevSendErrors) + delta(s.HealthCheckFailures, prevHCF)

		latencyCount := int64(0)
		latencySum := 0.0
		if s.Latency > 0 && s.Latency <= maxPlausibleUpstreamLatencyMS {
			if responsesDelta > 0 {
				latencyCount = responsesDelta
			} else {
				latencyCount = 1
			}
			latencySum = s.Latency * float64(latencyCount)
		}

		if _, err := tx.ExecContext(ctx, `
			INSERT INTO upstream_resolver_samples(ts, resolver_key, protocol, address, health_state, queries_delta, responses_delta, failures_delta, timeouts_delta, latency_sum_ms, latency_count)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			unixTS, s.ResolverKey, s.Protocol, s.Address, s.HealthState, queriesDelta, responsesDelta, failuresDelta, timeoutsDelta, latencySum, latencyCount,
		); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO upstream_resolver_counter_state(resolver_key, queries, responses, send_errors, health_check_failures, health_check_failures_timeout, tcp_connect_timeouts, tcp_read_timeouts, tcp_write_timeouts, tcp_gave_up, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(resolver_key) DO UPDATE SET
				queries=excluded.queries, responses=excluded.responses, send_errors=excluded.send_errors,
				health_check_failures=excluded.health_check_failures, health_check_failures_timeout=excluded.health_check_failures_timeout,
				tcp_connect_timeouts=excluded.tcp_connect_timeouts, tcp_read_timeouts=excluded.tcp_read_timeouts,
				tcp_write_timeouts=excluded.tcp_write_timeouts, tcp_gave_up=excluded.tcp_gave_up, updated_at=excluded.updated_at`,
			s.ResolverKey, s.Queries, s.Responses, s.SendErrors, s.HealthCheckFailures, s.HealthCheckFailuresTimeout,
			s.TCPConnectTimeouts, s.TCPReadTimeouts, s.TCPWriteTimeouts, s.TCPGaveUp, ts.UTC().Format(time.RFC3339),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PruneUpstreamSamples deletes sample rows older than cutoff -- called
// from the same prune pass query_events already goes through (see
// writer.go's prune()), so this table's retention tracks the rest of
// analytics rather than growing unbounded on its own schedule.
func PruneUpstreamSamples(ctx context.Context, db *sql.DB, cutoff int64) error {
	_, err := db.ExecContext(ctx, `DELETE FROM upstream_resolver_samples WHERE ts < ?`, cutoff)
	return err
}

// UpstreamStatsFetch is satisfied by a closure over
// internal/dnsruntime.Orchestrator.UpstreamStats -- kept as a plain
// function type, not an interface over that package's own result type,
// so this package never has to import internal/dnsruntime (see this
// file's own doc comment on the dependency-graph shape); cmd/
// alderpointdns-go is what actually wires the two together.
type UpstreamStatsFetch func(ctx context.Context) ([]UpstreamServerSample, error)

// RunUpstreamStatsScheduler polls fetch on a fixed tick and records
// whatever it returns -- same single-bounded-goroutine discipline as
// notifications.RunHealthChecksScheduler. A fetch error (host-agent
// unreachable, no DNS runtime configured, dnsdist API not yet known)
// is logged and skipped, never fatal -- this scheduler's only job is
// best-effort telemetry, and it must never affect real DNS serving.
func RunUpstreamStatsScheduler(ctx context.Context, db *sql.DB, fetch UpstreamStatsFetch, tick time.Duration, log *slog.Logger) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	poll := func() {
		samples, err := fetch(ctx)
		if err != nil {
			if log != nil {
				log.Warn("dnsanalytics: upstream resolver stats poll failed", "err", err)
			}
			return
		}
		if len(samples) == 0 {
			return // honestly nothing to record yet (no host-agent, no API key promoted, or zero apdns_-named backends) -- not an error
		}
		if err := RecordUpstreamSample(ctx, db, samples, time.Now()); err != nil && log != nil {
			log.Warn("dnsanalytics: recording upstream resolver sample failed", "err", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}

// TopUpstreams sums every resolver_key's real delta rows since `since`,
// ordered by real query volume -- most-active-first, matching V1's own
// ORDER BY value DESC. protocol/address/health_state are taken from
// each resolver's single most recent sample in the window (a live
// value, not summed) -- matching V1's own GROUP BY including those
// columns, which has the identical effect for a resolver whose
// protocol/address didn't change mid-window.
func (r *Reader) TopUpstreams(ctx context.Context, since time.Time, limit int) ([]pyanalytics.UpstreamResolverSummary, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := r.DB.QueryContext(ctx, `
		SELECT
			resolver_key,
			(SELECT protocol FROM upstream_resolver_samples s2 WHERE s2.resolver_key = s.resolver_key AND s2.ts >= ? ORDER BY s2.ts DESC LIMIT 1),
			(SELECT address FROM upstream_resolver_samples s2 WHERE s2.resolver_key = s.resolver_key AND s2.ts >= ? ORDER BY s2.ts DESC LIMIT 1),
			(SELECT health_state FROM upstream_resolver_samples s2 WHERE s2.resolver_key = s.resolver_key AND s2.ts >= ? ORDER BY s2.ts DESC LIMIT 1),
			sum(queries_delta), sum(responses_delta), sum(failures_delta), sum(timeouts_delta),
			sum(latency_sum_ms), sum(latency_count)
		FROM upstream_resolver_samples s
		WHERE ts >= ?
		GROUP BY resolver_key
		ORDER BY sum(queries_delta) DESC, resolver_key
		LIMIT ?`,
		since.Unix(), since.Unix(), since.Unix(), since.Unix(), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []pyanalytics.UpstreamResolverSummary
	for rows.Next() {
		var s pyanalytics.UpstreamResolverSummary
		var latencySum float64
		var latencyCount int64
		if err := rows.Scan(&s.ResolverKey, &s.Protocol, &s.Address, &s.HealthState,
			&s.QueriesAttempted, &s.SuccessfulResp, &s.Failures, &s.Timeouts, &latencySum, &latencyCount); err != nil {
			return nil, err
		}
		if latencyCount > 0 {
			s.AvgLatencyMS = latencySum / float64(latencyCount)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
