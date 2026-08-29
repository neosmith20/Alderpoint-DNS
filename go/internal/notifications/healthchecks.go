// Real periodic health-condition checkers, closing two more of the
// disclosed-but-unwired event categories (service_unavailable,
// replication_delayed) -- ported from app/notify_check.py's own design,
// read directly: edge-detected against a real notification_check_state
// table (0019_notification_check_state.sql) so a condition dispatches
// once when it starts (ok->bad) and once when it clears (bad->ok), not
// on every poll for an ongoing problem -- Dispatch's own cooldown/dedup
// is a second, independent layer of protection on top of this, exactly
// matching Python's own two-layer design.
//
// Still not attempted, disclosed rather than hidden: resolver_all_
// unavailable (needs a new per-transport (UDP/TCP/DoT/DoH) resolver
// prober -- internal/dnsperf has the real query primitives this would
// reuse, but wiring "probe every configured upstream endpoint on its
// own transport" is a real, separate piece of work) and backup_failure
// (this control plane has no scheduled/automatic backups yet -- see
// the Backup & Restore row in PARITY_MATRIX.md -- so there is no
// periodic background action for this category to observe failing;
// a manual Create failure is already surfaced synchronously to the
// caller in the HTTP response, which a background poller can't add to).
package notifications

import (
	"context"
	"fmt"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/replication"
)

func (s *Service) getCheckState(ctx context.Context, eventCategory, component string) string {
	var state string
	err := s.DB.QueryRowContext(ctx, `SELECT state FROM notification_check_state WHERE event_category=? AND component=?`, eventCategory, component).Scan(&state)
	if err != nil {
		return "" // no prior state recorded -- treated as "unknown", never as "ok" (a real first-ever bad reading must still fire)
	}
	return state
}

func (s *Service) setCheckState(ctx context.Context, eventCategory, component, state string) {
	s.DB.ExecContext(ctx, `
		INSERT INTO notification_check_state (event_category, component, state, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(event_category, component) DO UPDATE SET state=excluded.state, updated_at=excluded.updated_at`,
		eventCategory, component, state, time.Now().UTC().Format(time.RFC3339))
}

// fireEdge is the direct Go port of Python's _fire_edge: dispatch only
// on a real state transition.
func (s *Service) fireEdge(ctx context.Context, eventCategory, component string, currentlyBad bool, summaryBad, summaryOk, severity string) {
	previous := s.getCheckState(ctx, eventCategory, component)
	if currentlyBad {
		if previous != "bad" {
			s.Dispatch(ctx, eventCategory, severity, component, summaryBad, false)
		}
		s.setCheckState(ctx, eventCategory, component, "bad")
	} else {
		if previous == "bad" {
			s.Dispatch(ctx, eventCategory, severity, component, summaryOk, true)
		}
		s.setCheckState(ctx, eventCategory, component, "ok")
	}
}

// CheckServiceAvailability checks the real liveness of the two
// external, root-owned DNS-serving processes this control plane itself
// doesn't otherwise notify about (BIND and dnsdist) via the same
// dns_runtime.status hostagent op the DNS Runtime page's own status
// card already calls -- no new host-level check, just a new consumer
// of an already-real signal.
func (s *Service) CheckServiceAvailability(ctx context.Context, hostAgent *hostagent.Client) error {
	if hostAgent == nil {
		return nil // no DNS runtime configured for this deployment -- honestly nothing to check
	}
	var status struct {
		BindRunning    bool `json:"bind_running"`
		DnsdistRunning bool `json:"dnsdist_running"`
	}
	if err := hostAgent.Call(ctx, hostagent.OpDNSRuntimeStatus, nil, &status); err != nil {
		return fmt.Errorf("checking DNS runtime status: %w", err)
	}
	s.fireEdge(ctx, "service_unavailable", "BIND (named)", !status.BindRunning,
		"BIND (named) is not running", "BIND (named) is running again", "critical")
	s.fireEdge(ctx, "service_unavailable", "dnsdist", !status.DnsdistRunning,
		"dnsdist is not running", "dnsdist is running again", "critical")
	return nil
}

// healthySyncStatuses mirrors Python's own _HEALTHY_SYNC_STATUSES
// exactly -- "" (never attempted yet) is deliberately included: a
// brand-new, not-yet-synced replica is not itself an unhealthy state
// worth notifying about, only a sync that was actually ATTEMPTED and
// failed/errored/is unreachable is.
var healthySyncStatuses = map[string]bool{
	"": true, "success": true, "up_to_date": true, "skipped": true, "no_generation": true,
}

// CheckReplicationDelayed fires when an enrolled replica's own
// last_sync_status is not one of the healthy outcomes, or drift has
// been detected -- using internal/replication's own already-tracked
// settings (updated by every real SyncOnce/CheckDrift call), no new
// monitoring loop duplicated there. Matches Python's own
// check_replication() exactly: this checks the STATUS of the most
// recent sync attempt, not merely how long ago it was -- a replica
// whose primary has simply never published a generation yet
// (no_generation) is healthy, not "delayed".
func (s *Service) CheckReplicationDelayed(ctx context.Context, repl *replication.Service) error {
	if repl == nil {
		return nil
	}
	settings, err := repl.GetSettings(ctx)
	if err != nil {
		return fmt.Errorf("reading replication settings: %w", err)
	}
	if settings.Role != "replica" {
		return nil
	}
	unhealthyStatus := !healthySyncStatuses[settings.LastSyncStatus]
	bad := unhealthyStatus || settings.DriftDetected
	severity := "warning"
	if unhealthyStatus {
		severity = "critical"
	}
	detail := fmt.Sprintf("sync status %q", settings.LastSyncStatus)
	if settings.DriftDetected {
		detail += " with drift detected"
	}
	s.fireEdge(ctx, "replication_delayed", "Replication", bad,
		"Replication is unhealthy: "+detail, "Replication is healthy again", severity)
	return nil
}

// RunHealthChecksScheduler is a single, bounded goroutine polling both
// real checkers on a fixed tick -- same discipline as RunTLSExpiryScheduler
// and internal/blocklists.Service.RunScheduler.
func (s *Service) RunHealthChecksScheduler(ctx context.Context, hostAgent *hostagent.Client, repl *replication.Service, tick time.Duration) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.CheckServiceAvailability(ctx, hostAgent); err != nil && s.Log != nil {
				s.Log.Error("service availability check failed", "err", err)
			}
			if err := s.CheckReplicationDelayed(ctx, repl); err != nil && s.Log != nil {
				s.Log.Error("replication delayed check failed", "err", err)
			}
		}
	}
}
