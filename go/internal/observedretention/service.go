// Package observedretention implements owner-configurable Observed
// Clients retention/cleanup: a targeted per-client prune of the
// analytics query_events table (a client is removed only once its OWN
// most recent query is older than the configured retention window,
// never based on its earliest rows or a blanket age cutoff), with a
// manual "clean now" action and an optional daily/weekly/monthly
// schedule. Settings live in this control-plane database
// (observed_client_retention_settings, a singleton row -- see its own
// migration's doc comment); the actual clean/preview operations run
// against the separate analytics database via the same AnalyticsCleaner
// interface httpapi already depends on (dnsanalytics.Reader in
// production), so this package never needs its own DB handle to the
// analytics store.
//
// Scheduling follows internal/backup's own established RunScheduler
// pattern (a single bounded goroutine on a fixed poll tick, a pure
// dueForCleanup(settings, now) predicate for easy unit testing) rather
// than introducing a second scheduling mechanism.
package observedretention

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// AnalyticsCleaner is the exact method set this package needs from the
// analytics reader -- an interface (not a concrete *dnsanalytics.Reader)
// so tests can substitute a fake without a real analytics database.
type AnalyticsCleaner interface {
	PreviewStaleClients(ctx context.Context, cutoff int64) (int, error)
	CleanStaleClients(ctx context.Context, cutoff int64) (int, error)
}

// Service owns the singleton settings row in the control-plane database
// and drives cleanup against whatever AnalyticsCleaner is wired in.
// Analytics is nil-safe: matching every other optional analytics
// boundary in this codebase, a nil Analytics makes Preview/Clean report
// a clear "unavailable" error rather than panicking.
type Service struct {
	DB        *sql.DB
	Analytics AnalyticsCleaner
}

// Settings is the singleton row in observed_client_retention_settings.
type Settings struct {
	RetentionDays      int    `json:"retention_days"`
	Schedule           string `json:"schedule"` // "manual" | "daily" | "weekly" | "monthly"
	LastRunAt          string `json:"last_run_at,omitempty"`
	LastStatus         string `json:"last_status,omitempty"`
	LastError          string `json:"last_error,omitempty"`
	LastRemovedClients int    `json:"last_removed_clients"`
}

var validSchedules = map[string]bool{"manual": true, "daily": true, "weekly": true, "monthly": true}

var ErrInvalidSettings = errors.New("invalid observed-client retention settings")

func (s *Service) GetSettings(ctx context.Context) (Settings, error) {
	var out Settings
	var lastRunAt, lastStatus, lastError sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`SELECT retention_days, schedule, last_run_at, last_status, last_error, last_removed_clients
		 FROM observed_client_retention_settings WHERE id=1`,
	).Scan(&out.RetentionDays, &out.Schedule, &lastRunAt, &lastStatus, &lastError, &out.LastRemovedClients)
	if err != nil {
		return Settings{}, err
	}
	out.LastRunAt = lastRunAt.String
	out.LastStatus = lastStatus.String
	out.LastError = lastError.String
	return out, nil
}

// SetSettings validates and persists the owner's own choices --
// retention_days bounded 1..3650 (10 years; 0 would mean "delete
// everyone," which is exactly the "do not delete all observed clients
// blindly" behavior this feature must never allow) and schedule one of
// manual/daily/weekly/monthly.
func (s *Service) SetSettings(ctx context.Context, retentionDays int, schedule string) error {
	if retentionDays < 1 || retentionDays > 3650 {
		return ErrInvalidSettings
	}
	if !validSchedules[schedule] {
		return ErrInvalidSettings
	}
	_, err := s.DB.ExecContext(ctx,
		`UPDATE observed_client_retention_settings SET retention_days=?, schedule=? WHERE id=1`,
		retentionDays, schedule)
	return err
}

var ErrAnalyticsUnavailable = errors.New("observed-client retention: analytics is not configured for this deployment")

// cutoff converts a retention window (days, as of "now") into the Unix
// timestamp PreviewStaleClients/CleanStaleClients compare each client's
// own most recent query against.
func cutoff(retentionDays int, now time.Time) int64 {
	return now.AddDate(0, 0, -retentionDays).Unix()
}

// Preview reports how many distinct clients a cleanup at the currently
// configured retention_days would remove, without deleting anything --
// backs the "what will be removed" explanation the owner sees before
// running cleanup for real (manually or the settings form's own live
// preview).
func (s *Service) Preview(ctx context.Context, retentionDays int) (int, error) {
	if s.Analytics == nil {
		return 0, ErrAnalyticsUnavailable
	}
	return s.Analytics.PreviewStaleClients(ctx, cutoff(retentionDays, time.Now().UTC()))
}

// CleanNow runs a cleanup immediately at the currently persisted
// retention_days, records the outcome on the settings row (matching
// backup.Service's own recordScheduleRun convention), and returns how
// many distinct clients were removed. Used by both the owner's manual
// "Clean old observed clients" button and the scheduler below.
func (s *Service) CleanNow(ctx context.Context) (int, error) {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return 0, err
	}
	if s.Analytics == nil {
		s.recordRun(ctx, "failed", ErrAnalyticsUnavailable.Error(), 0)
		return 0, ErrAnalyticsUnavailable
	}
	removed, err := s.Analytics.CleanStaleClients(ctx, cutoff(settings.RetentionDays, time.Now().UTC()))
	if err != nil {
		s.recordRun(ctx, "failed", err.Error(), 0)
		return 0, err
	}
	s.recordRun(ctx, "succeeded", "", removed)
	return removed, nil
}

func (s *Service) recordRun(ctx context.Context, status, detail string, removed int) {
	s.DB.ExecContext(ctx,
		`UPDATE observed_client_retention_settings SET last_run_at=?, last_status=?, last_error=?, last_removed_clients=? WHERE id=1`,
		time.Now().UTC().Format(time.RFC3339), status, detail, removed)
}

// dueForCleanup reports whether enough time has passed since last_run_at
// for the currently-configured schedule to fire again. "manual" is
// never due (auto-clean off); a nil/empty last_run_at (never run yet) is
// always due for any non-manual schedule, matching
// backup.dueForScheduledBackup's own "first run is always due"
// convention.
func dueForCleanup(settings Settings, now time.Time) bool {
	interval, ok := scheduleInterval(settings.Schedule)
	if !ok {
		return false // "manual" (or an unrecognized value) never auto-runs
	}
	if settings.LastRunAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339, settings.LastRunAt)
	if err != nil {
		return true // an unparseable timestamp is not a reason to never run again
	}
	return now.Sub(last) >= interval
}

func scheduleInterval(schedule string) (time.Duration, bool) {
	switch schedule {
	case "daily":
		return 24 * time.Hour, true
	case "weekly":
		return 7 * 24 * time.Hour, true
	case "monthly":
		return 30 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

// TickResult, if observed via RunScheduler's onTick, carries whether
// this specific poll tick actually ran a cleanup and what it did --
// matching backup.ScheduleTickResult's own shape/purpose.
type TickResult struct {
	Ran     bool
	Failed  bool
	Removed int
	Detail  string
}

// RunScheduler is a single, bounded goroutine (not one per cleanup) that
// checks whether an auto-clean is due on a fixed poll tick and, if so,
// runs it via the same CleanNow the owner's own manual button uses.
func (s *Service) RunScheduler(ctx context.Context, pollTick time.Duration, onTick func(TickResult)) {
	ticker := time.NewTicker(pollTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result := s.runTickOnce(ctx)
			if onTick != nil {
				onTick(result)
			}
		}
	}
}

func (s *Service) runTickOnce(ctx context.Context) TickResult {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return TickResult{Failed: true, Detail: "reading retention settings: " + err.Error()}
	}
	if !dueForCleanup(settings, time.Now().UTC()) {
		return TickResult{}
	}
	removed, err := s.CleanNow(ctx)
	if err != nil {
		return TickResult{Ran: true, Failed: true, Detail: err.Error()}
	}
	return TickResult{Ran: true, Removed: removed}
}
