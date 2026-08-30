// Owner-configurable scheduled appliance backups -- field-matched
// against V1.1.1's own real settings (app/backup.py's settings():
// schedule_enabled, schedule_interval_hours default 24, retention_count
// default 7, read directly), but run by a bounded in-process goroutine
// (matching internal/blocklists.Service's own RunScheduler) instead of
// V1.1.1's systemd timer unit -- this appliance's other scheduled work
// (blocklist refresh, TLS-expiry/health-condition notification checks)
// already doesn't depend on systemd being present or reachable, and
// scheduled backups follow the same, already-established pattern rather
// than introducing a second, systemd-dependent one.
package backup

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ScheduleSettings is the singleton row in backup_schedule_settings.
type ScheduleSettings struct {
	Enabled        bool   `json:"enabled"`
	IntervalHours  int    `json:"interval_hours"`
	RetentionCount int    `json:"retention_count"`
	LastRunAt      string `json:"last_run_at,omitempty"`
	LastStatus     string `json:"last_status,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

func (s *Service) GetScheduleSettings(ctx context.Context) (ScheduleSettings, error) {
	var out ScheduleSettings
	var enabled int
	var lastRunAt, lastStatus, lastError sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`SELECT enabled, interval_hours, retention_count, last_run_at, last_status, last_error FROM backup_schedule_settings WHERE id=1`,
	).Scan(&enabled, &out.IntervalHours, &out.RetentionCount, &lastRunAt, &lastStatus, &lastError)
	if err != nil {
		return ScheduleSettings{}, err
	}
	out.Enabled = enabled != 0
	out.LastRunAt = lastRunAt.String
	out.LastStatus = lastStatus.String
	out.LastError = lastError.String
	return out, nil
}

var ErrInvalidSchedule = errors.New("invalid backup schedule settings")

// SetScheduleSettings validates and persists the owner's own choices --
// interval_hours bounded 1..720 and retention_count bounded 0..100,
// matching V1.1.1's own real validated ranges (app/backup.py's
// _validate_settings, read directly: schedule_interval_hours between 1
// and 720).
func (s *Service) SetScheduleSettings(ctx context.Context, enabled bool, intervalHours, retentionCount int) error {
	if intervalHours < 1 || intervalHours > 720 {
		return ErrInvalidSchedule
	}
	if retentionCount < 0 || retentionCount > 100 {
		return ErrInvalidSchedule
	}
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := s.DB.ExecContext(ctx,
		`UPDATE backup_schedule_settings SET enabled=?, interval_hours=?, retention_count=? WHERE id=1`,
		enabledInt, intervalHours, retentionCount)
	return err
}

func (s *Service) recordScheduleRun(ctx context.Context, status, detail string) {
	s.DB.ExecContext(ctx,
		`UPDATE backup_schedule_settings SET last_run_at=?, last_status=?, last_error=? WHERE id=1`,
		time.Now().UTC().Format(time.RFC3339), status, detail)
}

// dueForScheduledBackup reports whether enough time has passed since
// last_run_at for a new scheduled backup, given the currently-configured
// interval -- a nil/empty last_run_at (never run yet) is always due,
// matching every other "due" check in this codebase's own convention
// (a brand-new appliance shouldn't wait a full interval for its first
// automatic backup).
func dueForScheduledBackup(settings ScheduleSettings, now time.Time) bool {
	if settings.LastRunAt == "" {
		return true
	}
	last, err := time.Parse(time.RFC3339, settings.LastRunAt)
	if err != nil {
		return true // an unparseable timestamp is not a reason to never run again
	}
	return now.Sub(last) >= time.Duration(settings.IntervalHours)*time.Hour
}

// OnScheduledBackupComplete, if set, fires once after each scheduled-tick
// attempt (whether it actually ran a backup or found nothing due),
// carrying whether this specific tick performed a real backup and
// whether it failed -- the real hook internal/notifications' own
// CheckBackupFailure (an edge-detected fire-once-per-transition checker,
// matching every other health-condition check in that package) is wired
// to, closing the "no periodic background action for backup_failure to
// observe failing" gap this row's own doc comment used to disclose.
type ScheduleTickResult struct {
	Ran    bool
	Failed bool
	Detail string
}

// RunScheduler is a single, bounded goroutine (not one per backup) that
// checks whether a scheduled backup is due on a fixed poll tick and, if
// so, creates one for real via the same Create the owner's own "create a
// backup" button uses, then applies retention scoped to reason="scheduled"
// only (see applyRetention's own doc comment -- never touches manual or
// pre-restore-safety backups).
func (s *Service) RunScheduler(ctx context.Context, pollTick time.Duration, onTick func(ScheduleTickResult)) {
	ticker := time.NewTicker(pollTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result := s.runScheduledTickOnce(ctx)
			if onTick != nil {
				onTick(result)
			}
		}
	}
}

func (s *Service) runScheduledTickOnce(ctx context.Context) ScheduleTickResult {
	settings, err := s.GetScheduleSettings(ctx)
	if err != nil {
		return ScheduleTickResult{Failed: true, Detail: "reading schedule settings: " + err.Error()}
	}
	if !settings.Enabled {
		return ScheduleTickResult{}
	}
	if !dueForScheduledBackup(settings, time.Now().UTC()) {
		return ScheduleTickResult{}
	}
	_, err = s.Create(ctx, "scheduled")
	if err != nil {
		s.recordScheduleRun(ctx, "failed", err.Error())
		return ScheduleTickResult{Ran: true, Failed: true, Detail: err.Error()}
	}
	s.recordScheduleRun(ctx, "succeeded", "")
	_ = s.applyRetention(ctx, "scheduled", settings.RetentionCount, 0)
	return ScheduleTickResult{Ran: true}
}
