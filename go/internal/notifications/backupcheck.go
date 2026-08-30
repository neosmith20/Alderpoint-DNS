// CheckBackupFailure closes the last previously-disclosed unwired
// event category (backup_failure) now that internal/backup has a real
// periodic action to observe: scheduled backups (internal/backup's own
// RunScheduler). Unlike the other health checks in healthchecks.go,
// this one isn't itself polling anything -- it's invoked once per
// scheduled-backup tick, from main.go's own wiring of
// backup.Service.RunScheduler's onTick callback, and only updates edge
// state on a tick that actually attempted a backup (Ran==true); a tick
// that found nothing due yet is not itself informative and must not
// clear or set any state.
package notifications

import "context"

// BackupTickResult is a minimal, notifications-package-local mirror of
// internal/backup.ScheduleTickResult -- avoiding a dependency from
// internal/notifications on internal/backup for a single two-field
// struct (this package already stays a leaf dependency of the other
// service packages, never the reverse).
type BackupTickResult struct {
	Ran    bool
	Failed bool
	Detail string
}

func (s *Service) CheckBackupFailure(ctx context.Context, result BackupTickResult) {
	if !result.Ran {
		return // nothing attempted this tick -- not evidence of anything, good or bad
	}
	summaryBad := "The scheduled backup failed"
	if result.Detail != "" {
		summaryBad += ": " + result.Detail
	}
	s.fireEdge(ctx, "backup_failure", "Scheduled backup", result.Failed,
		summaryBad, "Scheduled backups are succeeding again", "warning")
}
