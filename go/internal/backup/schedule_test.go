package backup

import (
	"context"
	"testing"
	"time"
)

func TestScheduleSettingsDefaultsMatchV111(t *testing.T) {
	svc := newTestService(t)
	got, err := svc.GetScheduleSettings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Errorf("expected scheduled backups disabled by default, got enabled")
	}
	if got.IntervalHours != 24 {
		t.Errorf("interval_hours = %d, want 24 (matching V1.1.1's own default)", got.IntervalHours)
	}
	if got.RetentionCount != 7 {
		t.Errorf("retention_count = %d, want 7 (matching V1.1.1's own default)", got.RetentionCount)
	}
	if got.LastRunAt != "" || got.LastStatus != "" {
		t.Errorf("expected no prior run recorded on a fresh instance, got %+v", got)
	}
}

func TestSetScheduleSettingsPersistsAndValidates(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	if err := svc.SetScheduleSettings(ctx, true, 12, 3); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetScheduleSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.IntervalHours != 12 || got.RetentionCount != 3 {
		t.Fatalf("settings did not persist, got %+v", got)
	}

	for _, tc := range []struct {
		name           string
		intervalHours  int
		retentionCount int
	}{
		{"interval too low", 0, 3},
		{"interval too high", 721, 3},
		{"negative retention", 12, -1},
		{"retention too high", 12, 101},
	} {
		if err := svc.SetScheduleSettings(ctx, true, tc.intervalHours, tc.retentionCount); err != ErrInvalidSchedule {
			t.Errorf("%s: expected ErrInvalidSchedule, got %v", tc.name, err)
		}
	}
	// A rejected update must not have clobbered the real, previously-saved settings.
	after, err := svc.GetScheduleSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.IntervalHours != 12 || after.RetentionCount != 3 {
		t.Fatalf("a rejected SetScheduleSettings call changed the stored settings: %+v", after)
	}
}

func TestRunScheduledTickOnceDisabledIsANoOp(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	result := svc.runScheduledTickOnce(ctx)
	if result.Ran {
		t.Fatal("expected no backup to run while disabled (the real default)")
	}
	backups, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("expected zero real backups created, got %d", len(backups))
	}
}

func TestRunScheduledTickOnceCreatesARealBackupWhenDue(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	if err := svc.SetScheduleSettings(ctx, true, 24, 7); err != nil {
		t.Fatal(err)
	}

	result := svc.runScheduledTickOnce(ctx)
	if !result.Ran || result.Failed {
		t.Fatalf("expected a real scheduled backup to run successfully, got %+v", result)
	}
	backups, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 || backups[0].Reason != "scheduled" {
		t.Fatalf("expected exactly one real backup with reason=scheduled, got %+v", backups)
	}

	settings, err := svc.GetScheduleSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.LastStatus != "succeeded" || settings.LastRunAt == "" {
		t.Fatalf("expected last_run_at/last_status to be recorded, got %+v", settings)
	}

	// A second tick immediately after must NOT create another backup --
	// the real interval (24h) has not elapsed.
	result2 := svc.runScheduledTickOnce(ctx)
	if result2.Ran {
		t.Fatal("expected the second tick to be a no-op (not yet due again)")
	}
	backupsAfter, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(backupsAfter) != 1 {
		t.Fatalf("expected still exactly one backup after a not-yet-due tick, got %d", len(backupsAfter))
	}
}

func TestDueForScheduledBackupNeverRunYetIsAlwaysDue(t *testing.T) {
	due := dueForScheduledBackup(ScheduleSettings{IntervalHours: 24}, time.Now())
	if !due {
		t.Fatal("a schedule with no prior run must be due immediately, matching every other 'due' check in this codebase")
	}
}

func TestDueForScheduledBackupRespectsInterval(t *testing.T) {
	now := time.Now().UTC()
	settings := ScheduleSettings{IntervalHours: 24, LastRunAt: now.Add(-25 * time.Hour).Format(time.RFC3339)}
	if !dueForScheduledBackup(settings, now) {
		t.Fatal("expected due once the interval has elapsed")
	}
	settings.LastRunAt = now.Add(-1 * time.Hour).Format(time.RFC3339)
	if dueForScheduledBackup(settings, now) {
		t.Fatal("expected NOT due before the interval has elapsed")
	}
}

func TestScheduledRetentionOnlyPrunesScheduledBackups(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// A real manual backup must survive scheduled retention regardless
	// of how low retention_count is set.
	if _, err := svc.Create(ctx, "manual"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetScheduleSettings(ctx, true, 24, 1); err != nil {
		t.Fatal(err)
	}
	// Two scheduled backups, forcing the interval check to always pass
	// by resetting last_run_at between them.
	if result := svc.runScheduledTickOnce(ctx); !result.Ran {
		t.Fatalf("expected first scheduled tick to run, got %+v", result)
	}
	svc.recordScheduleRun(ctx, "succeeded", "") // reset so the second tick is due too
	svc.DB.ExecContext(ctx, `UPDATE backup_schedule_settings SET last_run_at=? WHERE id=1`, time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339))
	if result := svc.runScheduledTickOnce(ctx); !result.Ran {
		t.Fatalf("expected second scheduled tick to run, got %+v", result)
	}

	backups, err := svc.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var manualCount, scheduledCount int
	for _, b := range backups {
		switch b.Reason {
		case "manual":
			manualCount++
		case "scheduled":
			scheduledCount++
		}
	}
	if manualCount != 1 {
		t.Fatalf("expected the real manual backup to survive scheduled retention untouched, got %d manual backups", manualCount)
	}
	if scheduledCount != 1 {
		t.Fatalf("expected scheduled retention (retention_count=1) to prune down to exactly 1 scheduled backup, got %d", scheduledCount)
	}
}
