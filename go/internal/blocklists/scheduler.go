package blocklists

import (
	"context"
	"time"
)

// RunScheduler is a single, bounded goroutine (not one per subscription)
// that polls for due subscriptions on a fixed tick and enqueues a job for
// each. It respects ctx cancellation for graceful shutdown and never
// blocks the caller -- each due subscription's pull still goes through
// the same bounded semaphore runJob/pullOne use, so a scheduler tick that
// finds many due subscriptions at once still can't spawn unbounded
// concurrent downloads.
func (s *Service) RunScheduler(ctx context.Context, tick time.Duration) {
	s.init()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDueSubscriptions(ctx)
		}
	}
}

func (s *Service) runDueSubscriptions(ctx context.Context) {
	nowStr := now()
	rows, err := s.DB.QueryContext(ctx,
		`SELECT subscription_id FROM blocklist_subscriptions
		 WHERE enabled=1 AND update_in_progress=0 AND next_update_at IS NOT NULL AND next_update_at <= ?`,
		nowStr)
	if err != nil {
		if s.Log != nil {
			s.Log.Error("scheduler: query due subscriptions failed", "err", err)
		}
		return
	}
	var due []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			due = append(due, id)
		}
	}
	rows.Close()

	for _, id := range due {
		s.runningMu.Lock()
		alreadyRunning := s.running[id]
		s.runningMu.Unlock()
		if alreadyRunning {
			continue
		}
		jobID, err := s.newJob(ctx, "single", []string{id})
		if err != nil {
			if s.Log != nil {
				s.Log.Error("scheduler: create job failed", "subscription_id", id, "err", err)
			}
			continue
		}
		go s.runJob(jobID, []string{id})
	}
}
