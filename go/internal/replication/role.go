package replication

import (
	"context"
	"fmt"
)

// SetRole is the real role-transition action -- matches Python's own
// replication_role_post handler: switching TO primary starts (or
// prepares) the real listener; switching TO replica starts the real
// poller (only if enrollment material already exists -- a bare role
// change with no prior enrollment leaves the poller unable to start
// until Connect succeeds, matching Python's own ensure_replica_poller_
// running() "returns false if material is missing" contract); switching
// to any role stops whatever the previous role had running. Never
// interrupts DNS service either way -- this only starts/stops
// replication's own listener/poller goroutines.
func (s *Service) SetRole(ctx context.Context, role string) error {
	if !Roles[role] {
		return fmt.Errorf("%w: unknown role %q", ErrValidation, role)
	}
	previous, err := s.GetSettings(ctx)
	if err != nil {
		return err
	}
	if err := s.setSetting(ctx, "role", role); err != nil {
		return err
	}
	switch role {
	case "primary":
		s.StopPoller()
		if previous.Role != "primary" {
			s.EnsurePrimaryListenerRunning(ctx) // best-effort: a real CA/cert issuance failure here is surfaced on the next explicit action (Generate Token), not a fatal role-change error
		}
	case "replica":
		s.StopPrimaryListener()
		s.StartPoller(ctx)
	case "standalone":
		s.StopPrimaryListener()
		s.StopPoller()
	}
	return nil
}

// EnsurePrimaryListenerRunning is the real "start it if this node's
// role is primary" idempotent entry point -- matches Python's own
// ensure_primary_listener_running(), called both by role-switch and
// (defensively, since the listener may have failed to start earlier)
// every time an enrollment token is generated.
func (s *Service) EnsurePrimaryListenerRunning(ctx context.Context) error {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return err
	}
	if settings.Role != "primary" {
		return nil
	}
	return s.StartPrimaryListener(ctx)
}

func (s *Service) ListenerRunning() bool {
	return s.server != nil
}

func (s *Service) SyncHistory(ctx context.Context, limit int) ([]SyncResult, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT attempted_at, generation_number, result, message FROM replication_sync_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SyncResult{}
	for rows.Next() {
		var r SyncResult
		var genNum *int64
		if err := rows.Scan(&r.AttemptedAt, &genNum, &r.Result, &r.Message); err != nil {
			return nil, err
		}
		r.GenerationNumber = genNum
		out = append(out, r)
	}
	return out, rows.Err()
}
