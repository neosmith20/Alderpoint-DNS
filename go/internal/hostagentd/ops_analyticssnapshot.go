// Analytics snapshot publishing -- the root-owned half of the fix for
// the live "database disk image is malformed (11)" P0 (see
// internal/analyticssnapshot's own doc comment for the full design and
// internal/pyanalytics's for why the web process no longer reads
// Python's live aggregates.db directly at all). This file's whole job
// is periodic: call analyticssnapshot.Refresh on a fixed interval
// against the real, unrestricted host path (this process runs as root,
// so no read-only mount ever applies to it), and expose the result as
// two named, allowlisted operations -- no generic filesystem/shell
// access, matching every other operation in this package.
package hostagentd

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"alderpointdns/go-controlplane/internal/analyticssnapshot"
	"alderpointdns/go-controlplane/internal/hostagent"
)

// AnalyticsSnapshotConfig configures the periodic publisher.
type AnalyticsSnapshotConfig struct {
	// SourcePath is Python's real, live aggregates.db -- the actual host
	// path (never a container-mounted one; this process needs no mount
	// at all to reach it, root already has full access).
	SourcePath string
	// PublishedDir is where completed generations are published (see
	// internal/analyticssnapshot's layout doc comment) -- the Go web
	// container mounts this directory read-only.
	PublishedDir string
	// StagingDir is a scratch area on the SAME filesystem as
	// PublishedDir (so the final publish step is a same-filesystem
	// rename, genuinely atomic) that only this process ever touches.
	StagingDir string
	// Interval between refreshes. <=0 defaults to 15s (matching
	// analytics-worker's own heartbeat interval, see
	// internal/pyanalytics/health.go's analyticsWorkerIntervalSeconds).
	Interval time.Duration
	// Retain is how many generations Refresh keeps around; <2 defaults
	// to 3 (see analyticssnapshot.Refresh's own doc comment on why at
	// least 2 is required).
	Retain int
}

// AnalyticsSnapshotStatus is analytics_snapshot.status's response shape.
type AnalyticsSnapshotStatus struct {
	Configured        bool    `json:"configured"`
	LastRefreshAt     float64 `json:"last_refresh_at,omitempty"`
	LastRefreshOK     bool    `json:"last_refresh_ok"`
	LastError         string  `json:"last_error,omitempty"`
	LastGeneration    int64   `json:"last_generation,omitempty"`
	SourceJournalMode string  `json:"source_journal_mode,omitempty"`
	RefreshCount      int64   `json:"refresh_count"`
	FailureCount      int64   `json:"failure_count"`
}

type analyticsSnapshotState struct {
	mu     sync.Mutex
	status AnalyticsSnapshotStatus
	cfg    AnalyticsSnapshotConfig
}

func (st *analyticsSnapshotState) refreshOnce(ctx context.Context) AnalyticsSnapshotStatus {
	m, err := analyticssnapshot.Refresh(ctx, st.cfg.SourcePath, st.cfg.PublishedDir, st.cfg.StagingDir, st.cfg.Retain)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.status.Configured = true
	st.status.LastRefreshAt = float64(time.Now().Unix())
	if err != nil {
		st.status.LastRefreshOK = false
		st.status.LastError = err.Error()
		st.status.FailureCount++
	} else {
		st.status.LastRefreshOK = true
		st.status.LastError = ""
		st.status.LastGeneration = m.Generation
		st.status.SourceJournalMode = m.SourceJournalMode
		st.status.RefreshCount++
	}
	return st.status
}

// RegisterAnalyticsSnapshotOps starts the periodic publisher (a
// background goroutine, stopped via the returned func) and registers
// analytics_snapshot.status (report-only) and analytics_snapshot.refresh
// (force one refresh now, used by tests and an operator-triggered
// retry) -- neither takes any parameter beyond the fixed request
// envelope every operation already requires, matching this package's
// no-generic-input discipline.
func RegisterAnalyticsSnapshotOps(s *Server, cfg AnalyticsSnapshotConfig) func() {
	if cfg.Interval <= 0 {
		cfg.Interval = 15 * time.Second
	}
	if cfg.Retain < 2 {
		cfg.Retain = 3
	}
	st := &analyticsSnapshotState{cfg: cfg}

	s.Register(hostagent.OpAnalyticsSnapshotStatus, func(ctx context.Context, params json.RawMessage) (any, error) {
		st.mu.Lock()
		defer st.mu.Unlock()
		return st.status, nil
	})
	s.Register(hostagent.OpAnalyticsSnapshotRefresh, func(ctx context.Context, params json.RawMessage) (any, error) {
		status := st.refreshOnce(ctx)
		return status, nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Publish one generation immediately at startup rather than
		// waiting a full interval -- otherwise the web process would
		// report "no snapshot published yet" for up to Interval after
		// every apdns-hostagent restart, a real, avoidable availability
		// gap.
		st.refreshOnce(ctx)
		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if status := st.refreshOnce(ctx); !status.LastRefreshOK {
					s.Log.Warn("analytics snapshot refresh failed -- Dashboard/Top Domains will report degraded once the existing snapshot goes stale",
						"source", cfg.SourcePath, "published_dir", cfg.PublishedDir, "error", status.LastError)
				}
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}
