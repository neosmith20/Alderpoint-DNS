package replication

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SyncResult mirrors Python's own replica_sync_once() result shape.
type SyncResult struct {
	AttemptedAt      string `json:"attempted_at"`
	GenerationNumber *int64 `json:"generation_number,omitempty"`
	Result           string `json:"result"` // success | up_to_date | no_generation | unreachable | skipped | failed | error
	Message          string `json:"message"`
}

func (s *Service) recordSyncHistory(ctx context.Context, r SyncResult) {
	s.DB.ExecContext(ctx, `INSERT INTO replication_sync_history (attempted_at, generation_number, result, message) VALUES (?, ?, ?, ?)`,
		r.AttemptedAt, r.GenerationNumber, r.Result, r.Message)
	s.setSetting(ctx, "last_sync_status", r.Result)
	s.setSetting(ctx, "last_sync_at", now())
}

// SyncOnce is the full replica apply pipeline -- never returns a Go
// error for an ordinary sync failure (primary unreachable, hash
// mismatch, apply failure); every such case is recorded to
// replication_sync_history and returned in the result, exactly matching
// Python's own "never crash the polling loop, DNS keeps serving
// whatever was last applied" contract.
func (s *Service) SyncOnce(ctx context.Context, force bool) SyncResult {
	result := SyncResult{AttemptedAt: now(), Result: "error"}
	defer func() { s.recordSyncHistory(ctx, result) }()

	settings, err := s.GetSettings(ctx)
	if err != nil {
		result.Message = err.Error()
		return result
	}
	if settings.Paused && !force {
		result.Result, result.Message = "skipped", "replication is paused"
		return result
	}

	rc, err := s.buildReplicaTransportConfig(ctx)
	if err != nil {
		result.Result, result.Message = "unreachable", err.Error()
		return result
	}
	client, err := rc.httpClient()
	if err != nil {
		result.Result, result.Message = "unreachable", err.Error()
		return result
	}
	url := fmt.Sprintf("https://%s:%s/replication/generations/latest", rc.primaryHost, rc.primaryPort)
	status, data, err := httpsJSONRequest(ctx, client, "GET", url, nil)
	if err != nil {
		result.Result, result.Message = "unreachable", err.Error()
		return result
	}
	if status != 200 {
		result.Result, result.Message = "unreachable", fmt.Sprintf("primary returned HTTP %d", status)
		return result
	}
	genRaw, ok := data["generation"]
	if !ok || genRaw == nil {
		result.Result, result.Message = "no_generation", "primary has not published a generation yet"
		return result
	}
	genJSON, _ := json.Marshal(genRaw)
	var gen Generation
	if err := json.Unmarshal(genJSON, &gen); err != nil {
		result.Result, result.Message = "failed", "malformed generation payload from primary"
		return result
	}
	result.GenerationNumber = &gen.GenerationNumber

	if !force && gen.GenerationNumber <= settings.LastAppliedGeneration {
		result.Result, result.Message = "up_to_date", fmt.Sprintf("already at generation %d", settings.LastAppliedGeneration)
		return result
	}
	if gen.SchemaVersion > SchemaVersion {
		result.Result = "failed"
		result.Message = fmt.Sprintf("generation requires schema version %d, this replica only supports %d", gen.SchemaVersion, SchemaVersion)
		return result
	}

	actualHash, err := ContentHash(gen.Sections)
	if err != nil || actualHash != gen.ContentHash {
		result.Result, result.Message = "failed", "payload content hash did not match the generation's declared hash"
		s.ackGeneration(ctx, client, rc, gen.GenerationNumber, gen.ContentHash, "failed", result.Message)
		return result
	}

	snapshot, err := BuildPayload(ctx, s.DB)
	if err != nil {
		result.Result, result.Message = "failed", fmt.Sprintf("failed to snapshot current state: %v", err)
		return result
	}

	if err := ApplySections(ctx, s.DB, gen.Sections); err != nil {
		result.Result, result.Message = "failed", fmt.Sprintf("failed to apply staged data: %v", err)
		s.ackGeneration(ctx, client, rc, gen.GenerationNumber, gen.ContentHash, "failed", result.Message)
		return result
	}

	// This Go control plane's own DNS runtime compiler (internal/
	// dnsruntime) is applied by the caller (the HTTP handler / poller
	// wiring in cmd/alderpointdns-go), not here -- internal/replication
	// stays dependency-free of the runtime-compiler package, matching
	// this codebase's existing layering (internal/blocklists,
	// internal/localdns etc. all apply their own DB changes and leave
	// DNS-runtime recompilation to the caller too). DeployFn is set by
	// that caller; if unset, the sync is considered applied at the
	// database level only (still real, still rollback-safe) with no
	// runtime recompilation attempted.
	if s.DeployFn != nil {
		ok, deployMsg := s.DeployFn(ctx)
		if !ok {
			if err := ApplySections(ctx, s.DB, snapshot); err != nil && s.Log != nil {
				s.Log.Error("replication: failed to restore snapshot after a failed deploy", "err", err)
			}
			result.Result = "failed"
			result.Message = "deploy failed, rolled back: " + truncate(deployMsg, 500)
			s.ackGeneration(ctx, client, rc, gen.GenerationNumber, gen.ContentHash, "failed", result.Message)
			return result
		}
	}

	s.setSetting(ctx, "last_applied_generation", fmt.Sprintf("%d", gen.GenerationNumber))
	s.setSetting(ctx, "last_applied_hash", gen.ContentHash)
	s.setSetting(ctx, "drift_detected", "0")
	s.ackGeneration(ctx, client, rc, gen.GenerationNumber, gen.ContentHash, "success", "applied")
	result.Result, result.Message = "success", fmt.Sprintf("applied generation %d", gen.GenerationNumber)
	return result
}

func (s *Service) ackGeneration(ctx context.Context, client *http.Client, rc *replicaTransportConfig, genNumber int64, contentHash, resultStr, message string) {
	url := fmt.Sprintf("https://%s:%s/replication/ack", rc.primaryHost, rc.primaryPort)
	httpsJSONRequest(ctx, client, "POST", url, map[string]any{
		"generation_number": genNumber, "content_hash": contentHash, "result": resultStr, "message": message,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// DeployFn lets the caller (cmd/alderpointdns-go) hook in real DNS-
// runtime recompilation after a successful apply, without this package
// importing internal/dnsruntime directly (see SyncOnce's own comment).
type DeployFunc func(ctx context.Context) (ok bool, output string)

// CheckDrift recomputes this replica's own live-table hash and compares
// it against the hash it last successfully applied -- matches Python's
// check_drift() exactly.
func (s *Service) CheckDrift(ctx context.Context) (drifted bool, localHash, expectedHash string, err error) {
	settings, err := s.GetSettings(ctx)
	if err != nil {
		return false, "", "", err
	}
	sections, err := BuildPayload(ctx, s.DB)
	if err != nil {
		return false, "", "", err
	}
	localHash, err = ContentHash(sections)
	if err != nil {
		return false, "", "", err
	}
	drifted = settings.LastAppliedHash != "" && localHash != settings.LastAppliedHash
	s.setSetting(ctx, "drift_detected", strFromBool(drifted))
	s.setSetting(ctx, "drift_checked_at", now())
	return drifted, localHash, settings.LastAppliedHash, nil
}

// --- background poller ------------------------------------------------

type replicaPoller struct {
	mu      sync.Mutex
	stopCh  chan struct{}
	wakeCh  chan struct{}
	running bool
}

// StartPoller starts (idempotently) this node's own background replica
// poll loop -- fixed interval on success, capped exponential backoff on
// failure, matching Python's own ReplicaPoller exactly.
func (s *Service) StartPoller(ctx context.Context) {
	if s.poller != nil && s.poller.running {
		return
	}
	s.poller = &replicaPoller{stopCh: make(chan struct{}), wakeCh: make(chan struct{}, 1), running: true}
	go s.pollerLoop(ctx, s.poller)
}

func (s *Service) StopPoller() {
	if s.poller == nil {
		return
	}
	s.poller.mu.Lock()
	if s.poller.running {
		close(s.poller.stopCh)
		s.poller.running = false
	}
	s.poller.mu.Unlock()
	s.poller = nil
}

// SyncNow wakes the poller for an immediate forced sync, or (if no
// poller is running) performs the sync directly -- matches Python's
// trigger_sync_now().
func (s *Service) SyncNow(ctx context.Context) SyncResult {
	if s.poller != nil {
		select {
		case s.poller.wakeCh <- struct{}{}:
		default:
		}
	}
	return s.SyncOnce(ctx, true)
}

func (s *Service) pollerLoop(ctx context.Context, p *replicaPoller) {
	settings, err := s.GetSettings(ctx)
	interval := DefaultPollIntervalSec
	if err == nil && settings.PollIntervalSeconds > 0 {
		interval = settings.PollIntervalSeconds
	}
	backoff := interval
	for {
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		default:
		}
		result := s.SyncOnce(ctx, false)
		switch result.Result {
		case "success", "up_to_date", "skipped", "no_generation":
			backoff = interval
		default:
			backoff *= 2
			if backoff > MaxBackoffSeconds {
				backoff = MaxBackoffSeconds
			}
		}
		select {
		case <-p.stopCh:
			return
		case <-ctx.Done():
			return
		case <-p.wakeCh:
		case <-time.After(time.Duration(backoff) * time.Second):
		}
	}
}
