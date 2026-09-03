package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"alderpointdns/go-controlplane/internal/auth"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/updatehistory"
)

// hostagentUnavailable is the shared "no client configured / agent not
// reachable" reason, matching every other optional compatibility
// boundary's nil-safe contract (Analytics, RawQueryLog, TLSCert).
const hostagentUnavailable = "the host-control agent is not configured or not reachable"

// callAgent is the one place every hostagent-backed handler goes
// through: it turns "no client configured" and "agent unreachable" into
// the same honest degraded response shape, and a real ErrDenied from
// the agent into a 4xx with its actual reason -- never a generic 500
// that hides which case happened.
func callAgent[T any](s *Server, w http.ResponseWriter, r *http.Request, op string, params any) (T, bool) {
	var zero T
	if s.HostAgent == nil {
		WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": hostagentUnavailable})
		return zero, false
	}
	var out T
	err := s.HostAgent.Call(r.Context(), op, params, &out)
	if err == nil {
		return out, true
	}
	if errors.Is(err, hostagent.ErrDenied) {
		Err(http.StatusBadRequest, "denied", err.Error()).WriteJSON(w)
		return zero, false
	}
	WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": err.Error()})
	return zero, false
}

// --- Cache -------------------------------------------------------------

func (s *Server) handleCacheStatus(w http.ResponseWriter, r *http.Request) {
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpCacheStatus, nil)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleCacheFlush(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpCacheFlush, body)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// handleCacheDnsdistRestart is the real, safe alternative to a raw
// dnsdist cache "flush" (which OpCacheFlush honestly refuses -- dnsdist
// has no live administrative flush channel by design). A live UI defect
// this fixes: the Cache page exposed an "Attempt flush" button for
// dnsdist that could never succeed, since the backend always denies
// that request -- a broken button, not a degraded one. This action
// instead does the one thing that actually clears dnsdist's packet
// cache safely: re-runs the SAME stage -> validate -> promote -> reload
// -> health-check -> auto-rollback pipeline every other DNS-runtime-
// affecting change already goes through (internal/dnsruntime.
// Orchestrator.Apply -- see handleDNSRuntimeApply's own doc comment),
// which restarts dnsdist with its current, already-live-validated
// config. The result is a real internal/dnsruntime.Result (promoted/
// rolled_back/stage/detail), never a bare "ok" -- a failed health check
// here rolls back automatically and is reported honestly, exactly like
// every other DNS Runtime apply.
func (s *Server) handleCacheDnsdistRestart(w http.ResponseWriter, r *http.Request) {
	if s.DNSRuntime == nil {
		WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "unavailable", "detail": dnsRuntimeUnavailable})
		return
	}
	result := s.DNSRuntime.Apply(r.Context())
	s.notifyOnRollback(r, &result)
	WriteJSON(w, http.StatusOK, map[string]any{"dns_runtime": result})
}

// --- Network Configuration -----------------------------------------------

func (s *Server) handleNetworkStatus(w http.ResponseWriter, r *http.Request) {
	params := map[string]string{"interface": r.URL.Query().Get("interface")}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpNetworkStatus, params)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleNetworkApply(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpNetworkApply, body)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleNetworkConfirm(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpNetworkConfirm, body)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleNetworkRollback(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpNetworkRollback, body)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// --- Logs ------------------------------------------------------------------

func (s *Server) handleLogsListUnits(w http.ResponseWriter, r *http.Request) {
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpLogsListUnits, nil)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleLogsRead(w http.ResponseWriter, r *http.Request) {
	params := map[string]any{
		"unit":     r.PathValue("unit"),
		"lines":    intQuery(r, "lines", 200, 1, 2000),
		"severity": r.URL.Query().Get("severity"),
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpLogsRead, params)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// --- Software Updates ------------------------------------------------------

func (s *Server) handleUpdateHistory(w http.ResponseWriter, r *http.Request) {
	if s.UpdateHistory == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"entries": []any{}})
		return
	}
	entries, err := s.UpdateHistory.List(r.Context(), 50)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load update history").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpUpdateCheck, nil)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleUpdateStage(w http.ResponseWriter, r *http.Request) {
	var body json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpUpdateStage, body)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// handleUpdateApply enforces V1.1.1's own real, disclosed guarantee
// (system_software_updates.html: "A mandatory pre-upgrade backup is
// created before installation. If it fails, the update is aborted -- no
// changes are made.") -- a real appliance data backup (internal/backup,
// unencrypted like every other automated caller: an unattended/
// programmatic path can't hold a passphrase, same as the scheduler's own
// "scheduled" backups and Restore's own "pre-restore-safety" backup) is
// taken before the binary swap even starts. A failed backup aborts
// before OpUpdateApply is ever called -- this endpoint's OWN mandatory
// backup, distinct from and in addition to ops_update.go's own binary
// backup/rollback (that one recovers the Go binary itself; this one
// recovers the appliance's data if the new version turns out to need a
// schema rollback or otherwise corrupts state in a way a binary revert
// alone can't undo).
func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	// Capture from/to versions before anything else changes state -- see
	// internal/updatehistory's own doc comment for why this real record
	// exists at all (previously nothing about a past attempt was kept).
	var checkResult struct {
		CurrentVersion string `json:"current_version"`
		Staged         *struct {
			Version string `json:"version"`
		} `json:"staged"`
	}
	fromVersion, toVersion := s.Version, ""
	if s.HostAgent != nil {
		if err := s.HostAgent.Call(r.Context(), hostagent.OpUpdateCheck, nil, &checkResult); err == nil {
			if checkResult.CurrentVersion != "" {
				fromVersion = checkResult.CurrentVersion
			}
			if checkResult.Staged != nil {
				toVersion = checkResult.Staged.Version
			}
		}
	}

	backupRef := ""
	if s.Backup != nil {
		info, err := s.Backup.Create(r.Context(), "pre-update-safety", "")
		if err != nil {
			s.UpdateHistory.Record(r.Context(), updatehistory.RecordInput{
				FromVersion: fromVersion, ToVersion: toVersion, Source: "manual", Result: "failed",
				Error: "mandatory pre-upgrade backup failed: " + err.Error(),
			})
			Err(http.StatusInternalServerError, "backup_failed", "mandatory pre-upgrade backup failed -- update aborted, no changes were made: "+err.Error()).WriteJSON(w)
			return
		}
		backupRef = info.Filename
	}
	sess, _ := auth.FromContext(r.Context())
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpUpdateApply, nil)
	if !ok {
		s.AuditLog.Record(r.Context(), sess.AdminID, sess.Username, "software_update_install", false, clientIP(r), "")
		s.UpdateHistory.Record(r.Context(), updatehistory.RecordInput{
			FromVersion: fromVersion, ToVersion: toVersion, Source: "manual", Result: "failed", BackupRef: backupRef,
		})
		return
	}
	s.AuditLog.Record(r.Context(), sess.AdminID, sess.Username, "software_update_install", true, clientIP(r), "")
	s.UpdateHistory.Record(r.Context(), updatehistory.RecordInput{
		FromVersion: fromVersion, ToVersion: toVersion, Source: "manual", Result: "success", BackupRef: backupRef,
	})
	WriteJSON(w, http.StatusOK, result)
}
