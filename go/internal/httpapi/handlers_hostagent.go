package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"alderpointdns/go-controlplane/internal/hostagent"
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

// --- Replication ---------------------------------------------------------

func (s *Server) handleReplicationStatus(w http.ResponseWriter, r *http.Request) {
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpReplicationStatus, nil)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (s *Server) handleReplicationSync(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PeerNodeID string `json:"peer_node_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid JSON body").WriteJSON(w)
		return
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpReplicationSync, body)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
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
	params := map[string]any{"unit": r.PathValue("unit"), "lines": intQuery(r, "lines", 200, 1, 2000)}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpLogsRead, params)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// --- Software Updates ------------------------------------------------------

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

func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpUpdateApply, nil)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}
