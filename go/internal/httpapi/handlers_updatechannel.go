// Software Updates: the real remote-check half (internal/softwareupdates
// -- a GitHub Releases channel, owner-confirmed real coordinates, not
// invented). handleUpdateDownloadAndStage deliberately does NOT
// duplicate any verification logic: it downloads+checksums against the
// published SHA256SUMS (softwareupdates.Service.FetchLatestDeb), then
// hands the bytes to the exact same internal/hostagentd OpUpdateStage
// operation the pre-existing manual .deb upload flow already uses --
// one staging/verification pipeline, two ways to get bytes into it.
package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/softwareupdates"
)

func updateChannelErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, softwareupdates.ErrValidation):
		return http.StatusBadRequest, "validation_error"
	case errors.Is(err, softwareupdates.ErrNotFound):
		return http.StatusNotFound, "not_found"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func (s *Server) handleGetUpdateChannel(w http.ResponseWriter, r *http.Request) {
	if s.SoftwareUpdates == nil {
		WriteJSON(w, http.StatusOK, map[string]any{"configured": false})
		return
	}
	cs, err := s.SoftwareUpdates.Get(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load update channel settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, cs)
}

type updateChannelRequest struct {
	RepoOwner  string `json:"repo_owner"`
	RepoName   string `json:"repo_name"`
	Token      string `json:"token"`
	ClearToken bool   `json:"clear_token"`
}

func (s *Server) handleSetUpdateChannel(w http.ResponseWriter, r *http.Request) {
	if s.SoftwareUpdates == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "software update channel is not configured on this deployment").WriteJSON(w)
		return
	}
	var req updateChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.SoftwareUpdates.SetChannel(r.Context(), req.RepoOwner, req.RepoName, req.Token, req.ClearToken); err != nil {
		status, code := updateChannelErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

// handleCheckForUpdate hits the real configured GitHub Releases channel
// -- see softwareupdates.Service.CheckNow's own doc comment. A real
// upstream/network error is stored (last_check_status="error") and
// returned as a normal 200 with the error visible in the response body
// (not a 5xx) -- "GitHub was unreachable just now" is an expected,
// recoverable condition for a page an owner might load at any time, not
// a server fault.
func (s *Server) handleCheckForUpdate(w http.ResponseWriter, r *http.Request) {
	if s.SoftwareUpdates == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "software update channel is not configured on this deployment").WriteJSON(w)
		return
	}
	cs, err := s.SoftwareUpdates.CheckNow(r.Context())
	if err != nil {
		WriteJSON(w, http.StatusOK, map[string]any{"status": "checked", "channel": cs, "error": err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "checked", "channel": cs})
}

// handleUpdateDownloadAndStage downloads the latest known release
// (from the most recent CheckNow), verifies it against the published
// SHA256SUMS, then stages it via the exact same OpUpdateStage the
// manual-upload flow uses (that op does its OWN independent checksum +
// self-reported-version verification too -- two independent checks,
// not one trusted twice).
func (s *Server) handleUpdateDownloadAndStage(w http.ResponseWriter, r *http.Request) {
	if s.SoftwareUpdates == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "software update channel is not configured on this deployment").WriteJSON(w)
		return
	}
	data, version, sha256Hex, err := s.SoftwareUpdates.FetchLatestDeb(r.Context())
	if err != nil {
		status, code := updateChannelErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	params := map[string]any{
		"claimed_version": version,
		"sha256":          sha256Hex,
		"data_base64":     base64.StdEncoding.EncodeToString(data),
	}
	result, ok := callAgent[json.RawMessage](s, w, r, hostagent.OpUpdateStage, params)
	if !ok {
		return
	}
	WriteJSON(w, http.StatusOK, result)
}
