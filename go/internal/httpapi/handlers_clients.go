package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/clients"
)

func clientErrorStatus(err error) (int, string) {
	switch {
	case errors.Is(err, clients.ErrNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, clients.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, clients.ErrValidation):
		return http.StatusBadRequest, "validation_error"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.Clients.ListGroups(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load groups").WriteJSON(w)
		return
	}
	// Matches Python's GET /api/groups, which embeds each group's policy
	// layer directly rather than requiring a second round trip.
	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		layer, err := s.Policy.Load(r.Context(), "group", g.GroupID)
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", "failed to load group policy").WriteJSON(w)
			return
		}
		out = append(out, map[string]any{"group_id": g.GroupID, "name": g.Name, "priority": g.Priority, "members": g.Members, "policy": layer})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"groups": out})
}

type createGroupRequest struct {
	GroupID  string `json:"group_id"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}

func groupIDFromName(name string) string {
	slug := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, strings.ToLower(name))
	sum := sha256.Sum256([]byte(name + strconv.FormatInt(time.Now().UnixNano(), 10)))
	return slug + "-" + hex.EncodeToString(sum[:4])
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	id := strings.TrimSpace(req.GroupID)
	if id == "" {
		id = groupIDFromName(req.Name)
	}
	if err := s.Clients.CreateGroup(r.Context(), id, req.Name, req.Priority); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "group_id": id})
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	list, err := s.Clients.ListClients(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load clients").WriteJSON(w)
		return
	}
	// Matches Python's GET /api/clients, which embeds each client's
	// policy layer directly rather than requiring a second round trip.
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		layer, err := s.Policy.Load(r.Context(), "client", strconv.FormatInt(c.ID, 10))
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", "failed to load client policy").WriteJSON(w)
			return
		}
		overrides, err := s.Clients.DomainOverridesForClient(r.Context(), c.ID)
		if err != nil {
			Err(http.StatusInternalServerError, "internal_error", "failed to load domain overrides").WriteJSON(w)
			return
		}
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "description": c.Description, "enabled": c.Enabled,
			"identifiers": c.Identifiers, "groups": c.Groups, "policy": layer,
			"domain_overrides": overrides,
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"clients": out})
}

type createClientRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	id, err := s.Clients.CreateClient(r.Context(), req.Name, req.Description)
	if err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "client_id": id})
}

type addIdentifierRequest struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func (s *Server) handleAddClientIdentifier(w http.ResponseWriter, r *http.Request) {
	clientID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid client id").WriteJSON(w)
		return
	}
	var req addIdentifierRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.Clients.AddIdentifier(r.Context(), clientID, req.Kind, req.Value); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created"})
}

type generateClientIDRequest struct {
	Bits  int    `json:"bits"`
	Label string `json:"label"`
}

// handleGenerateClientID is the secure generation endpoint: the actual
// hex value is always produced server-side by internal/clientid's
// OS-backed CSPRNG, never accepted from the request body -- a caller
// can only choose the bit strength (192/256) and an operator-facing
// label.
func (s *Server) handleGenerateClientID(w http.ResponseWriter, r *http.Request) {
	clientID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid client id").WriteJSON(w)
		return
	}
	var req generateClientIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	bits := req.Bits
	if bits == 0 {
		bits = 256
	}
	if bits != 192 && bits != 256 {
		Err(http.StatusBadRequest, "validation_error", "bits must be 192 or 256").WriteJSON(w)
		return
	}
	ident, err := s.Clients.GenerateClientID(r.Context(), clientID, bits, req.Label)
	if err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "identifier": ident, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleRevokeClientIdentifier(w http.ResponseWriter, r *http.Request) {
	identifierID, err := strconv.ParseInt(r.PathValue("identifierId"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid identifier id").WriteJSON(w)
		return
	}
	if err := s.Clients.RevokeIdentifier(r.Context(), identifierID); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "revoked", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

// handleRegenerateClientIdentifier is the compromise-response action:
// revoke the old identity and mint a fresh one, atomically
// (internal/clients.RegenerateIdentifier), then reach the live runtime
// through the same auto-apply path as every other mutation here --
// this is exactly the "changing a DoH ClientID path requires listener/
// runtime restart" case, handled by the existing generic stage->
// validate->promote->reload->health-check->rollback pipeline (see
// internal/hostagentd/ops_dnsruntime.go), not a new mechanism.
func (s *Server) handleRegenerateClientIdentifier(w http.ResponseWriter, r *http.Request) {
	identifierID, err := strconv.ParseInt(r.PathValue("identifierId"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid identifier id").WriteJSON(w)
		return
	}
	ident, err := s.Clients.RegenerateIdentifier(r.Context(), identifierID)
	if err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "regenerated", "identifier": ident, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteClientIdentifier(w http.ResponseWriter, r *http.Request) {
	identifierID, err := strconv.ParseInt(r.PathValue("identifierId"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid identifier id").WriteJSON(w)
		return
	}
	if err := s.Clients.DeleteIdentifier(r.Context(), identifierID); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

type addDomainOverrideRequest struct {
	OverrideType string `json:"override_type"`
	Pattern      string `json:"pattern"`
}

func (s *Server) handleAddDomainOverride(w http.ResponseWriter, r *http.Request) {
	clientID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid client id").WriteJSON(w)
		return
	}
	var req addDomainOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	override, err := s.Clients.AddDomainOverride(r.Context(), clientID, req.OverrideType, req.Pattern)
	if err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "override": override, "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

func (s *Server) handleDeleteDomainOverride(w http.ResponseWriter, r *http.Request) {
	overrideID, err := strconv.ParseInt(r.PathValue("overrideId"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid override id").WriteJSON(w)
		return
	}
	if err := s.Clients.DeleteDomainOverride(r.Context(), overrideID); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

type addClientGroupRequest struct {
	GroupID string `json:"group_id"`
}

func (s *Server) handleAddClientGroup(w http.ResponseWriter, r *http.Request) {
	clientID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid client id").WriteJSON(w)
		return
	}
	var req addClientGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.Clients.AddToGroup(r.Context(), clientID, req.GroupID); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created"})
}

func (s *Server) handleRemoveClientGroup(w http.ResponseWriter, r *http.Request) {
	clientID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid client id").WriteJSON(w)
		return
	}
	if err := s.Clients.RemoveFromGroup(r.Context(), clientID, r.PathValue("groupId")); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "removed"})
}

type updateClientRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// handleUpdateClient mirrors V1's real update_client (app/clients.py) --
// name/description edit only; identifiers, groups and policy each have
// their own dedicated endpoints already.
func (s *Server) handleUpdateClient(w http.ResponseWriter, r *http.Request) {
	clientID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid client id").WriteJSON(w)
		return
	}
	var req updateClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.Clients.UpdateClient(r.Context(), clientID, req.Name, req.Description); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

type setClientEnabledRequest struct {
	Enabled bool `json:"enabled"`
}

// handleSetClientEnabled mirrors V1's set_client_enabled. A disabled
// client's Strong ClientID / IP identifiers stay stored, but
// AllActiveClientIdentities (internal/dnsruntime's compile input) must
// stop counting them as active -- see the corresponding change in
// internal/clients.AllActiveClientIdentities.
func (s *Server) handleSetClientEnabled(w http.ResponseWriter, r *http.Request) {
	clientID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid client id").WriteJSON(w)
		return
	}
	var req setClientEnabledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.Clients.SetClientEnabled(r.Context(), clientID, req.Enabled); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}

// handleDeleteClient mirrors V1's delete_client -- removes the client
// and everything scoped to it (identifiers, group memberships, domain
// overrides; see internal/clients.DeleteClient's doc comment for why
// this is done explicitly rather than relying on the schema's inert
// ON DELETE CASCADE annotations).
func (s *Server) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid client id").WriteJSON(w)
		return
	}
	if err := s.Clients.DeleteClient(r.Context(), clientID); err != nil {
		status, code := clientErrorStatus(err)
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted", "dns_runtime": s.applyDNSRuntimeBestEffort(r)})
}
