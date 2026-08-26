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
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "description": c.Description, "enabled": c.Enabled,
			"identifiers": c.Identifiers, "groups": c.Groups, "policy": layer,
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
