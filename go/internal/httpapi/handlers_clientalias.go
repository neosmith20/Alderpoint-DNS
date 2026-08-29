package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/clientalias"
)

// clientAliasUnavailable mirrors every other optional-service "nil
// means unwired, never a programming error" contract in this package.
const clientAliasUnavailable = "client aliases not configured"

func (s *Server) handleListClientAliases(w http.ResponseWriter, r *http.Request) {
	if s.ClientAliases == nil {
		Err(http.StatusServiceUnavailable, "unavailable", clientAliasUnavailable).WriteJSON(w)
		return
	}
	list, err := s.ClientAliases.List(r.Context())
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "list failed").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"aliases": list})
}

type clientAliasRequest struct {
	CIDR        string `json:"cidr"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

func (s *Server) handleCreateClientAlias(w http.ResponseWriter, r *http.Request) {
	if s.ClientAliases == nil {
		Err(http.StatusServiceUnavailable, "unavailable", clientAliasUnavailable).WriteJSON(w)
		return
	}
	var req clientAliasRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	alias, err := s.ClientAliases.Create(r.Context(), req.CIDR, req.DisplayName, req.Description)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"status": "created", "alias": alias})
}

func (s *Server) handleUpdateClientAlias(w http.ResponseWriter, r *http.Request) {
	if s.ClientAliases == nil {
		Err(http.StatusServiceUnavailable, "unavailable", clientAliasUnavailable).WriteJSON(w)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid id").WriteJSON(w)
		return
	}
	var req clientAliasRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if err := s.ClientAliases.Update(r.Context(), id, req.DisplayName, req.Description); err != nil {
		if err == clientalias.ErrNotFound {
			Err(http.StatusNotFound, "not_found", "client alias not found").WriteJSON(w)
			return
		}
		Err(http.StatusBadRequest, "validation_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "updated"})
}

func (s *Server) handleDeleteClientAlias(w http.ResponseWriter, r *http.Request) {
	if s.ClientAliases == nil {
		Err(http.StatusServiceUnavailable, "unavailable", clientAliasUnavailable).WriteJSON(w)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid id").WriteJSON(w)
		return
	}
	if err := s.ClientAliases.Delete(r.Context(), id); err != nil {
		if err == clientalias.ErrNotFound {
			Err(http.StatusNotFound, "not_found", "client alias not found").WriteJSON(w)
			return
		}
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}
