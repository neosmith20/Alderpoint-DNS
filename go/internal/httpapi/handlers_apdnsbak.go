// Real V2 Python .apdnsbak import -- see internal/apdnsbak's own doc
// comment for the exact format and what's deliberately not imported
// (secrets.json, certs/*). Mirrors handleImportLegacyAppliance's own
// conventions (raw body, ?filename=/?dry_run= query params, a
// dedicated passphrase header so it never lands in a URL/access log).
package httpapi

import (
	"io"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/apdnsbak"
	"alderpointdns/go-controlplane/internal/pymigrate"
)

const maxApdnsbakUploadBytes = 1_000_000_000

func (s *Server) handleImportApdnsbak(w http.ResponseWriter, r *http.Request) {
	if s.LocalDNS == nil || s.Upstreams == nil || s.DNSTransports == nil || s.Policy == nil || s.Blocklists == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "appliance backup import is not configured for this deployment").WriteJSON(w)
		return
	}
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		Err(http.StatusBadRequest, "validation_error", "?filename= query parameter required").WriteJSON(w)
		return
	}
	if !apdnsbak.IsApdnsbakName(filename) {
		Err(http.StatusBadRequest, "validation_error", "not a recognized .apdnsbak filename").WriteJSON(w)
		return
	}
	dryRun := true
	if v := r.URL.Query().Get("dry_run"); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			Err(http.StatusBadRequest, "validation_error", "dry_run must be true or false").WriteJSON(w)
			return
		}
		dryRun = parsed
	}
	passphrase := r.Header.Get("X-Apdnsbak-Passphrase")

	data, err := io.ReadAll(io.LimitReader(r.Body, maxApdnsbakUploadBytes+1))
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "failed to read request body").WriteJSON(w)
		return
	}
	if len(data) > maxApdnsbakUploadBytes {
		Err(http.StatusBadRequest, "archive_too_large", "upload exceeds the size limit").WriteJSON(w)
		return
	}

	dbPath, manifest, cleanup, err := apdnsbak.Extract(data, passphrase)
	defer cleanup()
	if err != nil {
		status := http.StatusBadRequest
		code := "invalid_archive"
		switch err {
		case apdnsbak.ErrPassphraseRequired:
			code = "passphrase_required"
		case apdnsbak.ErrWrongPassphrase:
			code = "wrong_passphrase"
		case apdnsbak.ErrNotPortable:
			code = "not_portable"
		case apdnsbak.ErrWrongProduct, apdnsbak.ErrNoDatabase:
			code = "invalid_archive"
		default:
			status = http.StatusInternalServerError
			code = "internal_error"
		}
		Err(status, code, err.Error()).WriteJSON(w)
		return
	}

	im := &pymigrate.Importer{
		PythonControlDBPath: dbPath,
		LocalDNS:            s.LocalDNS,
		Upstreams:           s.Upstreams,
		DNSTransports:       s.DNSTransports,
		Policy:              s.Policy,
		Blocklists:          s.Blocklists,
		Backup:              s.Backup,
	}
	report, err := im.Run(r.Context(), dryRun)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", err.Error()).WriteJSON(w)
		return
	}
	pymigrate.SortResultsForDisplay(report.Results)
	WriteJSON(w, http.StatusOK, map[string]any{
		"report": report,
		"manifest": map[string]any{
			"source_version":            manifest.SourceVersion,
			"control_db_schema_version": manifest.ControlDBSchemaVersion,
			"created_at":                manifest.CreatedAt,
			"source_node_id":            manifest.SourceNodeID,
			"contents":                  manifest.Contents,
		},
	})
}
