// Real V1.1.1 legacy-backup import -- the "V1.1.1 .tar.gz compatibility"
// gap disclosed on the Backup & Restore page. Reuses two pieces already
// built and independently tested for a different purpose: this session's
// own internal/legacyimport (validates/decrypts/extracts a real V1.1.1
// archive down to its embedded live SQLite database) and the existing
// internal/pymigrate.Importer (the exact same audited, bounded table set
// already used for the one-time cutover import from a live Python
// install -- unmodified here, just pointed at an extracted file instead
// of a live path).
package httpapi

import (
	"io"
	"net/http"
	"strconv"

	"alderpointdns/go-controlplane/internal/legacyimport"
	"alderpointdns/go-controlplane/internal/pymigrate"
)

const maxLegacyArchiveUploadBytes = 500_000_000

// handleImportLegacyAppliance accepts a raw V1.1.1 backup archive body
// (the same "own native format, no multipart" convention as
// handleUploadBackup -- exactly one file per request). Query params:
// ?filename= (required, used only to tell encrypted from unencrypted --
// a name ending .enc is decrypted, matching V1.1.1's own convention) and
// ?dry_run=true|false (default true -- never writes without an explicit
// dry_run=false, matching pymigrate's own CLI default posture). The
// archive's password, when needed, travels in a header
// (X-Legacy-Backup-Password), never in the URL/query string, so it
// never lands in an access log.
func (s *Server) handleImportLegacyAppliance(w http.ResponseWriter, r *http.Request) {
	if s.LocalDNS == nil || s.Upstreams == nil || s.DNSTransports == nil || s.Policy == nil || s.Blocklists == nil {
		Err(http.StatusServiceUnavailable, "unavailable", "legacy appliance backup import is not configured for this deployment").WriteJSON(w)
		return
	}
	filename := r.URL.Query().Get("filename")
	if filename == "" {
		Err(http.StatusBadRequest, "validation_error", "?filename= query parameter required").WriteJSON(w)
		return
	}
	if !legacyimport.IsLegacyArchiveName(filename) {
		Err(http.StatusBadRequest, "validation_error", "not a recognized V1.1.1 backup filename (expected alderpointdns-backup-*.tar.gz or .tar.gz.enc)").WriteJSON(w)
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
	password := r.Header.Get("X-Legacy-Backup-Password")

	data, err := io.ReadAll(io.LimitReader(r.Body, maxLegacyArchiveUploadBytes+1))
	if err != nil {
		Err(http.StatusBadRequest, "validation_error", "failed to read request body").WriteJSON(w)
		return
	}
	if len(data) > maxLegacyArchiveUploadBytes {
		Err(http.StatusBadRequest, "archive_too_large", "upload exceeds the size limit").WriteJSON(w)
		return
	}

	dbPath, manifest, cleanup, err := legacyimport.Extract(data, len(filename) > 4 && filename[len(filename)-4:] == ".enc", password)
	defer cleanup()
	if err != nil {
		status := http.StatusBadRequest
		code := "invalid_archive"
		switch err {
		case legacyimport.ErrPasswordRequired:
			code = "password_required"
		case legacyimport.ErrWrongPassword:
			code = "wrong_password"
		case legacyimport.ErrChecksumMismatch, legacyimport.ErrNoDatabase, legacyimport.ErrUnsupportedVersion:
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
			"alderpointdns_app_version": manifest.AlderpointdnsAppVersion,
			"database_schema_version":   manifest.DatabaseSchemaVersion,
			"created_at":                manifest.CreatedAt,
			"source_node_id":            manifest.SourceNodeID,
			"included_components":       manifest.IncludedComponents,
		},
	})
}
