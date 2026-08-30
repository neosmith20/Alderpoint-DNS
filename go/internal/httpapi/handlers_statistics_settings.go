package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"alderpointdns/go-controlplane/internal/dnsanalytics"
)

// Statistics settings: the singleton analytics_settings row, matching
// V1.1.1's real statistics_settings.html/webapp.py statistics_settings()
// field-for-field where this architecture has an equivalent -- see
// dnsanalytics.Settings's own doc comment for the two real V1 fields
// (aggregate_retention_days, collection_interval) deliberately NOT
// modeled here, and why.
// LoadAnalyticsSettingsForBoot is loadAnalyticsSettings, exported for
// cmd/alderpointdns-go's own startup wiring (it needs the persisted
// settings before the Writer/Server even exist, to hand the Writer a
// pre-populated SettingsHolder rather than one that starts on
// DefaultSettings until the first save).
func LoadAnalyticsSettingsForBoot(ctx context.Context, db *sql.DB) (dnsanalytics.Settings, error) {
	return loadAnalyticsSettings(ctx, db)
}

func loadAnalyticsSettings(ctx context.Context, db *sql.DB) (dnsanalytics.Settings, error) {
	var s dnsanalytics.Settings
	var analyticsEnabled, detailedEnabled int
	err := db.QueryRowContext(ctx, `
		SELECT analytics_enabled, detailed_query_logging_enabled, privacy_mode, client_anonymization,
		       detailed_retention_days, db_size_limit_bytes, recent_query_limit
		FROM analytics_settings WHERE id=1`,
	).Scan(&analyticsEnabled, &detailedEnabled, &s.PrivacyMode, &s.ClientAnonymization,
		&s.DetailedRetentionDays, &s.DBSizeLimitBytes, &s.RecentQueryLimit)
	if err != nil {
		return dnsanalytics.Settings{}, err
	}
	s.AnalyticsEnabled = analyticsEnabled != 0
	s.DetailedQueryLoggingEnabled = detailedEnabled != 0
	return s, nil
}

var validPrivacyModes = map[string]bool{"full": true, "anonymized_clients": true, "aggregate_only": true}
var validClientAnonymization = map[string]bool{"truncate": true, "hash": true}

func validateAnalyticsSettings(s dnsanalytics.Settings) *APIError {
	if !validPrivacyModes[s.PrivacyMode] {
		return ErrField(http.StatusBadRequest, "validation_error", "privacy_mode must be one of: full, anonymized_clients, aggregate_only", "privacy_mode")
	}
	if !validClientAnonymization[s.ClientAnonymization] {
		return ErrField(http.StatusBadRequest, "validation_error", "client_anonymization must be one of: truncate, hash", "client_anonymization")
	}
	if s.DetailedRetentionDays < 0 {
		return ErrField(http.StatusBadRequest, "validation_error", "detailed_retention_days must be >= 0", "detailed_retention_days")
	}
	if s.DBSizeLimitBytes < 1048576 {
		return ErrField(http.StatusBadRequest, "validation_error", "db_size_limit_bytes must be >= 1048576 (1 MiB)", "db_size_limit_bytes")
	}
	if s.RecentQueryLimit < 10 {
		return ErrField(http.StatusBadRequest, "validation_error", "recent_query_limit must be >= 10", "recent_query_limit")
	}
	return nil
}

func (s *Server) handleGetAnalyticsSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := loadAnalyticsSettings(r.Context(), s.DB)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to load statistics settings").WriteJSON(w)
		return
	}
	WriteJSON(w, http.StatusOK, settings)
}

func (s *Server) handleUpdateAnalyticsSettings(w http.ResponseWriter, r *http.Request) {
	var body dnsanalytics.Settings
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		Err(http.StatusBadRequest, "validation_error", "invalid request body").WriteJSON(w)
		return
	}
	if apiErr := validateAnalyticsSettings(body); apiErr != nil {
		apiErr.WriteJSON(w)
		return
	}
	_, err := s.DB.ExecContext(r.Context(), `
		UPDATE analytics_settings SET
			analytics_enabled=?, detailed_query_logging_enabled=?, privacy_mode=?, client_anonymization=?,
			detailed_retention_days=?, db_size_limit_bytes=?, recent_query_limit=?
		WHERE id=1`,
		boolToInt(body.AnalyticsEnabled), boolToInt(body.DetailedQueryLoggingEnabled), body.PrivacyMode, body.ClientAnonymization,
		body.DetailedRetentionDays, body.DBSizeLimitBytes, body.RecentQueryLimit)
	if err != nil {
		Err(http.StatusInternalServerError, "internal_error", "failed to save statistics settings").WriteJSON(w)
		return
	}
	// Takes effect immediately, no restart: the live analytics Writer
	// reads this same *SettingsHolder on its own hot path (see
	// dnsanalytics.Writer.applySettings).
	if s.AnalyticsSettings != nil {
		s.AnalyticsSettings.Store(body)
	}
	WriteJSON(w, http.StatusOK, body)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
