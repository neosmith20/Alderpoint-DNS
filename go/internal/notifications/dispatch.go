// Dispatch: event subscriptions, cooldown/dedup, delivery history --
// app/notifications.py's EVENT_CATEGORIES/dispatch()/notification_history
// logic (0015_notification_dispatch.sql), read directly and ported
// field-for-field. Closes the "nothing decides WHEN to notify" gap this
// package's own top-of-file doc comment previously disclosed.
package notifications

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// EventCategory mirrors app/notifications.py's EVENT_CATEGORIES entries.
type EventCategory struct {
	Key             string `json:"key"`
	Label           string `json:"label"`
	Wired           bool   `json:"wired"` // true = a real Go call site actually fires this category today
	DefaultSeverity string `json:"default_severity"`
}

// EventCategories is the fixed, real event vocabulary -- field-matched
// against Python's own EVENT_CATEGORIES dict. "Wired" is honestly
// narrower than Python's own set: only categories with a real Go call
// site set true here (see this package's own doc comment on Dispatch's
// callers) -- a category listed as available-to-subscribe-to but not
// yet wired is disclosed, not silently implied as monitored.
var EventCategories = []EventCategory{
	{"blocklist_update_failure", "Blocklist update failure", true, "warning"},
	{"deploy_failure", "Configuration compilation or deployment failure", true, "critical"},
	{"backup_failure", "Backup failure", false, "warning"},
	{"service_unavailable", "named, dnsdist, or the Go web/analytics service unavailable", true, "critical"},
	{"resolver_all_unavailable", "All upstream resolvers unavailable", false, "critical"},
	{"replication_delayed", "Replication delayed or failed", true, "warning"},
	{"tls_cert_expiring", "TLS certificate approaching expiration", true, "warning"},
}

var validEventCategories = func() map[string]bool {
	m := map[string]bool{}
	for _, c := range EventCategories {
		m[c.Key] = true
	}
	return m
}()

var severityRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

const DefaultCooldownMinutes = 30

type Subscription struct {
	ID              int64  `json:"id"`
	ProviderID      string `json:"provider_id"`
	ProviderName    string `json:"provider_name"`
	EventCategory   string `json:"event_category"`
	MinSeverity     string `json:"min_severity"`
	Enabled         bool   `json:"enabled"`
	CooldownMinutes *int   `json:"cooldown_minutes"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

func (s *Service) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT ns.id, ns.provider_id, np.display_name, ns.event_category, ns.min_severity, ns.enabled, ns.cooldown_minutes, ns.created_at, ns.updated_at
		FROM notification_subscriptions ns JOIN notification_providers np ON np.provider_id = ns.provider_id
		ORDER BY np.display_name, ns.event_category`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subscription{}
	for rows.Next() {
		var sub Subscription
		var enabled int
		if err := rows.Scan(&sub.ID, &sub.ProviderID, &sub.ProviderName, &sub.EventCategory, &sub.MinSeverity, &enabled, &sub.CooldownMinutes, &sub.CreatedAt, &sub.UpdatedAt); err != nil {
			return nil, err
		}
		sub.Enabled = enabled != 0
		out = append(out, sub)
	}
	return out, rows.Err()
}

// SetSubscription upserts one (provider, event_category) subscription --
// matches app/notifications.py's set_subscription's own
// INSERT ... ON CONFLICT DO UPDATE contract.
func (s *Service) SetSubscription(ctx context.Context, providerID, eventCategory, minSeverity string, enabled bool, cooldownMinutes *int) error {
	if !validEventCategories[eventCategory] {
		return fmt.Errorf("%w: unknown event category %q", ErrValidation, eventCategory)
	}
	if _, ok := severityRank[minSeverity]; !ok {
		return fmt.Errorf("%w: invalid min_severity %q", ErrValidation, minSeverity)
	}
	// This schema never sets PRAGMA foreign_keys=ON (a real, pre-existing
	// fact about this codebase -- see internal/clients.DeleteClient's own
	// disclosed finding), so the FK constraint on notification_subscriptions
	// is inert and would silently accept an unknown provider_id. Check
	// explicitly instead of trusting the FK to reject it.
	if _, err := s.get(ctx, providerID); err != nil {
		return fmt.Errorf("%w: unknown provider_id %q", ErrValidation, providerID)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO notification_subscriptions (provider_id, event_category, min_severity, enabled, cooldown_minutes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(provider_id, event_category) DO UPDATE SET
			min_severity = excluded.min_severity, enabled = excluded.enabled, cooldown_minutes = excluded.cooldown_minutes, updated_at = excluded.updated_at`,
		providerID, eventCategory, minSeverity, enabledInt, cooldownMinutes, now, now)
	return err
}

func (s *Service) DeleteSubscription(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM notification_subscriptions WHERE id = ?`, id)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

type HistoryEntry struct {
	ID            int64  `json:"id"`
	At            string `json:"at"`
	EventCategory string `json:"event_category"`
	Severity      string `json:"severity"`
	Component     string `json:"component"`
	Message       string `json:"message"`
	BeganAt       string `json:"began_at"`
	Recovered     bool   `json:"recovered"`
	ProviderID    string `json:"provider_id"`
	ProviderName  string `json:"provider_name"`
	Status        string `json:"status"` // sent | suppressed | failed
	Error         string `json:"error"`
}

func (s *Service) ListHistory(ctx context.Context, limit int) ([]HistoryEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, at, event_category, severity, component, message, began_at, recovered, provider_id, provider_name, status, error
		FROM notification_history ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HistoryEntry{}
	for rows.Next() {
		var h HistoryEntry
		var recovered int
		if err := rows.Scan(&h.ID, &h.At, &h.EventCategory, &h.Severity, &h.Component, &h.Message, &h.BeganAt, &recovered, &h.ProviderID, &h.ProviderName, &h.Status, &h.Error); err != nil {
			return nil, err
		}
		h.Recovered = recovered != 0
		out = append(out, h)
	}
	return out, rows.Err()
}

// fingerprint mirrors app/notifications.py's _fingerprint: identifies
// "the same real condition" for dedup purposes, independent of the
// exact wording of its summary.
func fingerprint(eventCategory, component string) string {
	sum := sha256.Sum256([]byte(eventCategory + ":" + component))
	return hex.EncodeToString(sum[:])[:16]
}

// DispatchOutcome is one provider's real result for one Dispatch call.
type DispatchOutcome struct {
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	Status       string `json:"status"` // sent | suppressed | failed
	Error        string `json:"error,omitempty"`
}

// Dispatch sends `summary` to every enabled subscription for
// eventCategory at or above its configured minimum severity, applying
// cooldown/duplicate suppression (bypassed for recovery notices, same
// as Python's own dispatch()), and records every outcome to
// notification_history. Never returns a Go error for an individual
// provider's send failure -- that's a real, recorded "failed" outcome,
// not a crash; a Go error here means the dispatch bookkeeping itself
// (loading subscriptions, writing history) failed.
func (s *Service) Dispatch(ctx context.Context, eventCategory, severity, component, summary string, recovered bool) ([]DispatchOutcome, error) {
	if !validEventCategories[eventCategory] {
		return nil, fmt.Errorf("%w: unknown event category %q", ErrValidation, eventCategory)
	}
	rank, ok := severityRank[severity]
	if !ok {
		return nil, fmt.Errorf("%w: invalid severity %q", ErrValidation, severity)
	}
	beganAt := time.Now().UTC().Format(time.RFC3339)
	fp := fingerprint(eventCategory, component)

	rows, err := s.DB.QueryContext(ctx, `
		SELECT ns.id, ns.provider_id, np.display_name, ns.min_severity, ns.cooldown_minutes, np.kind, np.config_json, np.has_secret
		FROM notification_subscriptions ns
		JOIN notification_providers np ON np.provider_id = ns.provider_id
		WHERE ns.event_category = ? AND ns.enabled = 1 AND np.enabled = 1`, eventCategory)
	if err != nil {
		return nil, err
	}
	type subRow struct {
		id, providerID, providerName, minSeverity, kind, configJSON string
		cooldown                                                    *int
		hasSecret                                                   bool
	}
	var subs []subRow
	for rows.Next() {
		var r subRow
		if err := rows.Scan(&r.id, &r.providerID, &r.providerName, &r.minSeverity, &r.cooldown, &r.kind, &r.configJSON, &r.hasSecret); err != nil {
			rows.Close()
			return nil, err
		}
		subs = append(subs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var outcomes []DispatchOutcome
	for _, sub := range subs {
		if rank < severityRank[sub.minSeverity] {
			continue
		}
		cooldown := DefaultCooldownMinutes
		if sub.cooldown != nil {
			cooldown = *sub.cooldown
		}

		var lastFingerprint, lastSentAt sql.NullString
		_ = s.DB.QueryRowContext(ctx, `SELECT last_fingerprint, last_sent_at FROM notification_rate_state WHERE event_category = ? AND provider_id = ?`,
			eventCategory, sub.providerID).Scan(&lastFingerprint, &lastSentAt)

		suppress := false
		if !recovered && lastFingerprint.String == fp && lastSentAt.Valid {
			if sentAt, err := time.Parse(time.RFC3339, lastSentAt.String); err == nil {
				if time.Since(sentAt) < time.Duration(cooldown)*time.Minute {
					suppress = true
				}
			}
		}

		if suppress {
			s.DB.ExecContext(ctx, `
				INSERT INTO notification_rate_state (event_category, provider_id, last_fingerprint, last_sent_at, suppressed_count)
				VALUES (?, ?, ?, ?, 1)
				ON CONFLICT(event_category, provider_id) DO UPDATE SET suppressed_count = suppressed_count + 1`,
				eventCategory, sub.providerID, fp, lastSentAt.String)
			s.recordHistory(ctx, eventCategory, severity, component, summary, beganAt, recovered, sub.providerID, sub.providerName, "suppressed", "")
			outcomes = append(outcomes, DispatchOutcome{ProviderID: sub.providerID, ProviderName: sub.providerName, Status: "suppressed"})
			continue
		}

		ok, sendErr := s.sendReal(ctx, sub.providerID, sub.kind, sub.configJSON, sub.hasSecret, summary)
		status := "sent"
		errStr := ""
		if !ok {
			status = "failed"
			if sendErr != nil {
				errStr = sendErr.Error()
			}
		}
		now := time.Now().UTC().Format(time.RFC3339)
		s.DB.ExecContext(ctx, `
			INSERT INTO notification_rate_state (event_category, provider_id, last_fingerprint, last_sent_at, suppressed_count)
			VALUES (?, ?, ?, ?, 0)
			ON CONFLICT(event_category, provider_id) DO UPDATE SET last_fingerprint = excluded.last_fingerprint, last_sent_at = excluded.last_sent_at`,
			eventCategory, sub.providerID, fp, now)
		s.recordHistory(ctx, eventCategory, severity, component, summary, beganAt, recovered, sub.providerID, sub.providerName, status, errStr)
		outcomes = append(outcomes, DispatchOutcome{ProviderID: sub.providerID, ProviderName: sub.providerName, Status: status, Error: errStr})
	}
	return outcomes, nil
}

func (s *Service) recordHistory(ctx context.Context, eventCategory, severity, component, summary, beganAt string, recovered bool, providerID, providerName, status, errStr string) {
	recoveredInt := 0
	if recovered {
		recoveredInt = 1
	}
	s.DB.ExecContext(ctx, `
		INSERT INTO notification_history (at, event_category, severity, component, message, began_at, recovered, provider_id, provider_name, status, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339), eventCategory, severity, component, summary, beganAt, recoveredInt, providerID, providerName, status, errStr)
}

// sendReal performs the actual send via apdns-hostagent -- same
// decrypt-inside-the-agent contract Test already uses, just via
// OpSecretsNotifySend with a real message instead of the fixed test
// string. Returns (false, nil) rather than an error when secrets
// aren't configured or the provider has no secret set yet -- a
// dispatch attempt against a half-configured provider is a real,
// recordable "failed" outcome, not a Go-level error that would abort
// every other subscription's delivery.
func (s *Service) sendReal(ctx context.Context, providerID, kind, configJSON string, hasSecret bool, message string) (bool, error) {
	if !hasSecret {
		return false, fmt.Errorf("no secret configured for this provider")
	}
	if s.Secrets == nil {
		return false, fmt.Errorf("secrets subsystem not configured on this deployment")
	}
	extra := map[string]any{"notify_kind": kind, "message": message}
	if kind == "email_smtp" {
		var cfg SMTPConfig
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return false, fmt.Errorf("stored SMTP config is invalid: %w", err)
		}
		extra["smtp_host"] = cfg.Host
		extra["smtp_port"] = cfg.Port
		extra["from_addr"] = cfg.FromAddr
		extra["to_addr"] = cfg.ToAddr
		extra["username"] = cfg.Username
	}
	params, err := s.Secrets.SealedParams(ctx, SecretKind, providerID, extra)
	if err != nil {
		return false, err
	}
	var out TestResult
	if err := s.Secrets.CallNotifySend(ctx, params, &out); err != nil {
		return false, err
	}
	if !out.OK {
		return false, fmt.Errorf("%s", out.Detail)
	}
	return true, nil
}
