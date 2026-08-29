// Package notifications is a native Go implementation of Notification
// Providers, matching app/notifications.py's real security model (read
// directly, not guessed): a provider's actual credential -- a webhook/
// Slack URL (itself a bearer token for most of these services), a
// Pushover "user_key:app_token" pair, or an SMTP password -- is the
// sensitive half and is NEVER stored in this table in plaintext.
// Non-secret shape (kind, display name, and for email_smtp: host/port/
// from/to/username) lives here in `config_json`; the credential itself
// is sealed via internal/secretstore (schema migration 0012/0013) and
// never read back once set -- `has_secret` is the only thing this
// table (or any API response) ever says about it.
//
// "Test" sends a real message using the stored credential, entirely
// inside apdns-hostagent (internal/hostagentd/ops_secrets.go's
// OpSecretsNotifyTest) -- this process never sees the decrypted value.
//
// Deliberately NOT built in this pass, disclosed rather than hidden:
// the event-driven dispatch engine (app/notifications.py's
// EVENT_CATEGORIES/subscriptions/dispatch/history/cooldown logic) and
// app/notify_check.py's real health-condition checkers. This package
// gives an owner real, working provider CRUD + secret storage + a real
// test-send -- a provider configured here can genuinely receive a
// message today -- but nothing in this Go control plane yet decides
// WHEN to automatically notify one. That is a separate, larger
// workflow, not a quick addition to this one.
package notifications

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"alderpointdns/go-controlplane/internal/secretstore"
)

var (
	ErrNotFound   = errors.New("unknown provider_id")
	ErrValidation = errors.New("notification provider validation failed")
)

var validKinds = map[string]bool{"webhook": true, "email_smtp": true, "pushover": true, "slack": true}

// SecretKind is this package's own namespace within the shared
// `secrets` table -- see internal/secretstore's doc comment for why
// kind+owner_ref (here, a provider_id) is what binds a stored
// ciphertext to exactly one record.
const SecretKind = "notification_secret"

// SMTPConfig is the non-secret shape for kind=email_smtp, stored in
// config_json. The password itself is never part of this struct --
// it's the secret, set separately via SetSecret.
type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	FromAddr string `json:"from_addr"`
	ToAddr   string `json:"to_addr"`
	Username string `json:"username"`
}

type Provider struct {
	ProviderID  string          `json:"provider_id"`
	Kind        string          `json:"kind"`
	DisplayName string          `json:"display_name"`
	Config      json.RawMessage `json:"config,omitempty"`
	HasSecret   bool            `json:"has_secret"`
	Enabled     bool            `json:"enabled"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

type Service struct {
	DB      *sql.DB
	Secrets *secretstore.Service
	Log     *slog.Logger // optional; used only by background schedulers (e.g. RunTLSExpiryScheduler)
}

func validate(kind, displayName string) error {
	if !validKinds[kind] {
		return fmt.Errorf("%w: invalid kind %q (must be one of webhook, email_smtp, pushover, slack)", ErrValidation, kind)
	}
	if strings.TrimSpace(displayName) == "" {
		return fmt.Errorf("%w: display_name must not be empty", ErrValidation)
	}
	return nil
}

func validateConfig(kind string, config json.RawMessage) (json.RawMessage, error) {
	if kind != "email_smtp" {
		return json.RawMessage(`{}`), nil
	}
	var cfg SMTPConfig
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return nil, fmt.Errorf("%w: invalid config: %v", ErrValidation, err)
		}
	}
	if strings.TrimSpace(cfg.Host) == "" || cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("%w: email_smtp requires host and a valid port", ErrValidation)
	}
	if strings.TrimSpace(cfg.FromAddr) == "" || strings.TrimSpace(cfg.ToAddr) == "" {
		return nil, fmt.Errorf("%w: email_smtp requires from_addr and to_addr", ErrValidation)
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func newProviderID(kind string) (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	return kind + "-" + hex.EncodeToString(suffix), nil
}

func (s *Service) List(ctx context.Context) ([]Provider, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT provider_id, kind, display_name, config_json, has_secret, enabled, created_at, updated_at FROM notification_providers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Provider{}
	for rows.Next() {
		var p Provider
		var config string
		if err := rows.Scan(&p.ProviderID, &p.Kind, &p.DisplayName, &config, &p.HasSecret, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Config = json.RawMessage(config)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) get(ctx context.Context, providerID string) (Provider, error) {
	var p Provider
	var config string
	err := s.DB.QueryRowContext(ctx, `SELECT provider_id, kind, display_name, config_json, has_secret, enabled, created_at, updated_at FROM notification_providers WHERE provider_id=?`, providerID).
		Scan(&p.ProviderID, &p.Kind, &p.DisplayName, &config, &p.HasSecret, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return Provider{}, ErrNotFound
	}
	if err != nil {
		return Provider{}, err
	}
	p.Config = json.RawMessage(config)
	return p, nil
}

func (s *Service) Create(ctx context.Context, kind, displayName string, config json.RawMessage) (Provider, error) {
	if err := validate(kind, displayName); err != nil {
		return Provider{}, err
	}
	cleanConfig, err := validateConfig(kind, config)
	if err != nil {
		return Provider{}, err
	}
	id, err := newProviderID(kind)
	if err != nil {
		return Provider{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO notification_providers (provider_id, kind, display_name, config_json, has_secret, enabled, created_at, updated_at) VALUES (?,?,?,?,0,1,?,?)`,
		id, kind, displayName, string(cleanConfig), now, now)
	if err != nil {
		return Provider{}, err
	}
	return Provider{ProviderID: id, Kind: kind, DisplayName: displayName, Config: cleanConfig, Enabled: true, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *Service) SetEnabled(ctx context.Context, providerID string, enabled bool) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.DB.ExecContext(ctx, `UPDATE notification_providers SET enabled=?, updated_at=? WHERE provider_id=?`, enabled, now, providerID)
	if err != nil {
		return err
	}
	return checkAffected(res)
}

func (s *Service) Delete(ctx context.Context, providerID string) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM notification_providers WHERE provider_id=?`, providerID)
	if err != nil {
		return err
	}
	if err := checkAffected(res); err != nil {
		return err
	}
	if s.Secrets != nil {
		// Best-effort: the provider row is already gone either way: a
		// deleted provider must never leave a live, usable secret
		// behind under its old provider_id.
		_ = s.Secrets.Revoke(ctx, SecretKind, providerID)
	}
	// This schema's ON DELETE CASCADE on notification_subscriptions is
	// inert (this codebase never sets PRAGMA foreign_keys=ON -- see
	// SetSubscription's own comment) -- clean up explicitly, or a
	// deleted provider leaves orphaned subscription rows that Dispatch
	// would still try to join against a provider that no longer exists.
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM notification_subscriptions WHERE provider_id=?`, providerID)
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM notification_rate_state WHERE provider_id=?`, providerID)
	return nil
}

// SetSecret stores/replaces this provider's credential. See
// internal/secretstore's doc comment: this process never reads the
// value back after this call returns.
func (s *Service) SetSecret(ctx context.Context, providerID, value string) error {
	if _, err := s.get(ctx, providerID); err != nil {
		return err
	}
	if s.Secrets == nil {
		return secretstore.ErrUnavailable
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: secret value must not be empty", ErrValidation)
	}
	if _, err := s.Secrets.Set(ctx, SecretKind, providerID, value); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.ExecContext(ctx, `UPDATE notification_providers SET has_secret=1, updated_at=? WHERE provider_id=?`, now, providerID)
	return err
}

// RevokeSecret clears this provider's credential -- it goes back to
// has_secret=false and can no longer be used to send/test until a new
// one is set.
func (s *Service) RevokeSecret(ctx context.Context, providerID string) error {
	if _, err := s.get(ctx, providerID); err != nil {
		return err
	}
	if s.Secrets != nil {
		if err := s.Secrets.Revoke(ctx, SecretKind, providerID); err != nil {
			return err
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.ExecContext(ctx, `UPDATE notification_providers SET has_secret=0, updated_at=? WHERE provider_id=?`, now, providerID)
	return err
}

// TestResult is the real, honest outcome of a test send -- never a
// fabricated success.
type TestResult struct {
	OK         bool   `json:"ok"`
	Detail     string `json:"detail"`
	StatusCode int    `json:"status_code,omitempty"`
}

// Test sends one real test message using this provider's stored
// credential. Runs entirely inside apdns-hostagent -- this method's
// caller (an HTTP handler) never has the plaintext credential in hand
// at any point.
func (s *Service) Test(ctx context.Context, providerID string) (TestResult, error) {
	p, err := s.get(ctx, providerID)
	if err != nil {
		return TestResult{}, err
	}
	if !p.HasSecret {
		return TestResult{}, fmt.Errorf("%w: no secret configured for this provider yet", ErrValidation)
	}
	if s.Secrets == nil {
		return TestResult{}, secretstore.ErrUnavailable
	}

	extra := map[string]any{"notify_kind": p.Kind}
	if p.Kind == "email_smtp" {
		var cfg SMTPConfig
		if err := json.Unmarshal(p.Config, &cfg); err != nil {
			return TestResult{}, fmt.Errorf("stored SMTP config is invalid: %w", err)
		}
		extra["smtp_host"] = cfg.Host
		extra["smtp_port"] = cfg.Port
		extra["from_addr"] = cfg.FromAddr
		extra["to_addr"] = cfg.ToAddr
		extra["username"] = cfg.Username
	}

	params, err := s.Secrets.SealedParams(ctx, SecretKind, providerID, extra)
	if err != nil {
		return TestResult{}, err
	}
	var out TestResult
	if err := s.Secrets.CallNotifyTest(ctx, params, &out); err != nil {
		return TestResult{}, err
	}
	return out, nil
}

func checkAffected(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
