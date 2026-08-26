// Package notifications is a native Go implementation of Notification
// Providers, matching app/v2/notification_store.py's
// notification_providers table field-for-field for the metadata columns
// (provider_id/kind/display_name/endpoint/enabled).
//
// Deliberately NOT carried over, disclosed rather than hidden:
// secret_ref. Python's own design (see that module's doc comment)
// already splits provider metadata (control.db) from the actual
// credential/token/webhook-secret (SecretStore) -- this package follows
// the metadata half of that split exactly, but there is no Go-native
// secrets store yet to hold the other half (the same disclosed gap as
// internal/upstreams's endpoint secret_ref and the Encryption page's
// DNSCrypt identity). A provider created here has no way to actually
// authenticate to its destination yet -- it is real, validated,
// listable, editable metadata, not a working notification channel.
package notifications

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrNotFound   = errors.New("unknown provider_id")
	ErrValidation = errors.New("notification provider validation failed")
)

var validKinds = map[string]bool{"webhook": true, "email_smtp": true, "pushover": true, "slack": true}

type Provider struct {
	ProviderID  string `json:"provider_id"`
	Kind        string `json:"kind"`
	DisplayName string `json:"display_name"`
	Endpoint    string `json:"endpoint"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type Service struct {
	DB *sql.DB
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

func newProviderID(kind string) (string, error) {
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	return kind + "-" + hex.EncodeToString(suffix), nil
}

func (s *Service) List(ctx context.Context) ([]Provider, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT provider_id, kind, display_name, endpoint, enabled, created_at, updated_at FROM notification_providers ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Provider{}
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ProviderID, &p.Kind, &p.DisplayName, &p.Endpoint, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Service) Create(ctx context.Context, kind, displayName, endpoint string) (Provider, error) {
	if err := validate(kind, displayName); err != nil {
		return Provider{}, err
	}
	id, err := newProviderID(kind)
	if err != nil {
		return Provider{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO notification_providers (provider_id, kind, display_name, endpoint, enabled, created_at, updated_at) VALUES (?,?,?,?,1,?,?)`,
		id, kind, displayName, endpoint, now, now)
	if err != nil {
		return Provider{}, err
	}
	return Provider{ProviderID: id, Kind: kind, DisplayName: displayName, Endpoint: endpoint, Enabled: true, CreatedAt: now, UpdatedAt: now}, nil
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
	return checkAffected(res)
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
