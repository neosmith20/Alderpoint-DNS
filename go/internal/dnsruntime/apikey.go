package dnsruntime

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"time"
)

// LoadOrCreateDnsdistAPIKey returns the persisted dnsdist webserver API
// key (dnsdist_api_key, a singleton row -- see that migration's own doc
// comment for the real cross-restart authentication gap this closes),
// generating and storing one on first use. Safe for concurrent callers
// (an INSERT OR IGNORE race just means the loser's own generated value
// is discarded in favor of whichever row actually landed first).
func LoadOrCreateDnsdistAPIKey(ctx context.Context, db *sql.DB) (string, error) {
	var existing string
	err := db.QueryRowContext(ctx, `SELECT key_value FROM dnsdist_api_key WHERE id = 1`).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}

	keyBytes := make([]byte, 24)
	if _, rerr := rand.Read(keyBytes); rerr != nil {
		return "", rerr
	}
	generated := base64.RawURLEncoding.EncodeToString(keyBytes)

	if _, err := db.ExecContext(ctx,
		`INSERT OR IGNORE INTO dnsdist_api_key (id, key_value, created_at) VALUES (1, ?, ?)`,
		generated, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return "", err
	}

	// Re-read rather than assume our own INSERT won a concurrent race --
	// this call site only ever runs once at process startup in practice,
	// but costs nothing to make correct regardless.
	if err := db.QueryRowContext(ctx, `SELECT key_value FROM dnsdist_api_key WHERE id = 1`).Scan(&existing); err != nil {
		return "", err
	}
	return existing, nil
}
