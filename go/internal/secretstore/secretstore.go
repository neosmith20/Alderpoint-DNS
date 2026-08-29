// Package secretstore is the web control plane's own half of the
// native Go secrets subsystem -- see internal/hostagentd/ops_secrets.go
// for the other half (the actual master key and AEAD engine, which
// never runs in this process).
//
// Design (the highest-leverage gap the 2026-08-27 database-at-rest
// audit identified): this process (the unprivileged web binary) can
// create, list metadata for, and revoke secrets, but it can NEVER read
// a secret's plaintext value back. The `secrets` table (schema
// migration 0012) stores only AES-256-GCM ciphertext + a nonce + which
// master-key version sealed it -- the key itself is generated and held
// only by apdns-hostagent (root, outside this container, never
// dumped/logged/returned over any API). Every actual USE of a secret
// (sending a real webhook, authenticating an upstream query, signing a
// replication request, ...) is a narrow, purpose-named hostagent
// operation that decrypts internally and performs exactly one bounded
// real action -- there is no generic "decrypt this for me" operation
// anywhere in this system, by design.
//
// Context binding: at seal time, `kind` and `ownerRef` (e.g.
// "notification_secret" + a provider_id) are folded into the AEAD's
// associated data. A ciphertext blob copied to a different secret's row
// -- or the same row's `kind`/`owner_ref` renamed --  will fail to
// decrypt (an authentication failure, not silently wrong data), so
// stored ciphertext cannot be replayed against a different record. The
// master key is itself already unique per appliance (generated locally,
// never exported) -- there is no cross-appliance replay concern to add
// an appliance identifier for on top of that.
package secretstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

var (
	ErrNotFound    = errors.New("secret not found")
	ErrUnavailable = errors.New("secrets subsystem unavailable (host-control agent not configured or not reachable)")
)

// Record is everything about a stored secret EXCEPT its value -- safe
// to log, return over an API, or include in a listing. Never carries
// plaintext or ciphertext.
type Record struct {
	ID         string  `json:"id"`
	Kind       string  `json:"kind"`
	OwnerRef   string  `json:"owner_ref"`
	KeyVersion int     `json:"key_version"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
	RevokedAt  *string `json:"revoked_at,omitempty"`
}

// sealed is the ciphertext-bearing shape used only internally, between
// this package and a narrow "use" hostagent op -- never serialized to
// any HTTP response.
type sealed struct {
	CiphertextB64 string
	NonceB64      string
	KeyVersion    int
}

type Service struct {
	DB        *sql.DB
	HostAgent *hostagent.Client
}

// Set creates a new secret version for (kind, ownerRef), revoking any
// prior non-revoked version for the same pair (kept, never deleted --
// an audit trail of "a secret existed here and was replaced on this
// date", not a way to recover the old value). The plaintext is sent to
// apdns-hostagent over the same trusted local unix-socket boundary
// every other privileged operation in this codebase already uses (see
// internal/hostagent's doc comment); it is never written to this
// process's own disk, logs, or database in cleartext.
func (s *Service) Set(ctx context.Context, kind, ownerRef, plaintext string) (Record, error) {
	if s.HostAgent == nil {
		return Record{}, ErrUnavailable
	}
	if kind == "" || ownerRef == "" {
		return Record{}, fmt.Errorf("kind and owner_ref are required")
	}
	if plaintext == "" {
		return Record{}, fmt.Errorf("secret value must not be empty")
	}

	var out struct {
		CiphertextB64 string `json:"ciphertext_b64"`
		NonceB64      string `json:"nonce_b64"`
		KeyVersion    int    `json:"key_version"`
	}
	if err := s.HostAgent.Call(ctx, hostagent.OpSecretsSeal, map[string]any{
		"kind": kind, "owner_ref": ownerRef, "value": plaintext,
	}, &out); err != nil {
		return Record{}, fmt.Errorf("sealing secret: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(out.CiphertextB64)
	if err != nil {
		return Record{}, fmt.Errorf("decoding sealed ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(out.NonceB64)
	if err != nil {
		return Record{}, fmt.Errorf("decoding sealed nonce: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE secrets SET revoked_at=? WHERE kind=? AND owner_ref=? AND revoked_at IS NULL`,
		now, kind, ownerRef); err != nil {
		return Record{}, err
	}

	id, err := newID()
	if err != nil {
		return Record{}, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO secrets (id, kind, owner_ref, key_version, nonce, ciphertext, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`,
		id, kind, ownerRef, out.KeyVersion, nonce, ciphertext, now, now); err != nil {
		return Record{}, err
	}
	if err := tx.Commit(); err != nil {
		return Record{}, err
	}
	return Record{ID: id, Kind: kind, OwnerRef: ownerRef, KeyVersion: out.KeyVersion, CreatedAt: now, UpdatedAt: now}, nil
}

// Status returns the current (non-revoked) secret's metadata for
// (kind, ownerRef), or (nil, nil) if none has ever been set -- never an
// error for the ordinary "not configured yet" case.
func (s *Service) Status(ctx context.Context, kind, ownerRef string) (*Record, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT id, kind, owner_ref, key_version, created_at, updated_at, revoked_at FROM secrets WHERE kind=? AND owner_ref=? AND revoked_at IS NULL`,
		kind, ownerRef)
	var r Record
	if err := row.Scan(&r.ID, &r.Kind, &r.OwnerRef, &r.KeyVersion, &r.CreatedAt, &r.UpdatedAt, &r.RevokedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// Revoke marks (kind, ownerRef)'s current secret revoked -- kept, not
// deleted, matching Set's own audit-trail policy. A no-op (not an
// error) if none was set.
func (s *Service) Revoke(ctx context.Context, kind, ownerRef string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.DB.ExecContext(ctx, `UPDATE secrets SET revoked_at=? WHERE kind=? AND owner_ref=? AND revoked_at IS NULL`, now, kind, ownerRef)
	return err
}

// sealedFor loads the current ciphertext blob for (kind, ownerRef) --
// package-internal only, handed straight to a narrow "use" hostagent
// op, never returned from any exported function that a handler could
// accidentally serialize to an HTTP response.
func (s *Service) sealedFor(ctx context.Context, kind, ownerRef string) (sealed, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT key_version, nonce, ciphertext FROM secrets WHERE kind=? AND owner_ref=? AND revoked_at IS NULL`,
		kind, ownerRef)
	var keyVersion int
	var nonce, ciphertext []byte
	if err := row.Scan(&keyVersion, &nonce, &ciphertext); err != nil {
		if err == sql.ErrNoRows {
			return sealed{}, ErrNotFound
		}
		return sealed{}, err
	}
	return sealed{
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		KeyVersion:    keyVersion,
	}, nil
}

// SealedParams returns the wire-format fields a narrow "use" hostagent
// op expects (ciphertext_b64/nonce_b64/key_version/kind/owner_ref) for
// (kind, ownerRef), merged with the caller's own op-specific params.
// This is the ONE sanctioned way another package reaches into a stored
// secret -- always immediately as input to one specific hostagent op,
// never resolved to plaintext in this process.
func (s *Service) SealedParams(ctx context.Context, kind, ownerRef string, extra map[string]any) (map[string]any, error) {
	if s.HostAgent == nil {
		return nil, ErrUnavailable
	}
	sl, err := s.sealedFor(ctx, kind, ownerRef)
	if err != nil {
		return nil, err
	}
	params := map[string]any{
		"kind": kind, "owner_ref": ownerRef,
		"ciphertext_b64": sl.CiphertextB64, "nonce_b64": sl.NonceB64, "key_version": sl.KeyVersion,
	}
	for k, v := range extra {
		params[k] = v
	}
	return params, nil
}

// CallNotifyTest is a thin, named passthrough to
// hostagent.OpSecretsNotifyTest -- kept here (rather than making every
// caller import internal/hostagent directly just for one op constant)
// so this package stays the single place that knows the wire-level
// operation names for the secrets subsystem.
func (s *Service) CallNotifyTest(ctx context.Context, params map[string]any, out any) error {
	if s.HostAgent == nil {
		return ErrUnavailable
	}
	return s.HostAgent.Call(ctx, hostagent.OpSecretsNotifyTest, params, out)
}

// CallNotifySend is CallNotifyTest's real-dispatch sibling -- see
// hostagent.OpSecretsNotifySend's own doc comment.
func (s *Service) CallNotifySend(ctx context.Context, params map[string]any, out any) error {
	if s.HostAgent == nil {
		return ErrUnavailable
	}
	return s.HostAgent.Call(ctx, hostagent.OpSecretsNotifySend, params, out)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
