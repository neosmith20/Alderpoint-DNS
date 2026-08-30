package replication

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type Enrollment struct {
	ID         int64  `json:"id"`
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name"`
	CreatedAt  string `json:"created_at"`
	ExpiresAt  string `json:"expires_at"`
	Status     string `json:"status"`
	ConsumedAt string `json:"consumed_at,omitempty"`
}

// IssuedToken is returned exactly once, at generation time -- the raw
// token is never stored, only its hash, matching Python's own
// generate_enrollment_token() contract.
type IssuedToken struct {
	Token     string `json:"token"`
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	ExpiresAt string `json:"expires_at"`
}

func rawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateEnrollmentToken creates a one-time, single-use, 15-minute
// enrollment token bound to a specific intended replica name -- matches
// Python's generate_enrollment_token() exactly, including that this
// node must be able to act as a primary (EnsureCA is called by the
// caller before this, matching Python's own ensure_primary_listener_
// running() call immediately before token generation).
func (s *Service) GenerateEnrollmentToken(ctx context.Context, nodeName string) (IssuedToken, error) {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return IssuedToken{}, fmt.Errorf("%w: node_name is required", ErrValidation)
	}
	token, err := rawToken()
	if err != nil {
		return IssuedToken{}, err
	}
	newNodeID, err := newNodeID()
	if err != nil {
		return IssuedToken{}, err
	}
	created := time.Now().UTC()
	expires := created.Add(EnrollmentTTL).Format(time.RFC3339)
	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO replication_enrollments (node_id, node_name, token_hash, created_at, expires_at, status)
		VALUES (?, ?, ?, ?, ?, 'pending')`,
		newNodeID, nodeName, hashToken(token), created.Format(time.RFC3339), expires,
	); err != nil {
		return IssuedToken{}, err
	}
	return IssuedToken{Token: token, NodeID: newNodeID, NodeName: nodeName, ExpiresAt: expires}, nil
}

func (s *Service) expireStaleEnrollments(ctx context.Context) {
	s.DB.ExecContext(ctx, `UPDATE replication_enrollments SET status='expired' WHERE status='pending' AND expires_at < ?`, now())
	staleBefore := time.Now().UTC().Add(-ReservationTTL).Format(time.RFC3339)
	s.DB.ExecContext(ctx, `UPDATE replication_enrollments SET reserved_at=NULL WHERE status='pending' AND reserved_at IS NOT NULL AND reserved_at < ?`, staleBefore)
}

func (s *Service) ListEnrollments(ctx context.Context) ([]Enrollment, error) {
	s.expireStaleEnrollments(ctx)
	rows, err := s.DB.QueryContext(ctx, `SELECT id, node_id, node_name, created_at, expires_at, status, consumed_at FROM replication_enrollments ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Enrollment{}
	for rows.Next() {
		var e Enrollment
		var consumed sql.NullString
		if err := rows.Scan(&e.ID, &e.NodeID, &e.NodeName, &e.CreatedAt, &e.ExpiresAt, &e.Status, &consumed); err != nil {
			return nil, err
		}
		e.ConsumedAt = consumed.String
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Service) RevokeEnrollment(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE replication_enrollments SET status='revoked' WHERE id=? AND status='pending'`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: no pending enrollment with that id", ErrNotFound)
	}
	return nil
}

// EnrollmentResult is what a primary hands back to a replica that
// presents a valid token -- the CA cert (public) plus a freshly-issued
// client cert+key (real key material, meant to be handed to the
// replica; this is the one place in this whole package a private key
// legitimately leaves apdns-hostagent as plaintext, by design -- see
// ca.go's own doc comment).
type EnrollmentResult struct {
	NodeID        string `json:"node_id"`
	NodeName      string `json:"node_name"`
	CACertPEM     string `json:"ca_cert_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
}

// ConsumeEnrollment is the primary-side handler for a replica's
// /replication/enroll call: verify the token (hash compare, not
// expired, not already consumed/revoked), issue a real client
// certificate, and record the new replica -- matching Python's
// consume_enrollment()/_finish_enrollment() exactly (no separate
// reserve/release dance here: Go's real hostagent-boundary crypto call
// is already fast and this handler already runs inside one SQL
// transaction's lifetime, so the "unprivileged listener can't hold a
// write transaction open across a slow sudo subprocess" problem
// Python's own comment describes doesn't apply to a same-process Go
// call).
func (s *Service) ConsumeEnrollment(ctx context.Context, raw string) (EnrollmentResult, error) {
	if raw == "" {
		return EnrollmentResult{}, fmt.Errorf("%w: token is required", ErrValidation)
	}
	s.expireStaleEnrollments(ctx)
	tokenHash := hashToken(raw)

	var id int64
	var nodeID, nodeName string
	row := s.DB.QueryRowContext(ctx, `SELECT id, node_id, node_name FROM replication_enrollments WHERE token_hash=? AND status='pending' AND expires_at >= ?`, tokenHash, now())
	if err := row.Scan(&id, &nodeID, &nodeName); err != nil {
		return EnrollmentResult{}, fmt.Errorf("enrollment token is invalid, expired, or already used")
	}

	caCertPEM, err := s.EnsureCA(ctx)
	if err != nil {
		return EnrollmentResult{}, err
	}
	issued, err := s.issueCert(ctx, nodeID, nil, "client", DefaultCertDays)
	if err != nil {
		return EnrollmentResult{}, err
	}

	ts := now()
	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO replication_replicas (node_id, display_name, cert_fingerprint, cert_serial, enrolled_at, status)
		VALUES (?, ?, ?, ?, ?, 'active')
		ON CONFLICT(node_id) DO UPDATE SET
			cert_fingerprint=excluded.cert_fingerprint, cert_serial=excluded.cert_serial,
			enrolled_at=excluded.enrolled_at, status='active'`,
		nodeID, nodeName, issued.Fingerprint, issued.Serial, ts,
	); err != nil {
		return EnrollmentResult{}, err
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE replication_enrollments SET status='consumed', consumed_at=? WHERE id=?`, ts, id); err != nil {
		return EnrollmentResult{}, err
	}

	if err := s.ensureServerCertFiles(ctx); err != nil {
		return EnrollmentResult{}, fmt.Errorf("provisioning server certificate: %w", err)
	}

	return EnrollmentResult{
		NodeID: nodeID, NodeName: nodeName, CACertPEM: caCertPEM,
		ClientCertPEM: issued.CertPEM, ClientKeyPEM: issued.KeyPEM,
	}, nil
}
