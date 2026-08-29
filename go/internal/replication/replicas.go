package replication

import (
	"context"
	"database/sql"
	"fmt"
)

type Replica struct {
	ID                  int64  `json:"id"`
	NodeID              string `json:"node_id"`
	DisplayName         string `json:"display_name"`
	CertFingerprint     string `json:"cert_fingerprint"`
	CertSerial          string `json:"cert_serial"`
	EnrolledAt          string `json:"enrolled_at"`
	Status              string `json:"status"`
	LastGenerationAcked int64  `json:"last_generation_acked"`
	LastAckHash         string `json:"last_ack_hash"`
	LastSeenAt          string `json:"last_seen_at,omitempty"`
	LastResult          string `json:"last_result"`
}

func (s *Service) ListReplicas(ctx context.Context) ([]Replica, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, node_id, display_name, cert_fingerprint, cert_serial, enrolled_at, status,
		       last_generation_acked, last_ack_hash, last_seen_at, last_result
		FROM replication_replicas ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Replica{}
	for rows.Next() {
		var r Replica
		var lastSeen sql.NullString
		if err := rows.Scan(&r.ID, &r.NodeID, &r.DisplayName, &r.CertFingerprint, &r.CertSerial, &r.EnrolledAt, &r.Status,
			&r.LastGenerationAcked, &r.LastAckHash, &lastSeen, &r.LastResult); err != nil {
			return nil, err
		}
		r.LastSeenAt = lastSeen.String
		out = append(out, r)
	}
	return out, rows.Err()
}

var validReplicaStatus = map[string]bool{"active": true, "paused": true, "revoked": true}

// SetReplicaStatus is the real peer add/remove/revoke primitive:
// "revoked" means this replica's certificate is no longer accepted by
// the mTLS listener (checked on every real request, see transport.go)
// even though the certificate itself remains cryptographically valid --
// matching Python's own documented revoke semantics exactly (no CRL,
// no cert-level revocation; a status check on every authenticated call
// instead).
func (s *Service) SetReplicaStatus(ctx context.Context, id int64, status string) error {
	if !validReplicaStatus[status] {
		return fmt.Errorf("%w: unknown replica status %q", ErrValidation, status)
	}
	res, err := s.DB.ExecContext(ctx, `UPDATE replication_replicas SET status=? WHERE id=?`, status, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: no replica with that id", ErrNotFound)
	}
	return nil
}

func (s *Service) replicaByFingerprint(ctx context.Context, fingerprint string) (*Replica, error) {
	row := s.DB.QueryRowContext(ctx, `
		SELECT id, node_id, display_name, cert_fingerprint, cert_serial, enrolled_at, status,
		       last_generation_acked, last_ack_hash, last_seen_at, last_result
		FROM replication_replicas WHERE cert_fingerprint=?`, fingerprint)
	var r Replica
	var lastSeen sql.NullString
	err := row.Scan(&r.ID, &r.NodeID, &r.DisplayName, &r.CertFingerprint, &r.CertSerial, &r.EnrolledAt, &r.Status,
		&r.LastGenerationAcked, &r.LastAckHash, &lastSeen, &r.LastResult)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.LastSeenAt = lastSeen.String
	return &r, nil
}
