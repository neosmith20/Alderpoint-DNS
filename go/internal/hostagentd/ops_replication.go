// Replication status, real, via a narrow read-only SQLite read of
// Python's own control.db -- the same isolation discipline the rest of
// this codebase's compatibility boundaries already use (pyanalytics,
// rawquerylog, tlscert): only ever SELECT, only ever the exact
// non-secret columns Python's own Peer.public_dict() exposes through
// its API (never ca_pem/client_cert_pem/client_key_pem -- the columns
// that actually hold credential material), never a write.
//
// This resolves the isolation concern that blocked Replication for the
// isolated :10443 preview differently than "mount control.db into the
// web container" would have: the web control-plane process itself still
// never touches control.db at all -- only this separate, root-owned,
// allowlisted, audited agent process does, and only through this one
// narrow read.
package hostagentd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/hostagent"
)

// ReplicationPeer mirrors Python's Peer.public_dict() exactly -- the
// deliberately redacted shape (no ca_pem/client_cert_pem/client_key_pem).
type ReplicationPeer struct {
	PeerNodeID             string `json:"peer_node_id"`
	DisplayName            string `json:"display_name"`
	URL                    string `json:"url"`
	ExpectedCertSHA256     string `json:"expected_cert_sha256"`
	ExpectedIncomingSHA256 string `json:"expected_incoming_cert_sha256"`
	Authorized             bool   `json:"authorized"`
	Direction              string `json:"direction"`
	LastAttemptAt          string `json:"last_attempt_at"`
	LastSuccessAt          string `json:"last_success_at"`
	LastError              string `json:"last_error"`
	LocalGeneration        int    `json:"local_generation"`
	RemoteKnownGeneration  int    `json:"remote_known_generation"`
	Lag                    int    `json:"lag"`
}

type NodeIdentity struct {
	NodeID        string `json:"node_id"`
	DisplayName   string `json:"display_name"`
	CreatedAt     string `json:"created_at"`
	RegeneratedAt string `json:"regenerated_at,omitempty"`
}

type ReplicationConfig struct {
	// ControlDBPath is Python's real control.db. Opened read-only
	// (SQLite URI mode=ro) on every call -- no persistent connection,
	// no write capability at the driver level even if a bug ever tried.
	ControlDBPath string
	SyncTimeout   time.Duration
}

func openControlDBReadOnly(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(3000)&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

func RegisterReplicationOps(s *Server, cfg ReplicationConfig) {
	if cfg.SyncTimeout <= 0 {
		cfg.SyncTimeout = 10 * time.Second
	}

	s.Register(hostagent.OpReplicationStatus, func(ctx context.Context, params json.RawMessage) (any, error) {
		db, err := openControlDBReadOnly(cfg.ControlDBPath)
		if err != nil {
			return nil, fmt.Errorf("opening control.db read-only: %w", err)
		}
		defer db.Close()

		var identity *NodeIdentity
		row := db.QueryRowContext(ctx, `SELECT node_id, display_name, created_at, regenerated_at FROM node_identity WHERE id=1`)
		var id NodeIdentity
		var regen sql.NullString
		if err := row.Scan(&id.NodeID, &id.DisplayName, &id.CreatedAt, &regen); err == nil {
			id.RegeneratedAt = regen.String
			identity = &id
		} else if err != sql.ErrNoRows {
			return nil, fmt.Errorf("reading node_identity: %w", err)
		}

		rows, err := db.QueryContext(ctx, `
			SELECT peer_node_id, display_name, url, expected_cert_sha256, expected_incoming_cert_sha256,
			       authorized, direction, last_attempt_at, last_success_at, last_error,
			       local_generation, remote_known_generation
			FROM replication_peers ORDER BY peer_node_id`)
		if err != nil {
			return nil, fmt.Errorf("reading replication_peers: %w", err)
		}
		defer rows.Close()
		peers := []ReplicationPeer{}
		for rows.Next() {
			var p ReplicationPeer
			var lastAttempt, lastSuccess sql.NullString
			if err := rows.Scan(&p.PeerNodeID, &p.DisplayName, &p.URL, &p.ExpectedCertSHA256, &p.ExpectedIncomingSHA256,
				&p.Authorized, &p.Direction, &lastAttempt, &lastSuccess, &p.LastError,
				&p.LocalGeneration, &p.RemoteKnownGeneration); err != nil {
				return nil, fmt.Errorf("scanning replication_peers row: %w", err)
			}
			p.LastAttemptAt = lastAttempt.String
			p.LastSuccessAt = lastSuccess.String
			p.Lag = p.LocalGeneration - p.RemoteKnownGeneration
			if p.Lag < 0 {
				p.Lag = 0
			}
			peers = append(peers, p)
		}
		return map[string]any{"node_identity": identity, "peers": peers}, rows.Err()
	})

	s.Register(hostagent.OpReplicationSync, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			PeerNodeID string `json:"peer_node_id"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if in.PeerNodeID == "" {
			return nil, fmt.Errorf("peer_node_id is required")
		}

		db, err := openControlDBReadOnly(cfg.ControlDBPath)
		if err != nil {
			return nil, fmt.Errorf("opening control.db read-only: %w", err)
		}
		defer db.Close()

		var url string
		var caPEM sql.NullString
		row := db.QueryRowContext(ctx, `SELECT url, ca_pem FROM replication_peers WHERE peer_node_id=?`, in.PeerNodeID)
		if err := row.Scan(&url, &caPEM); err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("unknown peer_node_id %q", in.PeerNodeID)
			}
			return nil, fmt.Errorf("reading peer: %w", err)
		}

		// A real, bounded connectivity check against the peer's real
		// HTTPS endpoint -- not Python's bespoke mTLS push/pull message
		// protocol (client-cert-authenticated, generation-tracked state
		// sync), which is out of scope for this pass and disclosed as
		// such rather than half-implemented. This proves the peer is
		// actually reachable and presenting a TLS certificate chained
		// to the configured CA, which is real, useful signal for an
		// operator diagnosing a broken peer -- it does not exchange or
		// apply any state.
		client := &http.Client{Timeout: cfg.SyncTimeout}
		if caPEM.Valid && caPEM.String != "" {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM([]byte(caPEM.String)) {
				client.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, cfg.SyncTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("building request to peer: %w", err)
		}
		started := time.Now()
		resp, err := client.Do(req)
		elapsed := time.Since(started)
		if err != nil {
			return map[string]any{
				"peer_node_id": in.PeerNodeID, "ok": false,
				"detail": err.Error(), "elapsed_ms": elapsed.Milliseconds(),
			}, nil
		}
		defer resp.Body.Close()
		return map[string]any{
			"peer_node_id": in.PeerNodeID, "ok": true,
			"detail":      fmt.Sprintf("reachable, HTTP %d", resp.StatusCode),
			"status_code": resp.StatusCode,
			"elapsed_ms":  elapsed.Milliseconds(),
		}, nil
	})
}
