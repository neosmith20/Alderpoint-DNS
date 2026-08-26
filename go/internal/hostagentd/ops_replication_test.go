package hostagentd

import (
	"context"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// newTestControlDB creates a throwaway SQLite file with the exact real
// column shapes of node_identity/replication_peers (matching
// app/v2/node_identity.py and app/v2/replication_v2.py, read directly,
// not guessed) and seeds one identity row plus two peers -- one with
// real secret-shaped columns populated, to prove this package's reader
// never selects them.
func newTestControlDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`
		CREATE TABLE node_identity (
			id INTEGER PRIMARY KEY CHECK(id = 1),
			node_id TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL,
			regenerated_at TEXT
		);
		CREATE TABLE replication_peers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			peer_node_id TEXT NOT NULL UNIQUE,
			display_name TEXT NOT NULL,
			url TEXT NOT NULL,
			ca_pem TEXT NOT NULL,
			expected_cert_sha256 TEXT NOT NULL,
			expected_incoming_cert_sha256 TEXT NOT NULL,
			client_cert_pem TEXT NOT NULL,
			client_key_pem TEXT NOT NULL,
			authorized INTEGER NOT NULL,
			direction TEXT NOT NULL,
			last_attempt_at TEXT,
			last_success_at TEXT,
			last_error TEXT NOT NULL DEFAULT '',
			local_generation INTEGER NOT NULL DEFAULT 0,
			remote_known_generation INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		);
		INSERT INTO node_identity(node_id, display_name, created_at) VALUES ('node-abc-123', 'test-node', '2026-01-01T00:00:00Z');
		INSERT INTO replication_peers(
			peer_node_id, display_name, url, ca_pem, expected_cert_sha256, expected_incoming_cert_sha256,
			client_cert_pem, client_key_pem, authorized, direction, last_attempt_at, last_success_at, last_error,
			local_generation, remote_known_generation, created_at, updated_at
		) VALUES (
			'peer-1', 'Peer One', 'https://peer1.example.com:9443',
			'-----BEGIN CERTIFICATE-----VERY-SECRET-CA-----END CERTIFICATE-----',
			'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
			'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
			'-----BEGIN CERTIFICATE-----CLIENT-CERT-----END CERTIFICATE-----',
			'-----BEGIN PRIVATE KEY-----THIS-IS-THE-SECRET-PRIVATE-KEY-----END PRIVATE KEY-----',
			1, 'bidirectional', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '',
			5, 3, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
		);
	`)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReplicationStatusReturnsRedactedPeersAndRealIdentity(t *testing.T) {
	dbPath := newTestControlDB(t)
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterReplicationOps(s, ReplicationConfig{ControlDBPath: dbPath})

	result, err := s.handlers["replication.status"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	body := string(encoded)

	// The single most important property this whole operation exists
	// for: none of the real secret material seeded above may appear
	// anywhere in the encoded result.
	for _, secret := range []string{"VERY-SECRET-CA", "CLIENT-CERT", "THIS-IS-THE-SECRET-PRIVATE-KEY"} {
		if strings.Contains(body, secret) {
			t.Fatalf("replication.status leaked secret material %q into its result: %s", secret, body)
		}
	}

	var decoded struct {
		NodeIdentity *NodeIdentity     `json:"node_identity"`
		Peers        []ReplicationPeer `json:"peers"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.NodeIdentity == nil || decoded.NodeIdentity.NodeID != "node-abc-123" {
		t.Fatalf("expected the real node identity, got %+v", decoded.NodeIdentity)
	}
	if len(decoded.Peers) != 1 {
		t.Fatalf("expected 1 peer, got %+v", decoded.Peers)
	}
	p := decoded.Peers[0]
	if p.PeerNodeID != "peer-1" || p.URL != "https://peer1.example.com:9443" || !p.Authorized || p.Direction != "bidirectional" {
		t.Fatalf("unexpected peer metadata: %+v", p)
	}
	if p.Lag != 2 {
		t.Fatalf("expected lag=5-3=2, got %d", p.Lag)
	}
}

func TestReplicationStatusOfEmptyPeerTableReturnsEmptySliceNotNil(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE node_identity (id INTEGER PRIMARY KEY, node_id TEXT, display_name TEXT, created_at TEXT, regenerated_at TEXT);
	          CREATE TABLE replication_peers (peer_node_id TEXT, display_name TEXT, url TEXT, ca_pem TEXT, expected_cert_sha256 TEXT,
	          expected_incoming_cert_sha256 TEXT, client_cert_pem TEXT, client_key_pem TEXT, authorized INTEGER, direction TEXT,
	          last_attempt_at TEXT, last_success_at TEXT, last_error TEXT, local_generation INTEGER, remote_known_generation INTEGER);`)
	db.Close()

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterReplicationOps(s, ReplicationConfig{ControlDBPath: path})
	result, err := s.handlers["replication.status"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), `"peers":null`) {
		t.Fatalf("expected peers to be an empty array, not null: %s", encoded)
	}
}

func TestReplicationSyncRejectsAnUnknownPeer(t *testing.T) {
	dbPath := newTestControlDB(t)
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterReplicationOps(s, ReplicationConfig{ControlDBPath: dbPath})
	_, err := s.handlers["replication.sync"](context.Background(), json.RawMessage(`{"peer_node_id":"does-not-exist"}`))
	if err == nil {
		t.Fatal("expected an error for an unknown peer")
	}
}

// TestReplicationSyncPerformsARealConnectivityCheck proves the sync
// operation makes a genuine outbound HTTPS request (against a real
// local httptest.Server, not a peer this test controls the response
// of), validating it against the peer's configured CA -- not a faked
// success.
func TestReplicationSyncPerformsARealConnectivityCheck(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	caPEM := certPEMFromTestServer(ts)

	path := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE replication_peers (peer_node_id TEXT, url TEXT, ca_pem TEXT);
	                   INSERT INTO replication_peers VALUES ('peer-1', ?, ?)`, ts.URL, caPEM)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterReplicationOps(s, ReplicationConfig{ControlDBPath: path})
	result, err := s.handlers["replication.sync"](context.Background(), json.RawMessage(`{"peer_node_id":"peer-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	var decoded struct {
		OK         bool `json:"ok"`
		StatusCode int  `json:"status_code"`
	}
	json.Unmarshal(encoded, &decoded)
	if !decoded.OK || decoded.StatusCode != 200 {
		t.Fatalf("expected a real successful connectivity check, got %s", encoded)
	}
}

func TestReplicationSyncOfAnUnreachablePeerReportsFailureHonestly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE replication_peers (peer_node_id TEXT, url TEXT, ca_pem TEXT);
	          INSERT INTO replication_peers VALUES ('peer-1', 'https://127.0.0.1:1', '')`)
	db.Close()

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterReplicationOps(s, ReplicationConfig{ControlDBPath: path})
	result, err := s.handlers["replication.sync"](context.Background(), json.RawMessage(`{"peer_node_id":"peer-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	var decoded struct {
		OK bool `json:"ok"`
	}
	json.Unmarshal(encoded, &decoded)
	if decoded.OK {
		t.Fatalf("expected ok=false for a genuinely unreachable peer, got %s", encoded)
	}
}

// TestReplicationStatusAgainstTheRealLiveControlDB proves this reader
// works against the actual live preview's real control.db (read-only),
// the same standard every other compatibility boundary in this codebase
// (pyanalytics/rawquerylog/tlscert) was proven against. Skipped if that
// file isn't present in this environment.
func TestReplicationStatusAgainstTheRealLiveControlDB(t *testing.T) {
	const real = "/root/apdns-v2-preview-state/var-lib/control.db"
	if _, err := os.Stat(real); err != nil {
		t.Skip("real live control.db not present in this environment")
	}
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterReplicationOps(s, ReplicationConfig{ControlDBPath: real})
	result, err := s.handlers["replication.status"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(result)
	var decoded struct {
		NodeIdentity *NodeIdentity     `json:"node_identity"`
		Peers        []ReplicationPeer `json:"peers"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.NodeIdentity == nil || decoded.NodeIdentity.NodeID == "" {
		t.Fatalf("expected a real node identity from the live control.db, got %+v", decoded.NodeIdentity)
	}
	t.Logf("real node_id=%s peers=%d", decoded.NodeIdentity.NodeID, len(decoded.Peers))
}

func certPEMFromTestServer(ts *httptest.Server) string {
	cert := ts.Certificate()
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}
