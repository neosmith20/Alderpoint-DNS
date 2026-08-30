// Package replication is the real Go-native replacement for the dead
// Python-control.db-reading Replication feature (see PARITY_MATRIX.md's
// 2026-08-29 entries). Rebuilt against V1.1.1's actual owner-facing
// workflow (app/replication.py, read directly, ~1600 lines): one-way
// primary-to-replica configuration sync over mutual TLS, with:
//
//   - a stable per-node identity (node_id, generated once via CSPRNG,
//     matching internal/clientid's own discipline -- never derived from
//     hostname);
//   - token-based enrollment: the primary issues a one-time, single-use,
//     short-lived token; a replica presents it once to receive a real
//     client certificate signed by a local CA, after which every
//     subsequent call is mutual-TLS-authenticated, never a password;
//   - numbered, content-hashed "generations": every time the primary's
//     replicable state changes, it can publish a new generation; a
//     replica polls for the latest one, verifies the hash, and applies
//     it transactionally, snapshotting first so a failed apply always
//     rolls back cleanly;
//   - drift detection: a replica can recompute its own live-table hash
//     and compare it against what it last successfully applied, to
//     catch manual edits made directly on the replica outside of
//     replication;
//   - safe error states throughout: replication failure (primary down,
//     replica down, revoked cert, corrupted generation) never
//     interrupts DNS service on either node -- a replica that can't
//     reach its primary simply keeps serving whatever it last applied.
//
// Two things are deliberately different from V1.1.1, both disclosed:
//
//   - The replicable-table allowlist is translated to this Go-native
//     schema, not a byte-for-byte copy of Python's table names (see
//     ReplicableTables/BuildPayload's own doc comment for the exact
//     list and the reasoning behind each inclusion/exclusion).
//   - The CA private key lives sealed inside the same Go-native secrets
//     subsystem internal/secretstore's sibling features already use
//     (apdns-hostagent's AES-256-GCM engine) rather than Python's own
//     SecretStore -- see ca.go. Signing (both the CA's own self-signed
//     cert and every leaf cert issued from it) happens entirely inside
//     apdns-hostagent; the plaintext CA key never exists outside that
//     one process, at rest or in memory anywhere else.
//
// Architecture: unlike Cache/Network/Logs (which need root/NET_ADMIN-
// equivalent host access), the mTLS listener, generation build/apply,
// and the replica poller are all plain SQLite + Go's own crypto/tls --
// no privilege needed, so they run entirely inside the unprivileged
// `alderpointdns-go web` process. Only CA generation and cert signing
// route through apdns-hostagent, for the key-custody reason above, not
// because of any OS permission requirement.
package replication

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

var ErrValidation = errors.New("validation failed")
var ErrNotFound = errors.New("not found")

// Roles mirrors Python's ROLES set exactly.
var Roles = map[string]bool{"standalone": true, "primary": true, "replica": true}

const (
	EnrollmentTTL          = 15 * time.Minute
	ReservationTTL         = 45 * time.Second
	DefaultListenPort      = 8843
	DefaultPollIntervalSec = 60
	MaxBackoffSeconds      = 300
	SchemaVersion          = 1
	DefaultCertDays        = 825
)

// Service is the single entry point every HTTP handler and background
// loop in this package goes through. HostAgent is required for any
// operation that touches the CA (EnsureCA, issuing a cert during
// enrollment or server-cert provisioning) -- nil-safe, matching this
// codebase's "optional, never fatal" boundary contract elsewhere: those
// specific calls report unavailable rather than panicking, and DNS
// answering is never affected either way.
type Service struct {
	DB        *sql.DB
	HostAgent *hostagent.Client
	CertDir   string // where the primary's own server cert/key and a replica's own client cert/key/CA cert live -- real files, not secrets (see transport.go's own doc comment for why)
	Log       *slog.Logger

	// DeployFn lets the caller (cmd/alderpointdns-go) hook in real DNS-
	// runtime recompilation after a successful replica apply, without
	// this package importing internal/dnsruntime directly -- see
	// sync.go's own doc comment. Nil means "database-level apply only,
	// no runtime recompilation attempted" -- still real, still
	// rollback-safe.
	DeployFn DeployFunc

	poller *replicaPoller
	server *primaryListener
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// newNodeID is a fresh, CSPRNG-backed 128-bit identity, hex-encoded --
// matching internal/clientid's own "OS-backed CSPRNG, never math/rand"
// discipline. Not a UUID string (no need for the dashes/version bits a
// real UUID library would add for a value nothing ever parses back
// apart) but the same real entropy Python's uuid.uuid4() carries.
func newNodeID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating node id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *Service) hostAgentCall(ctx context.Context, op string, params, out any) error {
	if s.HostAgent == nil {
		return fmt.Errorf("the host-control agent is not configured or not reachable")
	}
	return s.HostAgent.Call(ctx, op, params, out)
}
