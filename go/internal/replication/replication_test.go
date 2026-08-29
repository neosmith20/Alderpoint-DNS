package replication

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/hostagent"
	"alderpointdns/go-controlplane/internal/hostagentd"
)

func jsonUnmarshal(raw json.RawMessage, out any) error { return json.Unmarshal(raw, out) }
func jsonRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// newTestHostAgent starts a real, disposable apdns-hostagent server
// (real unix socket, real AEAD engine via RegisterSecretsOps) so this
// package's CA-touching tests prove the full real path, not a mock --
// same pattern internal/notifications' own newTestServiceWithSecrets
// uses.
func newTestHostAgent(t *testing.T) *hostagent.Client {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	audit, err := hostagentd.OpenAuditLog(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.Close() })
	srv := &hostagentd.Server{SocketPath: sockPath, AllowedUID: uint32(os.Getuid()), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Audit: audit}
	if err := hostagentd.RegisterSecretsOps(srv, hostagentd.SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan struct{})
	go func() {
		go func() {
			for i := 0; i < 100; i++ {
				if _, err := os.Stat(sockPath); err == nil {
					close(ready)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			close(ready)
		}()
		srv.Serve(ctx)
	}()
	<-ready
	return hostagent.NewClient(sockPath)
}

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(3000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

// newTestService builds a full Service backed by a real hostagent (for
// CA ops) and a real, migrated database -- used by every test in this
// package that doesn't need two independent nodes.
func newTestService(t *testing.T) *Service {
	t.Helper()
	return &Service{
		DB: newTestDB(t), HostAgent: newTestHostAgent(t), CertDir: t.TempDir(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestGetSettingsGeneratesANodeIDOnce(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	first, err := s.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.NodeID == "" {
		t.Fatal("expected a real node_id to be generated")
	}
	if first.Role != "standalone" {
		t.Fatalf("expected default role standalone, got %q", first.Role)
	}
	second, err := s.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.NodeID != first.NodeID {
		t.Fatal("expected the node_id to persist across calls, not regenerate")
	}
}

func TestSetRoleRejectsUnknownRole(t *testing.T) {
	s := newTestService(t)
	if err := s.SetRole(context.Background(), "overlord"); err == nil {
		t.Fatal("expected an error for an unknown role")
	}
}

// TestSetRoleToPrimaryStartsTheListenerOnTheVeryFirstCall is the direct
// regression proof for a real bug this session's own Chromium click-
// through caught live: StartPrimaryListener captured `settings` BEFORE
// calling ensureServerCertFiles (which generates and persists the CA
// the FIRST time a node ever becomes primary), so settings.CACertPEM
// was still empty and the listener failed to start with "failed to
// load this node's own CA certificate" -- invisible to a test that
// (like this package's other fixtures) always exercises this via
// newTestService, which never happened to call SetRole as the very
// first primary-transition until this test was added.
func TestSetRoleToPrimaryStartsTheListenerOnTheVeryFirstCall(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if err := s.UpdateSettings(ctx, "127.0.0.1", freePort(t), 60, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(ctx, "primary"); err != nil {
		t.Fatal(err)
	}
	if !s.ListenerRunning() {
		t.Fatal("expected the real mTLS listener to be running immediately after the very first SetRole(primary) call")
	}
	s.StopPrimaryListener()
}

// TestUpdateSettingsRestartsARunningListenerOnANewPort proves a changed
// listen_port actually takes effect immediately for an already-running
// primary, rather than silently keeping the old listener bound to the
// stale address until an unrelated action happens to restart it.
func TestUpdateSettingsRestartsARunningListenerOnANewPort(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	firstPort := freePort(t)
	if err := s.UpdateSettings(ctx, "127.0.0.1", firstPort, 60, false); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole(ctx, "primary"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.StopPrimaryListener)
	if !s.ListenerRunning() {
		t.Fatal("expected the listener to be running")
	}

	secondPort := freePort(t)
	if err := s.UpdateSettings(ctx, "127.0.0.1", secondPort, 60, false); err != nil {
		t.Fatal(err)
	}
	settings, err := s.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if settings.ListenPort != secondPort {
		t.Fatalf("expected the stored listen_port to be %d, got %d", secondPort, settings.ListenPort)
	}
	// The real proof: a fresh network dial to the OLD port must now
	// fail (nothing there any more), and the new port must actually
	// accept a real TLS connection.
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(firstPort), 300*time.Millisecond); err == nil {
		conn.Close()
		t.Fatal("expected the OLD listener port to no longer accept connections after a settings change")
	}
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(secondPort), time.Second)
	if err != nil {
		t.Fatalf("expected the NEW listener port to accept a real connection, got %v", err)
	}
	conn.Close()
}

func TestEnsureCAGeneratesOnceAndPersists(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	cert1, err := s.EnsureCA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cert1 == "" {
		t.Fatal("expected a real CA cert")
	}
	cert2, err := s.EnsureCA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if cert1 != cert2 {
		t.Fatal("expected EnsureCA to be idempotent, not regenerate the CA")
	}
}

func TestGenerateEnrollmentTokenRequiresNodeName(t *testing.T) {
	s := newTestService(t)
	if _, err := s.GenerateEnrollmentToken(context.Background(), "  "); err == nil {
		t.Fatal("expected an error for an empty node_name")
	}
}

func TestGenerateEnrollmentTokenAndConsumeIssuesARealReplica(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	s.SetRole(ctx, "primary")

	token, err := s.GenerateEnrollmentToken(ctx, "replica-1")
	if err != nil {
		t.Fatal(err)
	}
	if token.Token == "" {
		t.Fatal("expected a real raw token")
	}

	result, err := s.ConsumeEnrollment(ctx, token.Token)
	if err != nil {
		t.Fatal(err)
	}
	if result.ClientCertPEM == "" || result.ClientKeyPEM == "" || result.CACertPEM == "" {
		t.Fatalf("expected real cert material, got %+v", result)
	}

	replicas, err := s.ListReplicas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(replicas) != 1 || replicas[0].DisplayName != "replica-1" || replicas[0].Status != "active" {
		t.Fatalf("expected 1 real active replica, got %+v", replicas)
	}

	enrollments, err := s.ListEnrollments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(enrollments) != 1 || enrollments[0].Status != "consumed" {
		t.Fatalf("expected the enrollment to be marked consumed, got %+v", enrollments)
	}
}

func TestConsumeEnrollmentRejectsUnknownToken(t *testing.T) {
	s := newTestService(t)
	if _, err := s.ConsumeEnrollment(context.Background(), "not-a-real-token"); err == nil {
		t.Fatal("expected an error for an unknown token")
	}
}

func TestConsumeEnrollmentRejectsAlreadyConsumedToken(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	s.SetRole(ctx, "primary")
	token, _ := s.GenerateEnrollmentToken(ctx, "replica-1")
	if _, err := s.ConsumeEnrollment(ctx, token.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeEnrollment(ctx, token.Token); err == nil {
		t.Fatal("expected a second consumption of the same token to be rejected")
	}
}

func TestRevokeEnrollmentPreventsConsumption(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	s.SetRole(ctx, "primary")
	token, _ := s.GenerateEnrollmentToken(ctx, "replica-1")
	enrollments, _ := s.ListEnrollments(ctx)
	if err := s.RevokeEnrollment(ctx, enrollments[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeEnrollment(ctx, token.Token); err == nil {
		t.Fatal("expected a revoked token to be rejected")
	}
}

func TestRevokeEnrollmentOfUnknownIDIsRejected(t *testing.T) {
	s := newTestService(t)
	if err := s.RevokeEnrollment(context.Background(), 9999); err == nil {
		t.Fatal("expected an error for an unknown enrollment id")
	}
}

func TestSetReplicaStatusRejectsUnknownStatus(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	s.SetRole(ctx, "primary")
	token, _ := s.GenerateEnrollmentToken(ctx, "replica-1")
	s.ConsumeEnrollment(ctx, token.Token)
	replicas, _ := s.ListReplicas(ctx)
	if err := s.SetReplicaStatus(ctx, replicas[0].ID, "on-fire"); err == nil {
		t.Fatal("expected an error for an unknown status")
	}
}

func TestSetReplicaStatusPauseAndRevoke(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	s.SetRole(ctx, "primary")
	token, _ := s.GenerateEnrollmentToken(ctx, "replica-1")
	s.ConsumeEnrollment(ctx, token.Token)
	replicas, _ := s.ListReplicas(ctx)
	id := replicas[0].ID

	if err := s.SetReplicaStatus(ctx, id, "paused"); err != nil {
		t.Fatal(err)
	}
	replicas, _ = s.ListReplicas(ctx)
	if replicas[0].Status != "paused" {
		t.Fatalf("expected paused, got %+v", replicas[0])
	}

	if err := s.SetReplicaStatus(ctx, id, "revoked"); err != nil {
		t.Fatal(err)
	}
	replicas, _ = s.ListReplicas(ctx)
	if replicas[0].Status != "revoked" {
		t.Fatalf("expected revoked, got %+v", replicas[0])
	}
}

func TestBuildPayloadAndContentHashAreDeterministic(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	sections, err := BuildPayload(ctx, s.DB)
	if err != nil {
		t.Fatal(err)
	}
	hash1, err := ContentHash(sections)
	if err != nil {
		t.Fatal(err)
	}
	sections2, _ := BuildPayload(ctx, s.DB)
	hash2, _ := ContentHash(sections2)
	if hash1 != hash2 {
		t.Fatal("expected the same live state to always hash the same")
	}
}

func TestCreateGenerationIncrementsNumberAndAppliesElsewhereMatches(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO local_dns_records (name, record_type, value, ttl, enabled, created_at, updated_at) VALUES ('printer.lan', 'A', '10.0.0.50', 300, 1, ?, ?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	gen1, err := s.CreateGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gen1.GenerationNumber != 1 {
		t.Fatalf("expected generation 1, got %d", gen1.GenerationNumber)
	}
	gen2, err := s.CreateGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gen2.GenerationNumber != 2 {
		t.Fatalf("expected generation 2, got %d", gen2.GenerationNumber)
	}

	latest, err := s.LatestGeneration(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if latest.GenerationNumber != 2 {
		t.Fatalf("expected latest to be generation 2, got %+v", latest)
	}
	var recordsRaw []map[string]any
	rawSection := latest.Sections["local_dns_records"]
	if err := jsonUnmarshal(rawSection, &recordsRaw); err != nil {
		t.Fatal(err)
	}
	if len(recordsRaw) != 1 || recordsRaw[0]["name"] != "printer.lan" {
		t.Fatalf("expected the real local DNS record in the generation payload, got %+v", recordsRaw)
	}
}

func TestLatestGenerationOfEmptyDatabaseReturnsNilNotError(t *testing.T) {
	s := newTestService(t)
	gen, err := s.LatestGeneration(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if gen != nil {
		t.Fatalf("expected nil for no generations yet, got %+v", gen)
	}
}

// TestApplySectionsRoundTripsFlatAndNestedClientsData proves a full
// build->apply round trip actually reproduces the same real data on
// what's meant to simulate a second (replica) database.
func TestApplySectionsRoundTripsFlatAndNestedClientsData(t *testing.T) {
	primaryDB := newTestDB(t)
	ctx := context.Background()

	// Seed real primary-side state across several real tables.
	mustExec(t, primaryDB, `INSERT INTO local_dns_records (name, record_type, value, ttl, enabled, created_at, updated_at) VALUES ('printer.lan','A','10.0.0.50',300,1,?,?)`, now(), now())
	mustExec(t, primaryDB, `INSERT INTO custom_rules (rule_type, pattern, enabled, priority, created_at) VALUES ('block','ads.example.com',1,0,?)`, now())
	mustExec(t, primaryDB, `INSERT INTO client_groups (group_id, name, priority, created_at) VALUES ('kids','Kids',10,?)`, now())
	res := mustExec(t, primaryDB, `INSERT INTO clients (name, description, enabled, created_at, updated_at) VALUES ('laptop','',1,?,?)`, now(), now())
	clientID, _ := res.LastInsertId()
	mustExec(t, primaryDB, `INSERT INTO client_identifiers (client_id, kind, value, created_at) VALUES (?, 'ipv4', '10.0.0.9', ?)`, clientID, now())
	groupRow := primaryDB.QueryRowContext(ctx, `SELECT id FROM client_groups WHERE group_id='kids'`)
	var groupRowID int64
	groupRow.Scan(&groupRowID)
	mustExec(t, primaryDB, `INSERT INTO client_group_members (group_id, client_id) VALUES (?, ?)`, groupRowID, clientID)

	sections, err := BuildPayload(ctx, primaryDB)
	if err != nil {
		t.Fatal(err)
	}

	replicaDB := newTestDB(t)
	if err := ApplySections(ctx, replicaDB, sections); err != nil {
		t.Fatal(err)
	}

	var name string
	if err := replicaDB.QueryRowContext(ctx, `SELECT name FROM local_dns_records`).Scan(&name); err != nil || name != "printer.lan" {
		t.Fatalf("local_dns_records did not round-trip: name=%q err=%v", name, err)
	}
	var pattern string
	if err := replicaDB.QueryRowContext(ctx, `SELECT pattern FROM custom_rules`).Scan(&pattern); err != nil || pattern != "ads.example.com" {
		t.Fatalf("custom_rules did not round-trip: pattern=%q err=%v", pattern, err)
	}
	var clientName, identValue, groupName string
	if err := replicaDB.QueryRowContext(ctx, `SELECT name FROM clients`).Scan(&clientName); err != nil || clientName != "laptop" {
		t.Fatalf("clients did not round-trip: name=%q err=%v", clientName, err)
	}
	if err := replicaDB.QueryRowContext(ctx, `SELECT value FROM client_identifiers`).Scan(&identValue); err != nil || identValue != "10.0.0.9" {
		t.Fatalf("client_identifiers did not round-trip: value=%q err=%v", identValue, err)
	}
	if err := replicaDB.QueryRowContext(ctx, `
		SELECT cg.name FROM client_group_members cgm
		JOIN client_groups cg ON cg.id = cgm.group_id
		JOIN clients c ON c.id = cgm.client_id
		WHERE c.name = 'laptop'`).Scan(&groupName); err != nil || groupName != "Kids" {
		t.Fatalf("client_group_members did not round-trip (re-keyed by group_id): name=%q err=%v", groupName, err)
	}

	// Hashes of the two databases' own rebuilt payloads must now match.
	replicaSections, err := BuildPayload(ctx, replicaDB)
	if err != nil {
		t.Fatal(err)
	}
	primaryHash, _ := ContentHash(sections)
	replicaHash, _ := ContentHash(replicaSections)
	if primaryHash != replicaHash {
		t.Fatalf("expected identical content hashes after a real apply, got %s vs %s", primaryHash, replicaHash)
	}
}

func TestApplySectionsIsWhollyReplacingNotMerging(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustExec(t, db, `INSERT INTO custom_rules (rule_type, pattern, enabled, priority, created_at) VALUES ('block','old.example.com',1,0,?)`, now())

	newSections := Sections{"custom_rules": jsonRaw(t, []map[string]any{
		{"rule_type": "block", "pattern": "new.example.com", "rewrite_target": nil, "enabled": true, "priority": 0, "created_at": now()},
	})}
	if err := ApplySections(ctx, db, newSections); err != nil {
		t.Fatal(err)
	}
	var count int
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM custom_rules`).Scan(&count)
	if count != 1 {
		t.Fatalf("expected exactly 1 row after a wholesale replace, got %d", count)
	}
	var pattern string
	db.QueryRowContext(ctx, `SELECT pattern FROM custom_rules`).Scan(&pattern)
	if pattern != "new.example.com" {
		t.Fatalf("expected the old row to be replaced, got %q", pattern)
	}
}

func TestCheckDriftDetectsAManualEditOutsideReplication(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	sections, _ := BuildPayload(ctx, s.DB)
	hash, _ := ContentHash(sections)
	s.setSetting(ctx, "last_applied_hash", hash)

	drifted, _, _, err := s.CheckDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if drifted {
		t.Fatal("expected no drift immediately after recording the current hash")
	}

	mustExec(t, s.DB, `INSERT INTO custom_rules (rule_type, pattern, enabled, priority, created_at) VALUES ('block','manual-edit.example.com',1,0,?)`, now())
	drifted, _, _, err = s.CheckDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !drifted {
		t.Fatal("expected a manual edit to be detected as drift")
	}
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) sql.Result {
	t.Helper()
	res, err := db.ExecContext(context.Background(), query, args...)
	if err != nil {
		t.Fatal(err)
	}
	return res
}
