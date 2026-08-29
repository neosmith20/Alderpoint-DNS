package replication

import (
	"context"
	"net"
	"strconv"
	"testing"
)

// freePort asks the OS for a currently-unused loopback port -- the same
// approach every other disposable-fixture test in this codebase uses.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestFullEnrollmentAndSyncBetweenTwoRealNodes is the end-to-end proof
// the rebuild's own requirements call for: two independent Service
// instances (their own database, their own hostagent, their own cert
// directory -- genuinely two separate nodes, not two views of one),
// talking over a REAL mTLS connection on a real loopback port. Proves
// enrollment, sync, peer removal/revocation, restart persistence, and
// drift/error handling all for real.
func TestFullEnrollmentAndSyncBetweenTwoRealNodes(t *testing.T) {
	ctx := context.Background()
	port := freePort(t)

	primary := newTestService(t)
	// Real owner order: configure the listen address/port FIRST, then
	// switch to primary -- SetRole's own auto-start uses whatever
	// settings already exist at that moment (matching Python's own
	// ensure_primary_listener_running() singleton, which the same way
	// never re-reads settings after it's already running), so a test
	// that flips the role before configuring the port would start the
	// real listener on the WRONG (default) port -- a real ordering bug
	// this test itself caught once, not a hypothetical.
	if err := primary.UpdateSettings(ctx, "127.0.0.1", port, 5, false); err != nil {
		t.Fatal(err)
	}
	if err := primary.SetRole(ctx, "primary"); err != nil {
		t.Fatal(err)
	}
	if !primary.ListenerRunning() {
		t.Fatal("expected the real mTLS listener to be running after SetRole(primary)")
	}
	t.Cleanup(primary.StopPrimaryListener)

	// Seed real primary-side state before publishing a generation.
	mustExec(t, primary.DB, `INSERT INTO local_dns_records (name, record_type, value, ttl, enabled, created_at, updated_at) VALUES ('printer.lan','A','10.0.0.50',300,1,?,?)`, now(), now())
	gen1, err := primary.CreateGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gen1.GenerationNumber != 1 {
		t.Fatalf("expected generation 1, got %d", gen1.GenerationNumber)
	}

	token, err := primary.GenerateEnrollmentToken(ctx, "test-replica")
	if err != nil {
		t.Fatal(err)
	}

	replica := newTestService(t)
	enrolled, err := replica.EnrollWithPrimary(ctx, "127.0.0.1", port, token.Token)
	if err != nil {
		t.Fatalf("real enrollment over mTLS failed: %v", err)
	}
	if enrolled.ClientCertPEM == "" || enrolled.CACertPEM == "" {
		t.Fatalf("expected real cert material from enrollment, got %+v", enrolled)
	}
	if err := replica.StoreEnrollmentMaterial(ctx, "127.0.0.1:"+strconv.Itoa(port), enrolled); err != nil {
		t.Fatal(err)
	}

	replicasOnPrimary, err := primary.ListReplicas(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(replicasOnPrimary) != 1 || replicasOnPrimary[0].DisplayName != "test-replica" {
		t.Fatalf("expected the primary to record the real new replica, got %+v", replicasOnPrimary)
	}

	// --- real sync over the real mTLS connection ---
	result := replica.SyncOnce(ctx, false)
	if result.Result != "success" {
		t.Fatalf("expected a real successful sync, got %+v", result)
	}
	var gotRecord string
	if err := replica.DB.QueryRowContext(ctx, `SELECT name FROM local_dns_records`).Scan(&gotRecord); err != nil || gotRecord != "printer.lan" {
		t.Fatalf("expected the replica to have really applied the primary's local DNS record, got %q err=%v", gotRecord, err)
	}

	// The primary must have recorded a real ack from this specific replica.
	replicasOnPrimary, _ = primary.ListReplicas(ctx)
	if replicasOnPrimary[0].LastGenerationAcked != 1 {
		t.Fatalf("expected the primary to record the replica's real ack, got %+v", replicasOnPrimary[0])
	}
	if replicasOnPrimary[0].LastSeenAt == "" {
		t.Fatal("expected the primary to record a real last_seen_at from the mTLS-authenticated request")
	}

	settings, _ := replica.GetSettings(ctx)
	if settings.LastAppliedGeneration != 1 || settings.LastAppliedHash != gen1.ContentHash {
		t.Fatalf("expected the replica's own settings to reflect the real applied generation, got %+v", settings)
	}

	// A second sync with nothing new must report up_to_date, not
	// silently re-apply.
	result2 := replica.SyncOnce(ctx, false)
	if result2.Result != "up_to_date" {
		t.Fatalf("expected up_to_date on a second sync with no new generation, got %+v", result2)
	}

	// --- drift detection: a manual edit on the replica, outside replication ---
	mustExec(t, replica.DB, `INSERT INTO custom_rules (rule_type, pattern, enabled, priority, created_at) VALUES ('block','manual.example.com',1,0,?)`, now())
	drifted, _, _, err := replica.CheckDrift(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !drifted {
		t.Fatal("expected a real manual edit on the replica to be detected as drift")
	}

	// --- restart persistence: a brand-new Service pointed at the SAME
	// database/cert dir must see the same real state (settings, CA,
	// replicas) without needing to re-enroll -- simulating a real
	// process restart.
	restarted := &Service{DB: replica.DB, HostAgent: replica.HostAgent, CertDir: replica.CertDir, Log: replica.Log}
	restartedSettings, err := restarted.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if restartedSettings.Role != "replica" || restartedSettings.LastAppliedGeneration != 1 {
		t.Fatalf("expected settings to persist across a real restart, got %+v", restartedSettings)
	}
	// The restarted instance can still sync using the same on-disk
	// enrollment material (client cert/key/CA cert are real files, not
	// in-memory state).
	primaryRestarted := &Service{DB: primary.DB, HostAgent: primary.HostAgent, CertDir: primary.CertDir, Log: primary.Log, server: primary.server}
	mustExec(t, primaryRestarted.DB, `INSERT INTO local_dns_records (name, record_type, value, ttl, enabled, created_at, updated_at) VALUES ('nas.lan','A','10.0.0.60',300,1,?,?)`, now(), now())
	gen2, err := primaryRestarted.CreateGeneration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if gen2.GenerationNumber != 2 {
		t.Fatalf("expected generation 2, got %d", gen2.GenerationNumber)
	}
	resultAfterRestart := restarted.SyncOnce(ctx, false)
	if resultAfterRestart.Result != "success" {
		t.Fatalf("expected the restarted replica to sync successfully using its persisted enrollment material, got %+v", resultAfterRestart)
	}

	// --- peer removal/revocation: primary revokes the replica; a
	// subsequent sync attempt must be REJECTED (403-mapped to a "failed"
	// SyncOnce result via an unreachable/failed sync), proving the
	// revocation is actually enforced by the mTLS listener, not just a
	// cosmetic status flag. ---
	if err := primary.SetReplicaStatus(ctx, replicasOnPrimary[0].ID, "revoked"); err != nil {
		t.Fatal(err)
	}
	mustExec(t, primary.DB, `INSERT INTO local_dns_records (name, record_type, value, ttl, enabled, created_at, updated_at) VALUES ('should-not-sync.lan','A','10.0.0.70',300,1,?,?)`, now(), now())
	if _, err := primary.CreateGeneration(ctx); err != nil {
		t.Fatal(err)
	}
	resultAfterRevoke := restarted.SyncOnce(ctx, true)
	if resultAfterRevoke.Result == "success" {
		t.Fatal("expected sync to be REJECTED after the replica's certificate was revoked, not silently succeed")
	}
	var count int
	restarted.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_dns_records WHERE name='should-not-sync.lan'`).Scan(&count)
	if count != 0 {
		t.Fatal("expected the revoked replica to NOT have applied a generation published after its revocation")
	}
}

// TestSyncOfUnreachablePrimaryIsAnHonestUnreachableNotACrash proves DNS-
// safety: a replica whose primary is completely unreachable must report
// a clean "unreachable" result, never panic or hang past the client
// timeout.
func TestSyncOfUnreachablePrimaryIsAnHonestUnreachableNotACrash(t *testing.T) {
	replica := newTestService(t)
	ctx := context.Background()
	replica.SetRole(ctx, "replica")
	// Point at a real, currently-unused port -- nothing is listening.
	replica.setSetting(ctx, "primary_address", "127.0.0.1:"+strconv.Itoa(freePort(t)))
	// Fabricate just-enough "enrollment material" (self-consistent, but
	// nothing is listening on the far end) so buildReplicaTransportConfig
	// gets past its own file-existence check and actually attempts the
	// real network connection this test is proving fails cleanly.
	seedFakeEnrollmentMaterial(t, replica)

	result := replica.SyncOnce(ctx, false)
	if result.Result != "unreachable" {
		t.Fatalf("expected an honest 'unreachable' result, got %+v", result)
	}
}

func seedFakeEnrollmentMaterial(t *testing.T, s *Service) {
	t.Helper()
	// A real, disposable throwaway CA + client leaf -- reuses this same
	// package's own real cert-issuing hostagent op, not hand-rolled PEM.
	src := newTestService(t)
	ctx := context.Background()
	src.SetRole(ctx, "primary")
	token, err := src.GenerateEnrollmentToken(ctx, "throwaway")
	if err != nil {
		t.Fatal(err)
	}
	result, err := src.ConsumeEnrollment(ctx, token.Token)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StoreEnrollmentMaterial(ctx, "unused", result); err != nil {
		t.Fatal(err)
	}
}
