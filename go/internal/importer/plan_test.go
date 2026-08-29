package importer

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/backup"
	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/localdns"
)

func newTestService(t *testing.T) *Service {
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
	return &Service{
		DB:       db,
		LocalDNS: &localdns.Service{DB: db, StagingDir: t.TempDir(), RuntimeDir: t.TempDir()},
		Backup:   &backup.Service{DB: db, Dir: t.TempDir(), Version: "test"},
	}
}

func TestParseToPlanRejectsUnsupportedSourceType(t *testing.T) {
	if _, err := ParseToPlan("adguard", "x", ""); err == nil {
		t.Fatal("expected an error for an unsupported source_type")
	}
}

func TestParseHostsPlan(t *testing.T) {
	plan := parseHostsPlan("10.0.0.1 a.lan b.lan\n# comment\n\n10.0.0.2 c.lan\nmalformed-line")
	if len(plan.Rows) != 3 {
		t.Fatalf("expected 3 rows, got %d: %+v", len(plan.Rows), plan.Rows)
	}
	if plan.Rows[0].Name != "a.lan" || plan.Rows[0].Value != "10.0.0.1" {
		t.Errorf("unexpected first row: %+v", plan.Rows[0])
	}
}

func TestParseCSVPlan(t *testing.T) {
	plan := parseCSVPlan("name,record_type,value,ttl\nprinter.lan,A,10.0.0.50,600\nnas.lan,A,10.0.0.60,")
	if len(plan.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %d: %+v (errors: %v)", len(plan.Rows), plan.Rows, plan.ParseErrors)
	}
	if plan.Rows[0].TTL != 600 {
		t.Errorf("expected explicit ttl 600, got %d", plan.Rows[0].TTL)
	}
	if plan.Rows[1].TTL != hostsImportTTL {
		t.Errorf("expected the default ttl for an empty ttl cell, got %d", plan.Rows[1].TTL)
	}
}

func TestCreateJobAnnotatesRealConflicts(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.LocalDNS.Create(ctx, localdns.CreateInput{Name: "existing.lan", RecordType: "A", Value: "10.0.0.9", TTL: 300, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	job, err := s.CreateJob(ctx, "csv", "test.csv", "name,record_type,value\nexisting.lan,A,10.0.0.9\nnew.lan,A,10.0.0.10", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Plan.Rows) != 2 {
		t.Fatalf("expected 2 planned rows, got %d", len(job.Plan.Rows))
	}
	if !job.Plan.Rows[0].Conflict {
		t.Error("expected the row matching an existing record to be flagged as a conflict")
	}
	if job.Plan.Rows[1].Conflict {
		t.Error("expected the genuinely new row to not be flagged as a conflict")
	}
	if job.Status != "pending" {
		t.Errorf("expected a freshly created job to be pending, got %q", job.Status)
	}
	// Nothing written to local_dns_records yet -- CreateJob only plans.
	recs, err := s.LocalDNS.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected only the pre-seeded record (CreateJob must not write), got %d", len(recs))
	}
}

func TestApplyJobRealApplyWithSkipAndSnapshot(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	job, err := s.CreateJob(ctx, "csv", "test.csv", "name,record_type,value\nkeep.lan,A,10.0.0.1\nskip-me.lan,A,10.0.0.2", "")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.ApplyJob(ctx, job.ID, []int{1}) // skip index 1 (skip-me.lan)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != "applied" {
		t.Fatalf("expected status=applied, got %q", applied.Status)
	}
	if applied.Result == nil || applied.Result.Imported != 1 || applied.Result.Skipped != 1 {
		t.Fatalf("expected 1 imported + 1 skipped, got %+v", applied.Result)
	}
	if applied.SnapshotFilename == nil || *applied.SnapshotFilename == "" {
		t.Fatal("expected a real pre-apply snapshot filename to be recorded")
	}

	recs, err := s.LocalDNS.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Name != "keep.lan" {
		t.Fatalf("expected exactly the non-skipped row to be imported, got %+v", recs)
	}
}

func TestApplyJobIsIdempotent(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	job, err := s.CreateJob(ctx, "csv", "test.csv", "name,record_type,value\nonce.lan,A,10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyJob(ctx, job.ID, nil); err != nil {
		t.Fatal(err)
	}
	applied2, err := s.ApplyJob(ctx, job.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if applied2.Result.Imported != 0 || applied2.Result.Skipped != 1 {
		t.Fatalf("expected the second apply to skip the already-imported row (real duplicate detection), got %+v", applied2.Result)
	}
	recs, err := s.LocalDNS.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 {
		t.Fatalf("re-applying must never duplicate rows, got %d records", len(recs))
	}
}

func TestRollbackRestoresThePreApplyState(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	job, err := s.CreateJob(ctx, "csv", "test.csv", "name,record_type,value\nnew.lan,A,10.0.0.5", "")
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.ApplyJob(ctx, job.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	recsAfterApply, _ := s.LocalDNS.List(ctx)
	if len(recsAfterApply) != 1 {
		t.Fatalf("expected the apply to have written a real row, got %d", len(recsAfterApply))
	}

	if _, err := s.Rollback(ctx, applied.ID); err != nil {
		t.Fatal(err)
	}
	recsAfterRollback, err := s.LocalDNS.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recsAfterRollback) != 0 {
		t.Fatalf("expected rollback to restore the pre-apply (empty) state, got %d records", len(recsAfterRollback))
	}
}

func TestRollbackOfAnUnappliedJobIsRejected(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	job, err := s.CreateJob(ctx, "csv", "test.csv", "name,record_type,value\nnew.lan,A,10.0.0.5", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Rollback(ctx, job.ID); err == nil {
		t.Fatal("expected rollback of a never-applied job to be rejected (no snapshot exists)")
	}
}

func TestParseZonePlanRequiresDefaultDomain(t *testing.T) {
	if _, err := ParseToPlan("zone", "www IN A 10.0.0.5", ""); err == nil {
		t.Fatal("expected an error when default_domain is missing for a zone import")
	}
}

func TestParseZonePlan(t *testing.T) {
	plan, err := ParseToPlan("zone", "www IN A 10.0.0.5\nmail 600 IN A 10.0.0.6\n", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %+v", plan.Rows)
	}
	if plan.Rows[0].Name != "www.example.com" || plan.Rows[0].TTL != 300 {
		t.Fatalf("unexpected row 0: %+v", plan.Rows[0])
	}
	if plan.Rows[1].TTL != 600 {
		t.Fatalf("expected the explicit TTL to be honored, got %+v", plan.Rows[1])
	}
}

// TestCreateJobZoneAnnotatesConflictsAndAppliesThroughTheSameJobWorkflow
// proves zone-file import gets the same real preview/conflict/apply/
// rollback treatment as hosts and csv -- not a second-class one-shot
// path.
func TestCreateJobZoneAnnotatesConflictsAndAppliesThroughTheSameJobWorkflow(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()
	if _, err := s.LocalDNS.Create(ctx, localdns.CreateInput{Name: "existing.example.com", RecordType: "A", Value: "10.0.0.9", TTL: 300, Enabled: true}); err != nil {
		t.Fatal(err)
	}

	job, err := s.CreateJob(ctx, "zone", "test.zone", "existing IN A 10.0.0.9\nnew IN A 10.0.0.10\n", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(job.Plan.Rows) != 2 {
		t.Fatalf("expected 2 rows, got %+v", job.Plan.Rows)
	}
	if !job.Plan.Rows[0].Conflict {
		t.Fatalf("expected the existing record to be flagged as a conflict, got %+v", job.Plan.Rows[0])
	}
	if job.Plan.Rows[1].Conflict {
		t.Fatalf("expected the new record to NOT be flagged as a conflict, got %+v", job.Plan.Rows[1])
	}

	applied, err := s.ApplyJob(ctx, job.ID, []int{0}) // skip the conflicting row
	if err != nil {
		t.Fatal(err)
	}
	if applied.Result.Imported != 1 {
		t.Fatalf("expected only the non-conflicting row to be applied, got %+v", applied.Result)
	}
	records, err := s.LocalDNS.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 { // existing.example.com + new.example.com
		t.Fatalf("expected 2 real records after apply, got %+v", records)
	}
}
