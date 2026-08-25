package localdns

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE local_dns_records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		record_type TEXT NOT NULL CHECK(record_type IN ('A','AAAA','CNAME','PTR')),
		value TEXT NOT NULL,
		ttl INTEGER NOT NULL DEFAULT 300,
		enabled INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL,
		UNIQUE(name, record_type, value)
	)`)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return &Service{DB: db, StagingDir: filepath.Join(dir, "staging"), RuntimeDir: filepath.Join(dir, "runtime")}
}

func TestCreateListUpdateDelete(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	rec, err := svc.Create(ctx, CreateInput{Name: "host1.lan", RecordType: "A", Value: "10.0.0.5", TTL: 300, Enabled: true})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.Name != "host1.lan" {
		t.Errorf("name = %q", rec.Name)
	}

	list, err := svc.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v, len=%d", err, len(list))
	}

	newIP := "10.0.0.6"
	updated, err := svc.Update(ctx, rec.ID, UpdateInput{Value: &newIP})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Value != newIP {
		t.Errorf("value = %q, want %q", updated.Value, newIP)
	}

	if err := svc.Delete(ctx, rec.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	list, _ = svc.List(ctx)
	if len(list) != 0 {
		t.Fatalf("expected 0 records after delete, got %d", len(list))
	}

	// Runtime artifact should reflect the now-empty state (staged +
	// promoted, atomically).
	runtimeFile := filepath.Join(svc.RuntimeDir, "local-dns.hosts")
	data, err := os.ReadFile(runtimeFile)
	if err != nil {
		t.Fatalf("runtime artifact missing: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected empty runtime artifact, got %q", data)
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	cases := []struct {
		name string
		in   CreateInput
		ok   bool
	}{
		{"valid A", CreateInput{Name: "host.lan", RecordType: "A", Value: "192.168.1.1", TTL: 300, Enabled: true}, true},
		{"invalid A (not an IPv4)", CreateInput{Name: "host2.lan", RecordType: "A", Value: "not-an-ip", TTL: 300, Enabled: true}, false},
		{"A given IPv6", CreateInput{Name: "host3.lan", RecordType: "A", Value: "::1", TTL: 300, Enabled: true}, false},
		{"valid AAAA", CreateInput{Name: "host4.lan", RecordType: "AAAA", Value: "::1", TTL: 300, Enabled: true}, true},
		{"valid CNAME", CreateInput{Name: "alias.lan", RecordType: "CNAME", Value: "host.lan", TTL: 300, Enabled: true}, true},
		{"invalid record type", CreateInput{Name: "host5.lan", RecordType: "MX", Value: "10 mail.lan", TTL: 300, Enabled: true}, false},
		{"invalid hostname", CreateInput{Name: "-bad-.lan", RecordType: "A", Value: "10.0.0.1", TTL: 300, Enabled: true}, false},
		{"invalid ttl", CreateInput{Name: "host6.lan", RecordType: "A", Value: "10.0.0.1", TTL: 0, Enabled: true}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := svc.Create(ctx, c.in)
			if c.ok && err != nil {
				t.Errorf("expected success, got error: %v", err)
			}
			if !c.ok && err == nil {
				t.Errorf("expected an error, got success")
			}
		})
	}
}

func TestDuplicateRejected(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)
	in := CreateInput{Name: "dup.lan", RecordType: "A", Value: "10.0.0.1", TTL: 300, Enabled: true}
	if _, err := svc.Create(ctx, in); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if _, err := svc.Create(ctx, in); err != ErrDuplicate {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
}

func TestUpdateNotFound(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)
	newVal := "10.0.0.1"
	if _, err := svc.Update(ctx, 999, UpdateInput{Value: &newVal}); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
