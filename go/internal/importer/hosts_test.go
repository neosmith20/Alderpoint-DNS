package importer

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"

	"alderpointdns/go-controlplane/internal/dbmigrate"
	"alderpointdns/go-controlplane/internal/localdns"
)

func newTestLocalDNS(t *testing.T) *localdns.Service {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := dbmigrate.Up(context.Background(), db, "../../schema/migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	dir := t.TempDir()
	return &localdns.Service{DB: db, StagingDir: filepath.Join(dir, "staging"), RuntimeDir: filepath.Join(dir, "runtime")}
}

func TestImportHostsBasicFile(t *testing.T) {
	svc := newTestLocalDNS(t)
	text := "127.0.0.1 localhost\n10.0.0.5 nas nas.lan\n# a comment line\n\n::1 ip6-localhost\n"
	res, err := ImportHosts(context.Background(), svc, text)
	if err != nil {
		t.Fatal(err)
	}
	// localhost, nas, nas.lan, ip6-localhost = 4 real hostnames imported.
	if res.Imported != 4 {
		t.Fatalf("expected 4 imported, got %+v", res)
	}
	if res.Skipped != 0 {
		t.Fatalf("expected 0 skipped, got %+v", res)
	}

	records, err := svc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("expected 4 real records created, got %+v", records)
	}
	byName := map[string]localdns.Record{}
	for _, r := range records {
		byName[r.Name] = r
	}
	if byName["nas"].RecordType != "A" || byName["nas"].Value != "10.0.0.5" {
		t.Fatalf("expected nas -> A 10.0.0.5, got %+v", byName["nas"])
	}
	if byName["ip6-localhost"].RecordType != "AAAA" || byName["ip6-localhost"].Value != "::1" {
		t.Fatalf("expected ip6-localhost -> AAAA ::1, got %+v", byName["ip6-localhost"])
	}
}

func TestImportHostsSkipsInvalidIPWithoutAbortingTheRest(t *testing.T) {
	svc := newTestLocalDNS(t)
	text := "not-an-ip broken.example.com\n10.0.0.9 good.example.com\n"
	res, err := ImportHosts(context.Background(), svc, text)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 || res.Skipped != 1 || len(res.Errors) != 1 {
		t.Fatalf("expected 1 imported + 1 skipped with an error recorded, got %+v", res)
	}
	records, _ := svc.List(context.Background())
	if len(records) != 1 || records[0].Name != "good.example.com" {
		t.Fatalf("expected only the good line to have created a record, got %+v", records)
	}
}

func TestImportHostsDuplicateEntryIsRecordedNotFatal(t *testing.T) {
	svc := newTestLocalDNS(t)
	text := "10.0.0.5 dup.example.com\n10.0.0.5 dup.example.com\n"
	res, err := ImportHosts(context.Background(), svc, text)
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 || res.Skipped != 1 {
		t.Fatalf("expected the duplicate line to be skipped with an error, not silently dropped or fatal, got %+v", res)
	}
}

func TestImportHostsEmptyTextImportsNothing(t *testing.T) {
	svc := newTestLocalDNS(t)
	res, err := ImportHosts(context.Background(), svc, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 0 || res.Skipped != 0 {
		t.Fatalf("expected nothing imported for empty text, got %+v", res)
	}
	if res.Errors == nil {
		t.Fatal("expected Errors to be an empty slice, not nil (would JSON-marshal to null)")
	}
}
