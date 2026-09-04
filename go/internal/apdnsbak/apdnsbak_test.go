package apdnsbak

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

// realApdnsbakFixture returns a real .apdnsbak archive's bytes --
// generated once against the actual (now-decommissioned) Python
// app/v2/backup_restore.py + app/v2/secret_store.py modules and checked
// in as a static fixture (see testdata/fixture.apdnsbak's own
// generation, recorded in this repo's history), proving this Go reader
// against real output from the real tool that produced these archives,
// without this test SUITE ever executing that Python code itself (see
// the 2026-09-04 zero-Python audit: V2 must not execute old Python code,
// even in tests -- reading a real fixture it once produced is fine,
// re-running it on every `go test` is not). The fixture's own DB seeded
// exactly one row, `local_dns_records` name='apdnsbak-printer.lan', under
// passphrase "test-restore-passphrase" -- see the assertions below.
func realApdnsbakFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/fixture.apdnsbak")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestExtractRealApdnsbakArchive(t *testing.T) {
	data := realApdnsbakFixture(t)

	dbPath, manifest, cleanup, err := Extract(data, "test-restore-passphrase")
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Product != productID {
		t.Fatalf("expected product=%q, got %+v", productID, manifest)
	}
	if manifest.SourceNodeID != "fixture-node" {
		t.Fatalf("expected source_node_id to round-trip, got %+v", manifest)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err := db.QueryRow(`SELECT name FROM local_dns_records`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "apdnsbak-printer.lan" {
		t.Fatalf("expected apdnsbak-printer.lan, got %q", name)
	}
}

func TestExtractWithWrongPassphraseFails(t *testing.T) {
	data := realApdnsbakFixture(t)
	_, _, cleanup, err := Extract(data, "wrong-passphrase")
	defer cleanup()
	if err != ErrWrongPassphrase {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
}

func TestExtractWithNoPassphraseFails(t *testing.T) {
	data := realApdnsbakFixture(t)
	_, _, cleanup, err := Extract(data, "")
	defer cleanup()
	if err != ErrPassphraseRequired {
		t.Fatalf("expected ErrPassphraseRequired, got %v", err)
	}
}

func TestExtractOfLocalModeArchiveIsRejectedAsNotPortable(t *testing.T) {
	// A "local mode" archive has no FILE_MAGIC header at all -- just a
	// raw Fernet token keyed from the ORIGINAL appliance's own secret
	// store, meaningless to decrypt from anywhere else.
	_, _, cleanup, err := Extract([]byte("not a portable backup, no magic header"), "irrelevant")
	defer cleanup()
	if err != ErrNotPortable {
		t.Fatalf("expected ErrNotPortable, got %v", err)
	}
}

func TestIsApdnsbakName(t *testing.T) {
	if !IsApdnsbakName("appliance-1787460039.apdnsbak") {
		t.Fatal("expected a real .apdnsbak filename to match")
	}
	if IsApdnsbakName("appliance.tar.gz") {
		t.Fatal("expected a .tar.gz filename not to match")
	}
}
