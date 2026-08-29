package apdnsbak

import (
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// buildRealApdnsbakFixture generates a real .apdnsbak archive using the
// actual Python app/v2/backup_restore.py + app/v2/secret_store.py
// modules from this repo -- proving this Go reader against real output
// from the real tool that produces these archives, not a hand-built
// byte string.
func buildRealApdnsbakFixture(t *testing.T, passphrase string) []byte {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available for building a real .apdnsbak fixture")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "control.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE local_dns_records (
		id INTEGER PRIMARY KEY, name TEXT NOT NULL, record_type TEXT NOT NULL,
		value TEXT NOT NULL, ttl INTEGER NOT NULL DEFAULT 300, enabled INTEGER NOT NULL DEFAULT 1,
		created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(name, record_type, value)
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO local_dns_records(name, record_type, value, ttl, enabled, created_at, updated_at)
		VALUES('apdnsbak-printer.lan','A','10.0.0.88',300,1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	backupPath := filepath.Join(dir, "fixture.apdnsbak")
	script := `
import sys
sys.path.insert(0, "` + repoRoot(t) + `")
from pathlib import Path
from app.v2.backup_restore import create_appliance_backup
from app.v2.secret_store import SecretStore

store = SecretStore(Path(sys.argv[3]))
create_appliance_backup(
    control_db_path=Path(sys.argv[1]),
    secret_store=store,
    key=b"unused-in-passphrase-mode-000000",
    backup_path=Path(sys.argv[2]),
    source_version="v2-test",
    passphrase=sys.argv[4],
    source_node_id="fixture-node",
)
`
	secretDir := filepath.Join(dir, "secretstore")
	cmd := exec.Command("python3", "-c", script, dbPath, backupPath, secretDir, passphrase)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("building real .apdnsbak fixture (python deps missing?): %v: %s", err, out)
	}
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../../../")
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestExtractRealApdnsbakArchive(t *testing.T) {
	data := buildRealApdnsbakFixture(t, "test-restore-passphrase")

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
	data := buildRealApdnsbakFixture(t, "test-restore-passphrase")
	_, _, cleanup, err := Extract(data, "wrong-passphrase")
	defer cleanup()
	if err != ErrWrongPassphrase {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
}

func TestExtractWithNoPassphraseFails(t *testing.T) {
	data := buildRealApdnsbakFixture(t, "test-restore-passphrase")
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
