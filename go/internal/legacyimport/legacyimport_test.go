package legacyimport

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// buildFixtureArchive assembles a real tar.gz that matches V1.1.1's own
// create_backup() layout exactly (manifest.json + a real SQLite file at
// var/lib/alderpointdns/alderpointdns.db), using this test's own real
// `tar` binary -- not a hand-built byte string -- so a real Go tar
// reader is being tested against real tar output, same as production
// will see. If password != "", the resulting bytes are additionally
// piped through the real `openssl enc` binary with V1.1.1's own exact
// arguments, so this test proves interop with the real tool that
// produced these archives in the field, not just with this package's
// own opensslDecrypt.
func buildFixtureArchive(t *testing.T, dbBytes []byte, manifest Manifest, password string) []byte {
	t.Helper()
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	stage := t.TempDir()
	if err := os.WriteFile(filepath.Join(stage, "manifest.json"), manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	dbDir := filepath.Join(stage, "var", "lib", "alderpointdns")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "alderpointdns.db"), dbBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	cmd := exec.Command("tar", "-czf", archivePath, "-C", stage, "manifest.json", "var/lib/alderpointdns/alderpointdns.db")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("tar: %v: %s", err, out)
	}
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}

	if password == "" {
		return data
	}
	encPath := archivePath + ".enc"
	cmd = exec.Command("openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt", "-pass", "stdin", "-in", archivePath, "-out", encPath)
	cmd.Stdin = bytes.NewBufferString(password)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("openssl enc: %v: %s", err, out)
	}
	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	return encData
}

func realFixtureDB(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "src.db")
	db, err := sql.Open("sqlite", path)
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
		VALUES('printer.lan','A','10.0.0.50',300,1,datetime('now'),datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	return mustReadFile(t, path)
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestExtractUnencryptedArchiveRoundTripsARealDatabase(t *testing.T) {
	dbBytes := realFixtureDB(t)
	manifest := Manifest{
		BackupFormatVersion:     1,
		DatabaseSchemaVersion:   "42",
		AlderpointdnsAppVersion: "1.1.1",
		SHA256Checksums:         map[string]string{dbArchiveRelPath: sha256Hex(dbBytes)},
	}
	archive := buildFixtureArchive(t, dbBytes, manifest, "")

	dbPath, gotManifest, cleanup, err := Extract(archive, false, "")
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if gotManifest.DatabaseSchemaVersion != "42" {
		t.Fatalf("expected manifest to round-trip, got %+v", gotManifest)
	}
	extracted := mustReadFile(t, dbPath)
	if !bytes.Equal(extracted, dbBytes) {
		t.Fatal("expected the extracted database bytes to exactly match the original")
	}

	// Prove it's a real, openable SQLite file with the real row -- not
	// just byte-identical.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err := db.QueryRow(`SELECT name FROM local_dns_records`).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "printer.lan" {
		t.Fatalf("expected printer.lan, got %q", name)
	}
}

func TestExtractEncryptedArchiveWithTheRealOpensslBinary(t *testing.T) {
	dbBytes := realFixtureDB(t)
	manifest := Manifest{BackupFormatVersion: 1, SHA256Checksums: map[string]string{dbArchiveRelPath: sha256Hex(dbBytes)}}
	archive := buildFixtureArchive(t, dbBytes, manifest, "correct-password")

	dbPath, _, cleanup, err := Extract(archive, true, "correct-password")
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReadFile(t, dbPath), dbBytes) {
		t.Fatal("expected the decrypted+extracted database to match the original exactly")
	}
}

func TestExtractEncryptedArchiveWithWrongPasswordFails(t *testing.T) {
	dbBytes := realFixtureDB(t)
	manifest := Manifest{BackupFormatVersion: 1, SHA256Checksums: map[string]string{dbArchiveRelPath: sha256Hex(dbBytes)}}
	archive := buildFixtureArchive(t, dbBytes, manifest, "correct-password")

	_, _, cleanup, err := Extract(archive, true, "wrong-password")
	defer cleanup()
	if err == nil {
		t.Fatal("expected an error for the wrong password")
	}
}

func TestExtractWithNoPasswordOnEncryptedArchiveFails(t *testing.T) {
	dbBytes := realFixtureDB(t)
	manifest := Manifest{BackupFormatVersion: 1, SHA256Checksums: map[string]string{dbArchiveRelPath: sha256Hex(dbBytes)}}
	archive := buildFixtureArchive(t, dbBytes, manifest, "correct-password")

	_, _, cleanup, err := Extract(archive, true, "")
	defer cleanup()
	if err != ErrPasswordRequired {
		t.Fatalf("expected ErrPasswordRequired, got %v", err)
	}
}

func TestExtractRejectsATamperedChecksum(t *testing.T) {
	dbBytes := realFixtureDB(t)
	manifest := Manifest{BackupFormatVersion: 1, SHA256Checksums: map[string]string{dbArchiveRelPath: "0000000000000000000000000000000000000000000000000000000000000000"}}
	archive := buildFixtureArchive(t, dbBytes, manifest, "")

	_, _, cleanup, err := Extract(archive, false, "")
	defer cleanup()
	if err != ErrChecksumMismatch {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
}

func TestExtractRejectsAnUnsupportedFormatVersion(t *testing.T) {
	dbBytes := realFixtureDB(t)
	manifest := Manifest{BackupFormatVersion: 99, SHA256Checksums: map[string]string{dbArchiveRelPath: sha256Hex(dbBytes)}}
	archive := buildFixtureArchive(t, dbBytes, manifest, "")

	_, _, cleanup, err := Extract(archive, false, "")
	defer cleanup()
	if err == nil {
		t.Fatal("expected an error for an unsupported backup_format_version")
	}
}

func TestExtractOfArchiveMissingTheDatabaseComponentFails(t *testing.T) {
	// A real archive created with the "Database" component unchecked --
	// manifest.json present, no var/lib/alderpointdns/alderpointdns.db
	// member at all.
	stage := t.TempDir()
	manifestBytes, _ := json.Marshal(Manifest{BackupFormatVersion: 1})
	os.WriteFile(filepath.Join(stage, "manifest.json"), manifestBytes, 0o644)
	archivePath := filepath.Join(t.TempDir(), "archive.tar.gz")
	buf := new(bytes.Buffer)
	gz := gzip.NewWriter(buf)
	tw := tar.NewWriter(gz)
	data := mustReadFile(t, filepath.Join(stage, "manifest.json"))
	tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(data)), Mode: 0o644})
	tw.Write(data)
	tw.Close()
	gz.Close()
	os.WriteFile(archivePath, buf.Bytes(), 0o644)

	_, _, cleanup, err := Extract(mustReadFile(t, archivePath), false, "")
	defer cleanup()
	if err != ErrNoDatabase {
		t.Fatalf("expected ErrNoDatabase, got %v", err)
	}
}

func TestIsLegacyArchiveName(t *testing.T) {
	cases := map[string]bool{
		"alderpointdns-backup-20260101-000000+0000.tar.gz":     true,
		"alderpointdns-backup-20260101-000000+0000.tar.gz.enc": true,
		"apdns-native-backup-foo.tar":                          false,
		"random.tar.gz":                                        false,
		"alderpointdns-backup-x.zip":                           false,
	}
	for name, want := range cases {
		if got := IsLegacyArchiveName(name); got != want {
			t.Errorf("IsLegacyArchiveName(%q) = %v, want %v", name, got, want)
		}
	}
}
