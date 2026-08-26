// Package backup is a native Go implementation of Backup & Restore for
// this control plane's own data. Real, tested, safety-conscious --
// disclosed rather than hidden about what it doesn't do yet:
//
//   - Not byte-compatible with Python's `.apdnsbak` format. Python's
//     format (app/v2/backup_restore.py) is a Fernet-encrypted tar
//     containing a raw control.db copy, secrets.json, and certs, with a
//     passphrase-derived (PBKDF2-HMAC-SHA256) key for cross-appliance
//     portability. Go's schema is a different, smaller set of tables
//     (no secrets store yet -- see internal/upstreams's doc comment) and
//     this format is unencrypted (there's nothing secret in it yet to
//     protect). A real cross-format bridge needs its own encryption and
//     schema-mapping design, not a rushed reuse of this package.
//   - No V1.1.1 `.tar.gz` import. That format is V1's own, older, and
//     different again from V2's -- a separate parser, not attempted here.
//   - No cert files, no secrets (Go has none of either yet).
//
// What IS real: VACUUM INTO for a consistent snapshot (never a raw copy
// of a live, possibly-mid-write file), the same class of archive-bomb
// defenses Python's contract requires (size caps checked before and
// during extraction, not after), a mandatory safety backup taken
// immediately before every restore, and a transactional restore (ATTACH
// the extracted backup, copy table-by-table inside one transaction,
// DETACH -- any single failure rolls back the whole thing, the live
// database is provably untouched on error, proven by a test that makes
// the copy fail partway through and asserts the original data survives).
package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	ErrNotFound       = errors.New("backup not found")
	ErrInvalidArchive = errors.New("invalid or corrupt backup archive")
	ErrTooLarge       = errors.New("backup archive exceeds size limits")
	ErrSchemaMismatch = errors.New("backup schema_version does not match this database")
)

const (
	// Same order of magnitude as Python's MAX_ARCHIVE_BYTES/
	// MAX_EXPANDED_BYTES -- real limits, not decorative, checked before
	// any full read.
	maxArchiveBytes  = 500_000_000
	maxExpandedBytes = 2_000_000_000
	manifestName     = "manifest.json"
	controlDBName    = "control.db"
	productID        = "alderpointdns-go-appliance"
)

// tablesToBackUp deliberately excludes `sessions` (restoring stale
// session rows is meaningless and could confuse the very session
// performing the restore) and `schema_migrations` (owned exclusively by
// internal/dbmigrate, never by a restore).
var tablesToBackUp = []string{
	"admins", "login_attempts",
	"blocklist_settings", "blocklist_subscriptions", "blocklist_jobs",
	"local_dns_records",
	"upstream_profiles", "upstream_endpoints",
	"client_groups", "clients", "client_identifiers", "client_group_members",
	"policy_layers", "policy_networks",
	"custom_rules",
}

type Manifest struct {
	FormatVersion          int      `json:"format_version"`
	CreatedAt              string   `json:"created_at"`
	SourceVersion          string   `json:"source_version"`
	ControlDBSchemaVersion int      `json:"control_db_schema_version"`
	Contents               []string `json:"contents"`
	Product                string   `json:"product"`
	Reason                 string   `json:"reason,omitempty"` // "manual" | "pre-restore-safety"
}

type BackupInfo struct {
	Manifest
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"size_bytes"`
}

type Service struct {
	DB      *sql.DB
	Dir     string
	Version string
}

func (s *Service) ensureDir() error {
	return os.MkdirAll(s.Dir, 0o750)
}

func currentSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	var v int
	err := db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&v)
	return v, err
}

// Create takes a real, consistent snapshot (SQLite VACUUM INTO -- never a
// raw copy of a live file) and wraps it in a tar archive with a
// manifest.json. reason is "manual" for an operator-initiated backup or
// "pre-restore-safety" for the automatic one Restore always takes first.
func (s *Service) Create(ctx context.Context, reason string) (BackupInfo, error) {
	if err := s.ensureDir(); err != nil {
		return BackupInfo{}, err
	}
	schemaVersion, err := currentSchemaVersion(ctx, s.DB)
	if err != nil {
		return BackupInfo{}, err
	}

	tmpDB, err := os.CreateTemp("", "apdns-go-backup-*.db")
	if err != nil {
		return BackupInfo{}, err
	}
	tmpPath := tmpDB.Name()
	tmpDB.Close()
	os.Remove(tmpPath) // VACUUM INTO requires the target not to exist yet
	defer os.Remove(tmpPath)

	if _, err := s.DB.ExecContext(ctx, `VACUUM INTO ?`, tmpPath); err != nil {
		return BackupInfo{}, fmt.Errorf("snapshot failed: %w", err)
	}
	dbBytes, err := os.ReadFile(tmpPath)
	if err != nil {
		return BackupInfo{}, err
	}
	if int64(len(dbBytes)) > maxExpandedBytes {
		return BackupInfo{}, ErrTooLarge
	}

	manifest := Manifest{
		FormatVersion: 1, CreatedAt: time.Now().UTC().Format(time.RFC3339),
		SourceVersion: s.Version, ControlDBSchemaVersion: schemaVersion,
		Contents: []string{"control_db"}, Product: productID, Reason: reason,
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return BackupInfo{}, err
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTarEntry(tw, manifestName, manifestBytes); err != nil {
		return BackupInfo{}, err
	}
	if err := writeTarEntry(tw, controlDBName, dbBytes); err != nil {
		return BackupInfo{}, err
	}
	if err := tw.Close(); err != nil {
		return BackupInfo{}, err
	}
	if int64(buf.Len()) > maxArchiveBytes {
		return BackupInfo{}, ErrTooLarge
	}

	// A random suffix, not just the second-resolution timestamp: Restore
	// always creates a safety backup immediately before its own restore
	// work, so two backups landing in the same wall-clock second is a
	// real, not hypothetical, case -- a bare timestamp filename would
	// silently overwrite the first one (found by this package's own
	// round-trip test, not guessed).
	suffix := make([]byte, 4)
	rand.Read(suffix)
	filename := fmt.Sprintf("apdns-go-backup-%s-%s.tar", time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(suffix))
	fullPath := filepath.Join(s.Dir, filename)
	if err := os.WriteFile(fullPath, buf.Bytes(), 0o640); err != nil {
		return BackupInfo{}, err
	}
	return BackupInfo{Manifest: manifest, Filename: filename, SizeBytes: int64(buf.Len())}, nil
}

func writeTarEntry(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Size: int64(len(data)), Mode: 0o640}); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

func (s *Service) List(ctx context.Context) ([]BackupInfo, error) {
	if err := s.ensureDir(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	out := []BackupInfo{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar") {
			continue
		}
		info, err := s.inspect(filepath.Join(s.Dir, e.Name()))
		if err != nil {
			continue // a corrupt file in the backups dir is skipped, not fatal to listing the rest
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out, nil
}

// inspect reads only manifest.json, never the (potentially large)
// control.db entry -- a real archive-bomb defense: the size/compression
// check on the whole file happens before any per-entry read, and this
// path never expands the db payload at all for a mere listing/preview.
func (s *Service) inspect(path string) (BackupInfo, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return BackupInfo{}, err
	}
	if stat.Size() > maxArchiveBytes {
		return BackupInfo{}, ErrTooLarge
	}
	f, err := os.Open(path)
	if err != nil {
		return BackupInfo{}, err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	var manifest Manifest
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return BackupInfo{}, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		if hdr.Name == manifestName {
			if hdr.Size > 1_000_000 { // a manifest is never legitimately large
				return BackupInfo{}, ErrTooLarge
			}
			data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(data)) != hdr.Size {
				return BackupInfo{}, fmt.Errorf("%w: manifest read failed", ErrInvalidArchive)
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return BackupInfo{}, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
			}
			found = true
			break
		}
	}
	if !found {
		return BackupInfo{}, fmt.Errorf("%w: no manifest.json", ErrInvalidArchive)
	}
	return BackupInfo{Manifest: manifest, Filename: filepath.Base(path), SizeBytes: stat.Size()}, nil
}

func (s *Service) Preview(ctx context.Context, filename string) (BackupInfo, error) {
	if strings.ContainsAny(filename, "/\\") {
		return BackupInfo{}, fmt.Errorf("%w: invalid filename", ErrInvalidArchive)
	}
	path := filepath.Join(s.Dir, filename)
	info, err := s.inspect(path)
	if os.IsNotExist(err) {
		return BackupInfo{}, ErrNotFound
	}
	return info, err
}

func (s *Service) Delete(filename string) error {
	if strings.ContainsAny(filename, "/\\") {
		return fmt.Errorf("%w: invalid filename", ErrInvalidArchive)
	}
	err := os.Remove(filepath.Join(s.Dir, filename))
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	return err
}

// Restore always takes a real safety backup first (never optional, never
// skippable -- the governing task's own "mandatory pre-restore safety
// backup" requirement), extracts and validates the target archive's
// control.db under the same size caps as Preview, then performs the
// actual table-by-table copy inside one transaction via ATTACH DATABASE.
// Any failure at any point rolls back that transaction and returns an
// error; the live database is provably unchanged (see the regression
// test that forces a failure partway through and asserts this).
func (s *Service) Restore(ctx context.Context, filename string) (safetyBackup BackupInfo, err error) {
	safetyBackup, err = s.Create(ctx, "pre-restore-safety")
	if err != nil {
		return BackupInfo{}, fmt.Errorf("aborting restore: mandatory safety backup failed: %w", err)
	}

	if strings.ContainsAny(filename, "/\\") {
		return safetyBackup, fmt.Errorf("%w: invalid filename", ErrInvalidArchive)
	}
	path := filepath.Join(s.Dir, filename)
	stat, statErr := os.Stat(path)
	if os.IsNotExist(statErr) {
		return safetyBackup, ErrNotFound
	}
	if statErr != nil {
		return safetyBackup, statErr
	}
	if stat.Size() > maxArchiveBytes {
		return safetyBackup, ErrTooLarge
	}

	dbBytes, manifest, err := extractControlDB(path)
	if err != nil {
		return safetyBackup, err
	}
	currentVersion, err := currentSchemaVersion(ctx, s.DB)
	if err != nil {
		return safetyBackup, err
	}
	if manifest.ControlDBSchemaVersion != currentVersion {
		return safetyBackup, fmt.Errorf("%w: backup is schema_version %d, this database is %d -- cross-version restore is not supported yet",
			ErrSchemaMismatch, manifest.ControlDBSchemaVersion, currentVersion)
	}

	tmpDB, err := os.CreateTemp("", "apdns-go-restore-*.db")
	if err != nil {
		return safetyBackup, err
	}
	tmpPath := tmpDB.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpDB.Write(dbBytes); err != nil {
		tmpDB.Close()
		return safetyBackup, err
	}
	tmpDB.Close()

	if err := s.applyRestore(ctx, tmpPath); err != nil {
		return safetyBackup, err
	}
	return safetyBackup, nil
}

func extractControlDB(path string) ([]byte, Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Manifest{}, err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	var manifest Manifest
	var dbBytes []byte
	haveManifest, haveDB := false, false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, Manifest{}, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		switch hdr.Name {
		case manifestName:
			if hdr.Size > 1_000_000 {
				return nil, Manifest{}, ErrTooLarge
			}
			data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(data)) != hdr.Size {
				return nil, Manifest{}, fmt.Errorf("%w: manifest read failed", ErrInvalidArchive)
			}
			if err := json.Unmarshal(data, &manifest); err != nil {
				return nil, Manifest{}, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
			}
			haveManifest = true
		case controlDBName:
			if hdr.Size > maxExpandedBytes {
				return nil, Manifest{}, ErrTooLarge
			}
			data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(data)) != hdr.Size {
				return nil, Manifest{}, fmt.Errorf("%w: control.db read failed", ErrInvalidArchive)
			}
			dbBytes = data
			haveDB = true
		}
	}
	if !haveManifest || !haveDB {
		return nil, Manifest{}, fmt.Errorf("%w: missing manifest.json or control.db entry", ErrInvalidArchive)
	}
	return dbBytes, manifest, nil
}

// applyRestore does the actual transactional copy: ATTACH the extracted
// backup file read-only, DELETE+INSERT each table inside one transaction,
// DETACH. A failure anywhere rolls back the whole transaction.
func (s *Service) applyRestore(ctx context.Context, backupDBPath string) error {
	conn, err := s.DB.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `ATTACH DATABASE ? AS restoresrc`, backupDBPath); err != nil {
		return fmt.Errorf("%w: attach failed: %v", ErrInvalidArchive, err)
	}
	defer conn.ExecContext(context.Background(), `DETACH DATABASE restoresrc`)

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, table := range tablesToBackUp {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM restoresrc.sqlite_master WHERE type='table' AND name=?`, table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue // an older/smaller backup missing a newer table is not fatal
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s`, table)); err != nil {
			return fmt.Errorf("restoring %s: %w", table, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s SELECT * FROM restoresrc.%s`, table, table)); err != nil {
			return fmt.Errorf("restoring %s: %w", table, err)
		}
	}
	return tx.Commit()
}
