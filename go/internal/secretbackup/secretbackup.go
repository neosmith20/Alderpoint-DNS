// Package secretbackup is the real Go-native replacement for V1.1.1's
// disclosed-as-missing "Secret Backups" gap -- a real, tractable feature
// now that internal/secretstore/apdns-hostagent's AES-256-GCM secrets
// subsystem exists (it didn't when that gap was first disclosed). Field-
// matched against app/v2/secret_backup.py + its webapp.py routes (read
// directly), adapted to this Go-native architecture's stricter
// boundary: Python's SecretStore.export_all() holds every secret's
// plaintext in the WEB process's own memory, however briefly, before
// encrypting it for the backup file. This package never does -- every
// secret is decrypted, bulk-re-encrypted with a dedicated backup key,
// and (on restore) re-sealed under the live master key, ALL inside
// apdns-hostagent (internal/hostagentd/ops_secrets.go's
// OpSecretsBackupCreate/OpSecretsBackupRestore). This process only ever
// sees the outer backup ciphertext and sealed (never plaintext)
// ciphertext/nonce/key_version tuples -- a real secret's plaintext value
// crosses this process's memory at no point, stricter than the
// reference implementation.
package secretbackup

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

var ErrUnavailable = errors.New("secrets subsystem unavailable (host-control agent not configured or not reachable)")
var ErrNotFound = errors.New("backup not found")

const backupKeyKind, backupKeyOwnerRef = "internal_backup_key", "secrets_backup"

type Service struct {
	DB        *sql.DB
	HostAgent *hostagent.Client
	Dir       string
}

type BackupInfo struct {
	Name        string `json:"name"`
	SizeBytes   int64  `json:"size_bytes"`
	CreatedAt   string `json:"created_at"`
	SecretCount int    `json:"secret_count,omitempty"`
}

type Job struct {
	ID          int64  `json:"id"`
	Kind        string `json:"kind"`
	StartedAt   string `json:"started_at"`
	FinishedAt  string `json:"finished_at,omitempty"`
	Status      string `json:"status"`
	Filename    string `json:"filename,omitempty"`
	SecretCount int    `json:"secret_count"`
	Detail      string `json:"detail,omitempty"`
}

func (s *Service) ensureDir() error {
	return os.MkdirAll(s.Dir, 0o750)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// List real stored backup files, newest first, plus recent job history
// -- matches Python's own list_secret_backups() shape.
func (s *Service) List(ctx context.Context) ([]BackupInfo, []Job, error) {
	if err := s.ensureDir(); err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, nil, err
	}
	backups := []BackupInfo{}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".enc" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, BackupInfo{Name: e.Name(), SizeBytes: info.Size(), CreatedAt: info.ModTime().UTC().Format(time.RFC3339)})
	}
	sort.Slice(backups, func(i, j int) bool { return backups[i].CreatedAt > backups[j].CreatedAt })

	rows, err := s.DB.QueryContext(ctx, `SELECT id, kind, started_at, finished_at, status, filename, secret_count, detail FROM secret_backup_jobs ORDER BY id DESC LIMIT 20`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	jobs := []Job{}
	for rows.Next() {
		var j Job
		var finished sql.NullString
		if err := rows.Scan(&j.ID, &j.Kind, &j.StartedAt, &finished, &j.Status, &j.Filename, &j.SecretCount, &j.Detail); err != nil {
			return nil, nil, err
		}
		j.FinishedAt = finished.String
		jobs = append(jobs, j)
	}
	return backups, jobs, rows.Err()
}

type sealedSecretRow struct {
	ID, Kind, OwnerRef, CiphertextB64, NonceB64 string
	KeyVersion                                  int
}

func (s *Service) allSealedSecrets(ctx context.Context) ([]sealedSecretRow, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, kind, owner_ref, key_version, nonce, ciphertext FROM secrets WHERE revoked_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []sealedSecretRow{}
	for rows.Next() {
		var r sealedSecretRow
		var nonce, ciphertext []byte
		if err := rows.Scan(&r.ID, &r.Kind, &r.OwnerRef, &r.KeyVersion, &nonce, &ciphertext); err != nil {
			return nil, err
		}
		r.NonceB64 = base64.StdEncoding.EncodeToString(nonce)
		r.CiphertextB64 = base64.StdEncoding.EncodeToString(ciphertext)
		out = append(out, r)
	}
	return out, rows.Err()
}

// existingBackupKeyParams loads the persisted backup key's own sealed
// reference, if one has ever been created -- (nil, nil) the first time.
func (s *Service) existingBackupKeyParams(ctx context.Context) (map[string]any, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT key_version, nonce, ciphertext FROM secrets WHERE kind=? AND owner_ref=? AND revoked_at IS NULL`, backupKeyKind, backupKeyOwnerRef)
	var keyVersion int
	var nonce, ciphertext []byte
	if err := row.Scan(&keyVersion, &nonce, &ciphertext); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return map[string]any{
		"kind": backupKeyKind, "owner_ref": backupKeyOwnerRef,
		"ciphertext_b64": base64.StdEncoding.EncodeToString(ciphertext), "nonce_b64": base64.StdEncoding.EncodeToString(nonce),
		"key_version": keyVersion,
	}, nil
}

// persistBackupKeyIfNew stores a freshly-generated backup key's sealed
// reference (as returned by OpSecretsBackupCreate) into the shared
// `secrets` table, exactly like any other secret this codebase tracks
// -- idempotent: a no-op if this exact ciphertext is already the
// current one for (kind, owner_ref).
func (s *Service) persistBackupKeyIfNew(ctx context.Context, keyOut map[string]any) error {
	ciphertextB64, _ := keyOut["ciphertext_b64"].(string)
	nonceB64, _ := keyOut["nonce_b64"].(string)
	keyVersion, _ := keyOut["key_version"].(float64)

	existing, err := s.existingBackupKeyParams(ctx)
	if err != nil {
		return err
	}
	if existing != nil && existing["ciphertext_b64"] == ciphertextB64 {
		return nil // already persisted
	}
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return fmt.Errorf("decoding backup key ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return fmt.Errorf("decoding backup key nonce: %w", err)
	}
	id, err := newID()
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err = s.DB.ExecContext(ctx,
		`INSERT INTO secrets (id, kind, owner_ref, key_version, nonce, ciphertext, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`,
		id, backupKeyKind, backupKeyOwnerRef, int(keyVersion), nonce, ciphertext, now, now)
	return err
}

// Create builds a real Secret Backup: every currently-stored (non-
// revoked) secret, exported+re-encrypted entirely inside apdns-hostagent
// (see this package's own doc comment), written atomically to a real
// file.
func (s *Service) Create(ctx context.Context) (BackupInfo, error) {
	if s.HostAgent == nil {
		return BackupInfo{}, ErrUnavailable
	}
	if err := s.ensureDir(); err != nil {
		return BackupInfo{}, err
	}
	startedAt := time.Now().UTC().Format(time.RFC3339)
	jobID, err := s.startJob(ctx, "create", "")
	if err != nil {
		return BackupInfo{}, err
	}

	secrets, err := s.allSealedSecrets(ctx)
	if err != nil {
		s.finishJob(ctx, jobID, "failed", "", 0, err.Error())
		return BackupInfo{}, err
	}
	existingKey, err := s.existingBackupKeyParams(ctx)
	if err != nil {
		s.finishJob(ctx, jobID, "failed", "", 0, err.Error())
		return BackupInfo{}, err
	}

	params := map[string]any{"secrets": secretsToParams(secrets)}
	if existingKey != nil {
		params["backup_key"] = existingKey
	}
	var out struct {
		BackupB64   string         `json:"backup_b64"`
		SecretCount int            `json:"secret_count"`
		CreatedAt   string         `json:"created_at"`
		BackupKey   map[string]any `json:"backup_key"`
	}
	if err := s.HostAgent.Call(ctx, hostagent.OpSecretsBackupCreate, params, &out); err != nil {
		s.finishJob(ctx, jobID, "failed", "", 0, err.Error())
		return BackupInfo{}, fmt.Errorf("creating secret backup: %w", err)
	}
	if err := s.persistBackupKeyIfNew(ctx, out.BackupKey); err != nil {
		s.finishJob(ctx, jobID, "failed", "", 0, err.Error())
		return BackupInfo{}, fmt.Errorf("persisting backup key: %w", err)
	}

	filename := fmt.Sprintf("secrets-%d.enc", time.Now().Unix())
	path := filepath.Join(s.Dir, filename)
	backupBytes, err := base64.StdEncoding.DecodeString(out.BackupB64)
	if err != nil {
		s.finishJob(ctx, jobID, "failed", "", 0, "invalid backup encoding from hostagent")
		return BackupInfo{}, fmt.Errorf("decoding backup: %w", err)
	}
	if err := atomicWriteFile(path, backupBytes); err != nil {
		s.finishJob(ctx, jobID, "failed", "", 0, err.Error())
		return BackupInfo{}, err
	}

	s.finishJob(ctx, jobID, "succeeded", filename, out.SecretCount, "")
	return BackupInfo{Name: filename, SizeBytes: int64(len(backupBytes)), CreatedAt: startedAt, SecretCount: out.SecretCount}, nil
}

// Restore decrypts a real stored backup and re-seals every recovered
// secret under the CURRENT master key, writing the new sealed tuples
// into the `secrets` table -- overwrite=false skips (does not error on)
// any (kind, owner_ref) that already has a real non-revoked secret,
// matching Python's own explicit overwrite flag semantics.
func (s *Service) Restore(ctx context.Context, filename string, overwrite bool) (int, error) {
	if s.HostAgent == nil {
		return 0, ErrUnavailable
	}
	clean := filepath.Base(filename)
	if clean != filename || clean == "" {
		return 0, fmt.Errorf("invalid backup filename")
	}
	path := filepath.Join(s.Dir, clean)
	backupBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	backupKey, err := s.existingBackupKeyParams(ctx)
	if err != nil {
		return 0, err
	}
	if backupKey == nil {
		return 0, fmt.Errorf("no backup key is recorded on this appliance -- this backup cannot have been created here")
	}

	jobID, err := s.startJob(ctx, "restore", clean)
	if err != nil {
		return 0, err
	}

	var out struct {
		Secrets []struct {
			ID            string `json:"id"`
			Kind          string `json:"kind"`
			OwnerRef      string `json:"owner_ref"`
			CiphertextB64 string `json:"ciphertext_b64"`
			NonceB64      string `json:"nonce_b64"`
			KeyVersion    int    `json:"key_version"`
		} `json:"secrets"`
		SecretCount int    `json:"secret_count"`
		CreatedAt   string `json:"created_at"`
	}
	if err := s.HostAgent.Call(ctx, hostagent.OpSecretsBackupRestore, map[string]any{
		"backup_b64": base64.StdEncoding.EncodeToString(backupBytes), "backup_key": backupKey,
	}, &out); err != nil {
		s.finishJob(ctx, jobID, "failed", clean, 0, err.Error())
		return 0, fmt.Errorf("restoring secret backup: %w", err)
	}

	restoredCount := 0
	for _, rec := range out.Secrets {
		var existingCount int
		s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM secrets WHERE kind=? AND owner_ref=? AND revoked_at IS NULL`, rec.Kind, rec.OwnerRef).Scan(&existingCount)
		if existingCount > 0 && !overwrite {
			continue // matches Python's own overwrite=false: skip, don't error
		}
		if err := s.writeResealedSecret(ctx, rec.Kind, rec.OwnerRef, rec.CiphertextB64, rec.NonceB64, rec.KeyVersion); err != nil {
			s.finishJob(ctx, jobID, "failed", clean, restoredCount, err.Error())
			return restoredCount, err
		}
		restoredCount++
	}
	s.finishJob(ctx, jobID, "succeeded", clean, restoredCount, "")
	return restoredCount, nil
}

// Validate decrypts a real stored backup (proving the backup key still
// works and the ciphertext isn't corrupted/tampered) without writing
// anything -- matches Python's own /validate route, a safe dry-run
// before a real Restore.
func (s *Service) Validate(ctx context.Context, filename string) (int, error) {
	if s.HostAgent == nil {
		return 0, ErrUnavailable
	}
	clean := filepath.Base(filename)
	if clean != filename || clean == "" {
		return 0, fmt.Errorf("invalid backup filename")
	}
	path := filepath.Join(s.Dir, clean)
	backupBytes, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	backupKey, err := s.existingBackupKeyParams(ctx)
	if err != nil {
		return 0, err
	}
	if backupKey == nil {
		return 0, fmt.Errorf("no backup key is recorded on this appliance -- this backup cannot have been created here")
	}
	var out struct {
		SecretCount int `json:"secret_count"`
	}
	if err := s.HostAgent.Call(ctx, hostagent.OpSecretsBackupRestore, map[string]any{
		"backup_b64": base64.StdEncoding.EncodeToString(backupBytes), "backup_key": backupKey,
	}, &out); err != nil {
		return 0, fmt.Errorf("validating secret backup: %w", err)
	}
	return out.SecretCount, nil
}

func (s *Service) writeResealedSecret(ctx context.Context, kind, ownerRef, ciphertextB64, nonceB64 string, keyVersion int) error {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return fmt.Errorf("decoding resealed ciphertext: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return fmt.Errorf("decoding resealed nonce: %w", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE secrets SET revoked_at=? WHERE kind=? AND owner_ref=? AND revoked_at IS NULL`, now, kind, ownerRef); err != nil {
		return err
	}
	id, err := newID()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO secrets (id, kind, owner_ref, key_version, nonce, ciphertext, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)`,
		id, kind, ownerRef, keyVersion, nonce, ciphertext, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Service) Delete(filename string) error {
	clean := filepath.Base(filename)
	if clean != filename || clean == "" {
		return fmt.Errorf("invalid backup filename")
	}
	err := os.Remove(filepath.Join(s.Dir, clean))
	if os.IsNotExist(err) {
		return ErrNotFound
	}
	return err
}

func (s *Service) startJob(ctx context.Context, kind, filename string) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `INSERT INTO secret_backup_jobs (kind, started_at, status, filename) VALUES (?, ?, 'running', ?)`,
		kind, time.Now().UTC().Format(time.RFC3339), filename)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Service) finishJob(ctx context.Context, jobID int64, status, filename string, secretCount int, detail string) {
	s.DB.ExecContext(ctx, `UPDATE secret_backup_jobs SET finished_at=?, status=?, filename=?, secret_count=?, detail=? WHERE id=?`,
		time.Now().UTC().Format(time.RFC3339), status, filename, secretCount, detail, jobID)
}

func secretsToParams(secrets []sealedSecretRow) []map[string]any {
	out := make([]map[string]any, len(secrets))
	for i, r := range secrets {
		out[i] = map[string]any{
			"id": r.ID, "kind": r.Kind, "owner_ref": r.OwnerRef,
			"ciphertext_b64": r.CiphertextB64, "nonce_b64": r.NonceB64, "key_version": r.KeyVersion,
		}
	}
	return out
}

func atomicWriteFile(path string, data []byte) error {
	tmp := path + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
