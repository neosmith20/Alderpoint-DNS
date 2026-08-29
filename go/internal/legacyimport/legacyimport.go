// Package legacyimport extracts a real V1.1.1 owner-facing backup
// archive (app/backup.py's create_backup output: a tar.gz, optionally
// openssl-encrypted, of the live appliance -- see that file's own doc
// comment) far enough to hand its embedded live SQLite database off to
// the existing, audited internal/pymigrate.Importer -- the exact same
// bounded, disclosed table set already used for the one-time cutover
// import, reused here unchanged so a legacy archive uploaded after
// cutover gets exactly the same audited treatment a live migration
// would have. This package does not itself import any data -- it only
// gets a trustworthy path to a real SQLite file for pymigrate to read.
//
// Format, read directly from app/backup.py (V1.1.1, ~2,780 lines) and
// verified empirically (openssl round-trip in this session, not
// assumed): a tar archive (gzip-compressed), optionally wrapped in
// classic OpenSSL "enc" format (`openssl enc -aes-256-cbc -pbkdf2 -iter
// 200000 -salt`, filename suffix ".enc"). Inside the tar: `manifest.json`
// (backup_format_version, database_schema_version, sha256_checksums --
// see Manifest) and, when the "sqlite_data" component was included (the
// default), a full online-backup copy of the live database at
// `var/lib/alderpointdns/alderpointdns.db`. Other archive members
// (BIND/dnsdist config, certs, systemd units) are deliberately never
// read here -- Go owns its own DNS Runtime compilation and TLS/DNSCrypt
// identity, and none of that legacy material is trustworthy input for a
// different appliance's own runtime state.
package legacyimport

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// dbArchiveRelPath matches Python's own DB_ARCHIVE_RELPATH
// (Path("/var/lib/alderpointdns/alderpointdns.db").relative_to("/")).
const dbArchiveRelPath = "var/lib/alderpointdns/alderpointdns.db"

const (
	manifestName = "manifest.json"
	// Same disclosed caps as internal/backup's own archive-bomb
	// defenses -- a legacy archive is no more trusted than a native one.
	maxCompressedBytes = 500_000_000
	maxExpandedBytes   = 2_000_000_000
	maxManifestBytes   = 1_000_000
)

var (
	ErrInvalidArchive     = errors.New("invalid or unrecognized legacy backup archive")
	ErrPasswordRequired   = errors.New("this backup is password-encrypted; a password is required")
	ErrWrongPassword      = errors.New("incorrect password (or corrupt archive)")
	ErrNoDatabase         = errors.New("this backup does not include the appliance database (the \"Database\" component was not selected when it was created)")
	ErrChecksumMismatch   = errors.New("the extracted database does not match the backup's own checksum -- the archive may be corrupt or tampered with")
	ErrUnsupportedVersion = errors.New("unrecognized backup_format_version")
)

// Manifest is the subset of V1.1.1's real manifest.json this package
// actually reads. Extra fields in the real file are ignored.
type Manifest struct {
	BackupFormatVersion     int               `json:"backup_format_version"`
	AlderpointdnsAppVersion string            `json:"alderpointdns_app_version"`
	DatabaseSchemaVersion   string            `json:"database_schema_version"`
	CreatedAt               string            `json:"created_at"`
	SourceNodeID            string            `json:"source_node_id"`
	IncludedComponents      []string          `json:"included_components"`
	SHA256Checksums         map[string]string `json:"sha256_checksums"`
	Purpose                 string            `json:"purpose"`
}

// IsLegacyArchiveName reports whether name matches V1.1.1's own naming
// convention closely enough to be worth attempting (alderpointdns-
// backup-*.tar.gz[.enc]) -- a cheap up-front check so an operator gets
// an immediate, specific rejection for an unrelated file rather than a
// confusing extraction error.
func IsLegacyArchiveName(name string) bool {
	name = filepath.Base(name)
	return strings.HasPrefix(name, "alderpointdns-backup-") &&
		(strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tar.gz.enc"))
}

// Extract validates and unpacks archiveData (the full uploaded file, in
// memory -- callers are expected to have already enforced their own
// upload-size limit before calling this), returning a path to a real,
// checksum-verified copy of the embedded SQLite database plus the
// archive's manifest. The returned cleanup func removes every temp file
// this call created; callers must call it exactly once when done
// (typically via defer), on every return path including error.
//
// password is required iff the archive's filename ends ".enc"; pass ""
// for an unencrypted archive.
func Extract(archiveData []byte, encrypted bool, password string) (dbPath string, manifest Manifest, cleanup func(), err error) {
	cleanup = func() {}
	if len(archiveData) > maxCompressedBytes {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: exceeds %d bytes", ErrInvalidArchive, maxCompressedBytes)
	}

	plainTarGz := archiveData
	if encrypted {
		if password == "" {
			return "", Manifest{}, cleanup, ErrPasswordRequired
		}
		plainTarGz, err = opensslDecrypt(archiveData, password)
		if err != nil {
			return "", Manifest{}, cleanup, err
		}
	}

	gz, err := gzip.NewReader(bytes.NewReader(plainTarGz))
	if err != nil {
		if encrypted {
			// A genuinely wrong password decrypts to noise, which is
			// never valid gzip -- that's the honest, common failure
			// mode here, not a generic "corrupt archive".
			return "", Manifest{}, cleanup, ErrWrongPassword
		}
		return "", Manifest{}, cleanup, fmt.Errorf("%w: not a gzip archive: %v", ErrInvalidArchive, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var manifestBytes, dbBytes []byte
	expanded := int64(0)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", Manifest{}, cleanup, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		expanded += hdr.Size
		if expanded > maxExpandedBytes {
			return "", Manifest{}, cleanup, fmt.Errorf("%w: expands beyond %d bytes", ErrInvalidArchive, maxExpandedBytes)
		}
		switch name {
		case manifestName:
			if hdr.Size > maxManifestBytes {
				return "", Manifest{}, cleanup, fmt.Errorf("%w: manifest implausibly large", ErrInvalidArchive)
			}
			data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(data)) != hdr.Size {
				return "", Manifest{}, cleanup, fmt.Errorf("%w: manifest read failed", ErrInvalidArchive)
			}
			manifestBytes = data
		case dbArchiveRelPath:
			if hdr.Size > maxExpandedBytes {
				return "", Manifest{}, cleanup, fmt.Errorf("%w: database entry implausibly large", ErrInvalidArchive)
			}
			data, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(data)) != hdr.Size {
				return "", Manifest{}, cleanup, fmt.Errorf("%w: database read failed", ErrInvalidArchive)
			}
			dbBytes = data
		}
	}

	if manifestBytes == nil {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: missing manifest.json -- this may not be a real appliance backup", ErrInvalidArchive)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: manifest.json is not valid JSON: %v", ErrInvalidArchive, err)
	}
	if manifest.BackupFormatVersion != 1 {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: %d", ErrUnsupportedVersion, manifest.BackupFormatVersion)
	}
	if dbBytes == nil {
		return "", Manifest{}, cleanup, ErrNoDatabase
	}
	if want, ok := manifest.SHA256Checksums[dbArchiveRelPath]; ok && want != "" {
		got := sha256.Sum256(dbBytes)
		if hex.EncodeToString(got[:]) != want {
			return "", Manifest{}, cleanup, ErrChecksumMismatch
		}
	}

	tmpDir, err := os.MkdirTemp("", "apdns-legacy-import-")
	if err != nil {
		return "", Manifest{}, cleanup, fmt.Errorf("staging extracted database: %w", err)
	}
	cleanup = func() { os.RemoveAll(tmpDir) }
	dbPath = filepath.Join(tmpDir, "legacy.db")
	if err := os.WriteFile(dbPath, dbBytes, 0o600); err != nil {
		cleanup()
		return "", Manifest{}, func() {}, fmt.Errorf("staging extracted database: %w", err)
	}
	return dbPath, manifest, cleanup, nil
}

// opensslDecrypt reverses `openssl enc -aes-256-cbc -pbkdf2 -iter 200000
// -salt -pass stdin` (app/backup.py's OPENSSL_ENC_ARGS) in pure Go -- no
// shelling out to openssl. Verified empirically against a real openssl
// round-trip during development, not assumed from documentation:
// classic "Salted__" + 8-byte-salt header, PBKDF2-HMAC-SHA256 (openssl's
// own default digest for -pbkdf2 since 1.1.1) deriving a 48-byte
// key+IV, AES-256-CBC, PKCS#7 padding.
func opensslDecrypt(data []byte, password string) ([]byte, error) {
	const saltedMagic = "Salted__"
	if len(data) < 16 || string(data[:8]) != saltedMagic {
		return nil, fmt.Errorf("%w: missing OpenSSL salt header", ErrInvalidArchive)
	}
	salt := data[8:16]
	ciphertext := data[16:]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrWrongPassword
	}
	keyIV := pbkdf2.Key([]byte(password), salt, 200_000, 48, sha256.New)
	key, iv := keyIV[:32], keyIV[32:48]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	padLen := int(plain[len(plain)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(plain) {
		return nil, ErrWrongPassword
	}
	for _, b := range plain[len(plain)-padLen:] {
		if int(b) != padLen {
			return nil, ErrWrongPassword
		}
	}
	return plain[:len(plain)-padLen], nil
}
