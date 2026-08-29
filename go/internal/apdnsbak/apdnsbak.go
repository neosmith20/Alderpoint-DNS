// Package apdnsbak extracts a real V2 Python `.apdnsbak` portable
// appliance backup (app/v2/backup_restore.py, read directly) far enough
// to hand its embedded control.db off to the existing, unmodified
// internal/pymigrate.Importer -- the same real, tested schema-mapping
// path already proven for both the live cutover and the V1.1.1
// legacy-backup import (see internal/legacyimport), reused again here
// because the V2 Python control.db this format carries is the exact
// same schema pymigrate already targets.
//
// Format, read directly and verified empirically (a real Fernet
// round-trip against Python's own `cryptography.fernet` during
// development, not assumed from documentation): a Fernet-encrypted
// (AES-128-CBC + HMAC-SHA256, authenticated) tar of control.db +
// secrets.json + certs/* + manifest.json. Only "passphrase mode" is
// importable here -- "local mode" derives its key from a secret that
// only exists inside the ORIGINAL appliance's own secret store, making
// such a backup meaningless to decrypt from any other process, exactly
// as Python's own doc comment describes ("what makes a backup
// restorable on a different appliance"). Only the control.db member is
// consumed; secrets.json (Python's own, differently-encrypted
// SecretStore export) and certs/* are deliberately not imported --
// Go's own secrets store and TLS/DNSCrypt identity are not compatible
// containers for that material, and importing it would need a second,
// separate translation this pass does not attempt (disclosed, not
// hidden).
package apdnsbak

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	fileMagic       = "APDNSBAKv2\n"
	controlDBName   = "control.db"
	manifestName    = "manifest.json"
	productID       = "alderpointdns-v2-appliance"
	pbkdf2MinIter   = 200_000
	pbkdf2MaxIter   = 1_000_000
	saltBytes       = 16
	maxArchiveBytes = 1_000_000_000
	maxExpandedByte = 4_000_000_000
)

var (
	ErrPassphraseRequired = errors.New("this backup requires its restore passphrase")
	ErrNotPortable        = errors.New("this backup was not created in portable (passphrase) mode -- it can only be restored on the exact appliance that created it, and cannot be imported here")
	ErrWrongPassphrase    = errors.New("cannot decrypt backup -- wrong passphrase, or the backup file is corrupted/tampered with")
	ErrInvalidArchive     = errors.New("invalid or unrecognized .apdnsbak archive")
	ErrWrongProduct       = errors.New("this backup is not a compatible Alderpoint DNS appliance backup")
	ErrNoDatabase         = errors.New("this backup does not include the appliance database")
)

// Manifest is the subset of the real manifest.json this package reads.
type Manifest struct {
	FormatVersion         int      `json:"format_version"`
	Product               string   `json:"product"`
	CreatedAt             string   `json:"created_at"`
	SourceVersion         string   `json:"source_version"`
	SourceNodeID          string   `json:"source_node_id"`
	ControlDBSchemaVersion int     `json:"control_db_schema_version"`
	Contents              []string `json:"contents"`
	SecretCount           int      `json:"secret_count"`
	CertFiles             []string `json:"cert_files"`
	KeyMode               string   `json:"key_mode"`
}

// IsApdnsbakName is a cheap up-front filename check -- V2's own
// convention is `<name>-<timestamp>.apdnsbak`, no fixed prefix, so this
// only checks the extension (Python's own importer never trusts the
// filename either, only real content).
func IsApdnsbakName(name string) bool {
	return strings.HasSuffix(strings.ToLower(filepath.Base(name)), ".apdnsbak")
}

// Extract validates, decrypts (Fernet, passphrase mode only), and
// untars archiveData, returning a path to the real extracted control.db
// plus the archive's manifest. cleanup removes every temp file this
// call created; callers must call it exactly once, on every return path.
func Extract(archiveData []byte, passphrase string) (dbPath string, manifest Manifest, cleanup func(), err error) {
	cleanup = func() {}
	if len(archiveData) > maxArchiveBytes {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: exceeds %d bytes", ErrInvalidArchive, maxArchiveBytes)
	}
	if !bytes.HasPrefix(archiveData, []byte(fileMagic)) {
		return "", Manifest{}, cleanup, ErrNotPortable
	}
	rest := archiveData[len(fileMagic):]
	idx := bytes.IndexByte(rest, '\n')
	if idx < 0 {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: missing portable-backup header", ErrInvalidArchive)
	}
	var header struct {
		SaltB64    string `json:"salt_b64"`
		Iterations int    `json:"iterations"`
	}
	if err := json.Unmarshal(rest[:idx], &header); err != nil {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: invalid portable-backup header: %v", ErrInvalidArchive, err)
	}
	salt, err := base64.StdEncoding.DecodeString(header.SaltB64)
	if err != nil || len(salt) != saltBytes {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: invalid portable-backup salt", ErrInvalidArchive)
	}
	if header.Iterations < pbkdf2MinIter || header.Iterations > pbkdf2MaxIter {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: portable-backup KDF iteration count out of bounds", ErrInvalidArchive)
	}
	if passphrase == "" {
		return "", Manifest{}, cleanup, ErrPassphraseRequired
	}

	tokenB64 := rest[idx+1:]
	plain, err := fernetDecrypt(tokenB64, passphrase, salt, header.Iterations)
	if err != nil {
		return "", Manifest{}, cleanup, err
	}

	manifestBytes, dbBytes, err := readTar(plain)
	if err != nil {
		return "", Manifest{}, cleanup, err
	}
	if manifestBytes == nil {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: missing manifest.json", ErrInvalidArchive)
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: manifest.json is not valid JSON: %v", ErrInvalidArchive, err)
	}
	if manifest.Product != productID {
		return "", Manifest{}, cleanup, fmt.Errorf("%w: %q", ErrWrongProduct, manifest.Product)
	}
	if dbBytes == nil {
		return "", Manifest{}, cleanup, ErrNoDatabase
	}

	tmpDir, err := os.MkdirTemp("", "apdns-apdnsbak-import-")
	if err != nil {
		return "", Manifest{}, cleanup, fmt.Errorf("staging extracted database: %w", err)
	}
	cleanup = func() { os.RemoveAll(tmpDir) }
	dbPath = filepath.Join(tmpDir, "control.db")
	if err := os.WriteFile(dbPath, dbBytes, 0o600); err != nil {
		cleanup()
		return "", Manifest{}, func() {}, fmt.Errorf("staging extracted database: %w", err)
	}
	return dbPath, manifest, cleanup, nil
}

func readTar(data []byte) (manifestBytes, dbBytes []byte, err error) {
	tr := tar.NewReader(bytes.NewReader(data))
	expanded := int64(0)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		expanded += hdr.Size
		if expanded > maxExpandedByte {
			return nil, nil, fmt.Errorf("%w: expands beyond %d bytes", ErrInvalidArchive, maxExpandedByte)
		}
		switch name {
		case manifestName:
			b, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(b)) != hdr.Size {
				return nil, nil, fmt.Errorf("%w: manifest read failed", ErrInvalidArchive)
			}
			manifestBytes = b
		case controlDBName:
			b, err := io.ReadAll(io.LimitReader(tr, hdr.Size+1))
			if err != nil || int64(len(b)) != hdr.Size {
				return nil, nil, fmt.Errorf("%w: control.db read failed", ErrInvalidArchive)
			}
			dbBytes = b
		}
	}
	return manifestBytes, dbBytes, nil
}

// fernetDecrypt reverses a real Fernet token (RFC-less but well-specified:
// https://github.com/fernet/spec) -- version byte 0x80, 8-byte
// big-endian timestamp (ignored: neither this package nor Python's own
// caller here passes a ttl, so no expiry is enforced, matching
// app/v2/backup_restore.py's own `fernet.decrypt(ciphertext)` call
// exactly), 16-byte IV, AES-128-CBC ciphertext, 32-byte HMAC-SHA256 over
// everything before it. The 32-byte Fernet key (PBKDF2-HMAC-SHA256 here,
// base64url-encoded per Python's own derive_key_from_passphrase) splits
// into a 16-byte signing key and a 16-byte encryption key. Verified
// empirically against a real token produced by Python's own
// `cryptography.fernet.Fernet` during development.
func fernetDecrypt(tokenB64 []byte, passphrase string, salt []byte, iterations int) ([]byte, error) {
	keyRaw := pbkdf2.Key([]byte(passphrase), salt, iterations, 32, sha256.New)
	fernetKey := make([]byte, base64.URLEncoding.EncodedLen(len(keyRaw)))
	base64.URLEncoding.Encode(fernetKey, keyRaw)
	keyBytes, err := base64.URLEncoding.DecodeString(string(fernetKey))
	if err != nil || len(keyBytes) != 32 {
		return nil, fmt.Errorf("%w: internal key derivation error", ErrInvalidArchive)
	}
	signingKey, encKey := keyBytes[:16], keyBytes[16:]

	token, err := base64.URLEncoding.DecodeString(strings.TrimSpace(string(tokenB64)))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	if len(token) < 1+8+16+32 || token[0] != 0x80 {
		return nil, ErrWrongPassphrase
	}
	iv := token[9:25]
	tag := token[len(token)-32:]
	ciphertext := token[25 : len(token)-32]
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, ErrWrongPassphrase
	}

	mac := hmac.New(sha256.New, signingKey)
	mac.Write(token[:len(token)-32])
	if !hmac.Equal(mac.Sum(nil), tag) {
		return nil, ErrWrongPassphrase
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArchive, err)
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)
	padLen := int(plain[len(plain)-1])
	if padLen < 1 || padLen > aes.BlockSize || padLen > len(plain) {
		return nil, ErrWrongPassphrase
	}
	for _, b := range plain[len(plain)-padLen:] {
		if int(b) != padLen {
			return nil, ErrWrongPassphrase
		}
	}
	return plain[:len(plain)-padLen], nil
}
