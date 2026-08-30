// Optional passphrase protection for this package's own native backup
// archive -- added 2026-08-29 to close a real, previously-disclosed
// owner-facing gap versus V1.1.1's own optional password-protected
// `.tar.gz.enc` (see this package's own top-of-file doc comment): the
// native archive always includes `admin_accounts` (argon2id password
// hashes) and every managed client/network's identifying data, and
// shipped with no way to protect a downloaded copy at rest.
//
// Format: a whole-archive envelope (the same design choice V1.1.1 made
// -- its own preview_restore(path, password) needs the password before
// it can show ANYTHING about a backup, not just before restoring one),
// not per-entry encryption inside the tar:
//
//	[8 bytes magic "APDNSBK1"] [1 byte version] [16 bytes salt]
//	[12 bytes AES-GCM nonce] [ciphertext, GCM tag included]
//
// Key derivation: Argon2id, the exact same tuned parameters
// internal/auth uses for password hashing (m=19MiB, t=2, p=1) --
// deliberately reused rather than picking a stronger-looking, untested
// number: this codebase already measured that a larger Argon2id working
// set (64 MiB) leaves Go's allocator holding scavenged-but-unreturned
// heap for minutes afterward (see internal/auth/password.go's own doc
// comment), and this session's own OOM-incident investigation is
// exactly why a new code path must not gamble with that again. The
// threat model here (offline brute force against a stolen backup file)
// is the same one password hashing already defends against, so the same
// proven-safe parameters apply.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	encMagic     = "APDNSBK1" // 8 bytes -- identifies this package's own encrypted-backup envelope
	encVersion   = 1
	encSaltLen   = 16
	encNonceLen  = 12 // AES-GCM standard nonce size
	encKeyLen    = 32 // AES-256
	encHeaderLen = len(encMagic) + 1 + encSaltLen + encNonceLen

	// Same tuned Argon2id parameters as internal/auth/password.go --
	// see this file's own doc comment for why these specific numbers,
	// not stronger ones, are the deliberate, safety-conscious choice.
	encArgonTime    = 2
	encArgonMemory  = 19 * 1024 // KiB = 19 MiB
	encArgonThreads = 1
)

// ErrPassphraseRequired is returned by Preview/Restore when the target
// archive is a real encrypted envelope and no passphrase was given --
// distinct from ErrWrongPassphrase (a passphrase WAS given but didn't
// decrypt it) so the frontend can tell "ask for a passphrase" apart from
// "that passphrase was wrong" and word the prompt accordingly.
var ErrPassphraseRequired = errors.New("this backup is passphrase-protected")

// ErrWrongPassphrase is returned when a passphrase was given but could
// not decrypt the archive -- GCM's own authentication tag check failing,
// which also means "this file was corrupted/tampered with" a plausible
// alternate cause reported identically (never distinguishable to an
// external caller, exactly like a login's own wrong-password contract).
var ErrWrongPassphrase = errors.New("wrong passphrase, or the backup file is corrupt")

// isEncryptedArchive reports whether raw begins with this package's own
// encrypted-envelope magic -- a cheap, no-decryption-attempted check,
// safe to run on every listed file regardless of whether a passphrase
// is available.
func isEncryptedArchive(raw []byte) bool {
	return len(raw) >= len(encMagic) && string(raw[:len(encMagic)]) == encMagic
}

// deriveKey rate-limits how often it returns Argon2id's working memory
// to the OS -- see forceReturnMemoryToOS's own doc comment in
// internal/auth/password.go for the identical reasoning (this is a
// deliberate, small duplication rather than an import of internal/auth,
// since backup and auth are otherwise unrelated domains and it's a
// handful of lines).
var lastFreeOSMemory struct {
	sync.Mutex
	at time.Time
}

func deriveKey(passphrase string, salt []byte) []byte {
	defer func() {
		lastFreeOSMemory.Lock()
		defer lastFreeOSMemory.Unlock()
		if time.Since(lastFreeOSMemory.at) < 2*time.Second {
			return
		}
		lastFreeOSMemory.at = time.Now()
		go debug.FreeOSMemory()
	}()
	return argon2.IDKey([]byte(passphrase), salt, encArgonTime, encArgonMemory, encArgonThreads, encKeyLen)
}

// encryptArchive wraps plaintext (the real tar bytes Create already
// builds) in this package's own envelope. The passphrase itself is
// never retained anywhere beyond this call's own stack -- no logging,
// no persistence, by construction (it's a local variable that goes out
// of scope the moment this returns).
func encryptArchive(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, encSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, encNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, encHeaderLen+len(ciphertext))
	out = append(out, []byte(encMagic)...)
	out = append(out, byte(encVersion))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// decryptArchive reverses encryptArchive. Returns ErrWrongPassphrase
// (never the underlying crypto error, which would leak implementation
// detail with no benefit to a legitimate caller) on any failure to
// parse the envelope or authenticate the ciphertext.
func decryptArchive(envelope []byte, passphrase string) ([]byte, error) {
	if len(envelope) < encHeaderLen || !isEncryptedArchive(envelope) {
		return nil, ErrWrongPassphrase
	}
	version := envelope[len(encMagic)]
	if version != encVersion {
		return nil, fmt.Errorf("%w: unsupported envelope version %d", ErrInvalidArchive, version)
	}
	off := len(encMagic) + 1
	salt := envelope[off : off+encSaltLen]
	off += encSaltLen
	nonce := envelope[off : off+encNonceLen]
	off += encNonceLen
	ciphertext := envelope[off:]

	key := deriveKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return plaintext, nil
}

// readArchiveBody is the single shared entry point every reader of an
// on-disk backup file (inspect, extractControlDB) goes through: reads
// the raw file, detects the envelope, and returns the real (decrypted,
// if applicable) tar bytes -- so tar-parsing logic downstream never
// needs to know or care whether the file on disk was encrypted.
//
// requirePassphrase distinguishes Preview/Restore's contract (a real
// passphrase is required up front, matching V1.1.1's own
// preview_restore(path, password)'s behavior of needing the password
// before showing anything) from List's own bulk-listing contract (an
// encrypted file with no passphrase degrades to minimal metadata,
// engineered by the caller checking the returned encrypted flag rather
// than this function erroring).
func readArchiveBody(path, passphrase string) (body []byte, encrypted bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if int64(len(raw)) > maxArchiveBytes {
		return nil, false, ErrTooLarge
	}
	if !isEncryptedArchive(raw) {
		return raw, false, nil
	}
	if passphrase == "" {
		return nil, true, ErrPassphraseRequired
	}
	plaintext, err := decryptArchive(raw, passphrase)
	if err != nil {
		return nil, true, err
	}
	return plaintext, true, nil
}
