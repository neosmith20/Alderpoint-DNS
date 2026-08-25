// Package auth implements first-run setup, Argon2id password hashing,
// cookie sessions, CSRF, and rate-limited login -- mirroring
// app/v2/webapp.py's real session/CSRF scheme (SESSION_COOKIE_NAME,
// SameSite=Strict, X-CSRF-Token header checked with a constant-time
// compare) and app/v2/auth_hash.py's Argon2id hashing so the two
// implementations are behaviorally equivalent, not just similarly named.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

// forceReturnMemoryToOS asks the Go runtime to hand the ~19 MiB Argon2id
// working buffer's pages back to the OS promptly instead of waiting for
// the background scavenger (which defaults to reclaiming idle heap over
// several minutes). Rate-limited to at most once per 2 seconds -- a login
// storm (or the rate limiter above already bounding failed attempts)
// must never turn this into its own CPU cost under load.
var lastFreeOSMemory struct {
	sync.Mutex
	at time.Time
}

func forceReturnMemoryToOS() {
	lastFreeOSMemory.Lock()
	defer lastFreeOSMemory.Unlock()
	if time.Since(lastFreeOSMemory.at) < 2*time.Second {
		return
	}
	lastFreeOSMemory.at = time.Now()
	go debug.FreeOSMemory() // off the request path; login/setup don't wait on this
}

// Argon2id parameters: OWASP's current baseline recommendation
// (m=19MiB, t=2, p=1) -- NOT the earlier 64 MiB this package shipped with
// during Milestone 1 development, which was found (real measurement, see
// the migration report) to leave Go's allocator holding ~130-150 MB of
// scavenged-but-unreturned heap after just one setup+login, blowing the
// "idle RSS < 25 MB" performance gate for many minutes afterward even
// though nothing was actually leaked. 19 MiB is still comfortably above
// the >=15 MiB OWASP considers minimally acceptable, and combined with
// forceReturnMemoryToOS() below (called once per hash op, off the hot
// path) keeps steady-state RSS in budget without weakening the hash.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB = 19 MiB
	argonThreads = 1
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword returns a PHC-formatted Argon2id hash string:
// $argon2id$v=19$m=19456,t=2,p=1$<salt-b64>$<hash-b64>
func HashPassword(password string) (string, error) {
	defer forceReturnMemoryToOS()
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))
	return encoded, nil
}

// VerifyPassword checks password against an encoded PHC hash. A
// malformed/foreign hash fails closed (false, nil) rather than panicking
// or erroring, so callers never need special-case handling around a
// corrupt row -- same "fail closed" contract as auth_hash.py's
// verify_password.
func VerifyPassword(encodedHash, password string) bool {
	defer forceReturnMemoryToOS()
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var mem uint32
	var t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, mem, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}
