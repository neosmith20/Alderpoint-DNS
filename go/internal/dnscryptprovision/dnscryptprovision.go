// Package dnscryptprovision generates real DNSCrypt provider/resolver
// key material by driving the real, installed dnsdist binary's own
// console -- ported from app/v2/dnscrypt_provisioning.py, read directly.
//
// Why this exists instead of hand-rolling the DNSCrypt binary formats in
// Go: DNSCrypt provider keys (Ed25519) and the signed resolver
// certificate dnsdist actually verifies at query time are a real, exact
// binary wire format (RFC-adjacent, not standardized the way X.509 is)
// -- getting a byte offset or the signing scope wrong produces broken
// or insecure crypto that would only be caught, if at all, by a real
// client failing a handshake in production. dnsdist itself is the
// authoritative implementation (it is also the verifier), so this
// package always asks the real installed dnsdist binary to generate the
// material via its own generateDNSCryptProviderKeys/
// generateDNSCryptCertificate console functions, never reimplemented
// here.
//
// A real, live-reproduced dnsdist behavior this package works around:
// invoking these functions via `dnsdist -l ... -e script` (one-shot, no
// console) reliably prints a provider fingerprint but does NOT persist
// the key files to disk -- confirmed live against the real installed
// dnsdist binary this session: `generateDNSCryptProviderKeys` via a
// bare `-e` command prints "Provider fingerprint is: ..." and writes
// nothing. The same call issued as a genuine interactive console
// command (piped via stdin to `dnsdist -C <config> -c`, against an
// already-running scratch dnsdist process with a real controlSocket/
// setKey) reliably writes both files -- confirmed live, repeatedly.
// This package therefore always drives generation through a genuine,
// disposable, throwaway dnsdist instance with a real console -- never
// -e, never a bare one-shot -l listener.
//
// Why a disposable scratch instance, not the live production dnsdist:
// the real compiled runtime (internal/dnscompile) has no controlSocket/
// console at all -- adding a permanent console to the live query-
// serving process is real new attack surface. Provisioning is an
// infrequent, explicit administrative action, not something the hot
// query path needs -- so it gets a fully disposable, loopback-only,
// random-key, random-port dnsdist instance that exists only for the few
// hundred milliseconds this package needs it, torn down immediately
// after, never reachable from anywhere but this process.
package dnscryptprovision

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	ProviderPublicKeyLength  = 32
	ProviderPrivateKeyLength = 64
	ResolverPrivateKeyLength = 32
	// The real DNSCrypt signed-certificate wire format dnsdist emits: 4-byte
	// magic + 2-byte crypto-construction version + 2-byte protocol minor
	// version + 64-byte Ed25519 signature + 32-byte short-term resolver
	// public key + 8-byte client magic + 4-byte serial + 4-byte ts_start +
	// 4-byte ts_end = 124 bytes total -- verified against a real generated
	// cert this session, not assumed from memory.
	DNSCryptCertLength = 124

	consoleTimeout    = 15 * time.Second
	readyPollAttempts = 50
	readyPollInterval = 100 * time.Millisecond
)

type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }
func errf(format string, a ...any) error {
	return &Error{fmt.Sprintf(format, a...)}
}

func luaString(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}

func freeLoopbackPort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func waitUntilConnectable(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for i := 0; i < readyPollAttempts; i++ {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(readyPollInterval)
	}
	return errf("scratch dnsdist console on %s never became connectable", addr)
}

type scratchInstance struct {
	cmd        *exec.Cmd
	configPath string
}

// startScratchDnsdist launches a disposable, loopback-only dnsdist
// instance with a real console (required -- see package doc comment)
// and no real DNS-serving purpose (setLocal is still required --
// omitting it entirely made a real "console-only" scratch instance
// collide with the real system DNS service already using port 53 and
// fail to start, confirmed live -- so it gets its own scratch port with
// nothing behind it).
func startScratchDnsdist(dir, dnsdistBinary string) (*scratchInstance, error) {
	consolePort, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	dnsPort, err := freeLoopbackPort()
	if err != nil {
		return nil, err
	}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, err
	}
	keyB64 := base64.StdEncoding.EncodeToString(keyBytes)

	configPath := filepath.Join(dir, "scratch.conf")
	config := fmt.Sprintf("setLocal(%s)\ncontrolSocket(%s)\nsetKey(%s)\n",
		luaString(fmt.Sprintf("127.0.0.1:%d", dnsPort)),
		luaString(fmt.Sprintf("127.0.0.1:%d", consolePort)),
		luaString(keyB64))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return nil, err
	}

	cmd := exec.Command(dnsdistBinary, "-C", configPath, "--supervised")
	if err := cmd.Start(); err != nil {
		return nil, errf("could not start scratch dnsdist instance: %v", err)
	}
	if err := waitUntilConnectable(consolePort); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return nil, err
	}
	return &scratchInstance{cmd: cmd, configPath: configPath}, nil
}

func stopScratchDnsdist(inst *scratchInstance) {
	if inst == nil || inst.cmd.Process == nil {
		return
	}
	inst.cmd.Process.Kill()
	inst.cmd.Wait()
}

// runConsoleCommand feeds a single command to a real interactive
// console session over stdin (never -e -- see package doc comment for
// why that path is unreliable) and returns combined stdout+stderr for
// error reporting.
func runConsoleCommand(inst *scratchInstance, dnsdistBinary, command string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), consoleTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, dnsdistBinary, "-C", inst.configPath, "-c")
	cmd.Stdin = strings.NewReader(command + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return string(out), errf("dnsdist console session timed out: %v", err)
		}
		if _, ok := err.(*exec.ExitError); !ok {
			return string(out), err
		}
	}
	return string(out), nil
}

// GenerateProviderKeypair generates a real DNSCrypt provider (long-term,
// root-of-trust) Ed25519 keypair via the real dnsdist binary. Returns
// (publicKey, privateKey) as raw bytes -- callers are responsible for
// persisting the private key securely (a real file, 0600, matching the
// same convention internal/tlscert already uses for the management TLS
// key) and for never logging it.
func GenerateProviderKeypair(dnsdistBinary string) (publicKey, privateKey []byte, err error) {
	if dnsdistBinary == "" {
		dnsdistBinary = "dnsdist"
	}
	dir, err := os.MkdirTemp("", "dnscrypt-provision-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	inst, err := startScratchDnsdist(dir, dnsdistBinary)
	if err != nil {
		return nil, nil, err
	}
	defer stopScratchDnsdist(inst)

	pubPath := filepath.Join(dir, "provider.public")
	privPath := filepath.Join(dir, "provider.private")
	command := fmt.Sprintf("generateDNSCryptProviderKeys(%s, %s)", luaString(pubPath), luaString(privPath))
	output, err := runConsoleCommand(inst, dnsdistBinary, command)
	if err != nil {
		return nil, nil, errf("dnsdist console session failed: %v", err)
	}
	pub, errPub := os.ReadFile(pubPath)
	priv, errPriv := os.ReadFile(privPath)
	if errPub != nil || errPriv != nil {
		return nil, nil, errf("dnsdist did not write DNSCrypt provider key files; console output: %q", output)
	}
	if len(pub) != ProviderPublicKeyLength {
		return nil, nil, errf("unexpected provider public key length %d (expected %d)", len(pub), ProviderPublicKeyLength)
	}
	if len(priv) != ProviderPrivateKeyLength {
		return nil, nil, errf("unexpected provider private key length %d (expected %d)", len(priv), ProviderPrivateKeyLength)
	}
	return pub, priv, nil
}

// GenerateResolverCertificate generates a real, signed, short-term
// DNSCrypt resolver certificate (the record clients actually fetch and
// verify before establishing an encrypted session) plus its matching
// X25519 private key, signed by providerPrivateKey. Returns (certBytes,
// resolverPrivateKey) as raw bytes.
func GenerateResolverCertificate(dnsdistBinary string, providerPrivateKey []byte, serial int64, validFrom, validUntil int64) (cert, resolverKey []byte, err error) {
	if dnsdistBinary == "" {
		dnsdistBinary = "dnsdist"
	}
	if len(providerPrivateKey) != ProviderPrivateKeyLength {
		return nil, nil, errf("providerPrivateKey must be %d bytes, got %d", ProviderPrivateKeyLength, len(providerPrivateKey))
	}
	if serial < 1 {
		return nil, nil, errf("serial must be a positive integer, got %d", serial)
	}
	if validFrom >= validUntil {
		return nil, nil, errf("valid_from (%d) must be smaller than valid_until (%d)", validFrom, validUntil)
	}
	dir, err := os.MkdirTemp("", "dnscrypt-provision-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	inst, err := startScratchDnsdist(dir, dnsdistBinary)
	if err != nil {
		return nil, nil, err
	}
	defer stopScratchDnsdist(inst)

	providerPrivPath := filepath.Join(dir, "provider.private")
	if err := os.WriteFile(providerPrivPath, providerPrivateKey, 0o600); err != nil {
		return nil, nil, err
	}
	certPath := filepath.Join(dir, "resolver.cert")
	keyPath := filepath.Join(dir, "resolver.key")
	command := fmt.Sprintf("generateDNSCryptCertificate(%s, %s, %s, %d, %d, %d)",
		luaString(providerPrivPath), luaString(certPath), luaString(keyPath), serial, validFrom, validUntil)
	output, err := runConsoleCommand(inst, dnsdistBinary, command)
	if err != nil {
		return nil, nil, errf("dnsdist console session failed: %v", err)
	}
	certBytes, errCert := os.ReadFile(certPath)
	keyBytes, errKey := os.ReadFile(keyPath)
	if errCert != nil || errKey != nil {
		return nil, nil, errf("dnsdist did not write DNSCrypt resolver certificate files; console output: %q", output)
	}
	if len(certBytes) != DNSCryptCertLength {
		return nil, nil, errf("unexpected resolver certificate length %d (expected %d)", len(certBytes), DNSCryptCertLength)
	}
	if len(keyBytes) != ResolverPrivateKeyLength {
		return nil, nil, errf("unexpected resolver private key length %d (expected %d)", len(keyBytes), ResolverPrivateKeyLength)
	}
	return certBytes, keyBytes, nil
}

// ProviderFingerprint is the human-readable colon-grouped hex
// fingerprint, matching dnsdist's own generateDNSCryptProviderKeys/
// printDNSCryptProviderFingerprint display format exactly (verified
// live against a real generated key this session) -- pure formatting of
// already-known-real bytes, no dnsdist invocation needed.
func ProviderFingerprint(publicKey []byte) (string, error) {
	if len(publicKey) != ProviderPublicKeyLength {
		return "", errf("publicKey must be %d bytes, got %d", ProviderPublicKeyLength, len(publicKey))
	}
	hexStr := strings.ToUpper(fmt.Sprintf("%x", publicKey))
	var groups []string
	for i := 0; i < len(hexStr); i += 4 {
		groups = append(groups, hexStr[i:i+4])
	}
	return strings.Join(groups, ":"), nil
}
