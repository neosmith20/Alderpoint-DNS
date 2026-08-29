// Native Go secrets subsystem, real half. This is the ONLY place in
// the whole Go control plane that ever holds the master key or a
// secret's plaintext value -- the unprivileged web process (internal/
// secretstore) only ever sends a plaintext value in (to be sealed) or
// asks this agent to use an already-sealed value for one specific,
// named purpose (e.g. "send this test webhook"). There is no operation
// here that returns a decrypted plaintext value to a caller, by design
// -- see this package's doc comment on RegisterSecretsOps and
// PARITY_MATRIX.md's database-at-rest audit for why this exists.
//
// Master key: AES-256, 32 random bytes from crypto/rand, generated on
// first use and persisted at <KeyDir>/master.key.v1 (mode 0600, inside
// a directory created at mode 0700) -- root-owned (this whole process
// is root), never copied into the web container's image or state, never
// returned by any operation, never written to the audit log (audit
// entries carry only op name/peer uid/ok/duration/a caller-safe detail
// string, see audit.go -- nothing here ever puts key or plaintext
// material into that detail string).
//
// Versioning: key files are named master.key.v<N>; every version ever
// generated is kept (never deleted) so a record sealed under an older
// version can still be opened after a future rotation -- this session
// does not implement a rotation *operation* (generating v2 and
// re-sealing existing records under it), but the on-disk shape and the
// seal/open code already support one being added later without a data
// migration: open() looks up whichever key_version a record says it
// was sealed with.
//
// AEAD: AES-256-GCM. Associated data (authenticated, not secret) is
// "<kind>|<owner_ref>" -- see internal/secretstore's doc comment for
// why this is what stops ciphertext from one record being replayed
// against another.
package hostagentd

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

const (
	masterKeySize   = 32 // AES-256
	masterKeyPrefix = "master.key.v"
)

var masterKeyFileRe = regexp.MustCompile(`^master\.key\.v(\d+)$`)

// SecretsConfig configures the master-key-backed AEAD engine.
type SecretsConfig struct {
	// KeyDir is where master key versions live. Must be a dedicated
	// directory this agent (root) exclusively controls -- never inside
	// any path the web container mounts. Empty = secrets ops
	// unavailable (RegisterSecretsOps is simply not called).
	KeyDir string
}

type secretsEngine struct {
	mu      sync.RWMutex
	keys    map[int][]byte
	current int
}

// loadOrCreateKeyring reads every master.key.v<N> file in dir,
// generating v1 with crypto/rand if the directory is empty. The
// directory and every key file are created/verified at the strictest
// permissions a root-owned, single-reader secret store needs (0700/
// 0600) -- matching app/v2/secret_store.py's own posture for its
// directory, one level stricter because this holds a key that can
// decrypt many secrets, not one secret's own value.
func loadOrCreateKeyring(dir string) (*secretsEngine, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating secrets key directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("hardening secrets key directory permissions: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	keys := map[int][]byte{}
	current := 0
	for _, e := range entries {
		m := masterKeyFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		version, _ := strconv.Atoi(m[1])
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		if len(raw) != masterKeySize {
			return nil, fmt.Errorf("%s is %d bytes, want %d -- refusing to use a malformed master key", e.Name(), len(raw), masterKeySize)
		}
		keys[version] = raw
		if version > current {
			current = version
		}
	}

	if current == 0 {
		key := make([]byte, masterKeySize)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("generating master key: %w", err)
		}
		path := filepath.Join(dir, masterKeyPrefix+"1")
		if err := writeKeyFileAtomic(path, key); err != nil {
			return nil, err
		}
		keys[1] = key
		current = 1
	}

	return &secretsEngine{keys: keys, current: current}, nil
}

func writeKeyFileAtomic(path string, key []byte) error {
	tmp := path + fmt.Sprintf(".tmp.%d", time.Now().UnixNano())
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func aadFor(kind, ownerRef string) []byte {
	return []byte(kind + "|" + ownerRef)
}

func (e *secretsEngine) seal(kind, ownerRef, plaintext string) (ciphertext, nonce []byte, keyVersion int, err error) {
	e.mu.RLock()
	key := e.keys[e.current]
	version := e.current
	e.mu.RUnlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, 0, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, 0, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, 0, err
	}
	ciphertext = gcm.Seal(nil, nonce, []byte(plaintext), aadFor(kind, ownerRef))
	return ciphertext, nonce, version, nil
}

// open decrypts and authenticates a stored secret. A wrong kind/
// owner_ref, a tampered ciphertext, or an unknown key_version all fail
// the SAME way (a generic error), never distinguishing which -- this
// value is never returned to any external caller, but the failure mode
// itself must not leak information about which check failed.
func (e *secretsEngine) open(kind, ownerRef string, keyVersion int, nonce, ciphertext []byte) (string, error) {
	e.mu.RLock()
	key, ok := e.keys[keyVersion]
	e.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("secret could not be opened")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("secret could not be opened")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("secret could not be opened")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aadFor(kind, ownerRef))
	if err != nil {
		return "", fmt.Errorf("secret could not be opened")
	}
	return string(plaintext), nil
}

// RegisterSecretsOps wires OpSecretsSeal and every narrow "use"
// operation. Returns an error only for a real setup failure (bad
// KeyDir permissions, corrupt key file) -- never registers a
// half-working engine.
func RegisterSecretsOps(s *Server, cfg SecretsConfig) error {
	engine, err := loadOrCreateKeyring(cfg.KeyDir)
	if err != nil {
		return err
	}

	s.Register(hostagent.OpSecretsSeal, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			Kind     string `json:"kind"`
			OwnerRef string `json:"owner_ref"`
			Value    string `json:"value"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if in.Kind == "" || in.OwnerRef == "" {
			return nil, fmt.Errorf("kind and owner_ref are required")
		}
		if in.Value == "" {
			return nil, fmt.Errorf("value must not be empty")
		}
		ciphertext, nonce, version, err := engine.seal(in.Kind, in.OwnerRef, in.Value)
		if err != nil {
			return nil, fmt.Errorf("sealing failed")
		}
		return map[string]any{
			"ciphertext_b64": base64.StdEncoding.EncodeToString(ciphertext),
			"nonce_b64":      base64.StdEncoding.EncodeToString(nonce),
			"key_version":    version,
		}, nil
	})

	s.Register(hostagent.OpSecretsNotifyTest, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in sealedIn
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		var extra struct {
			NotifyKind string `json:"notify_kind"` // "webhook" | "slack" | "pushover" | "email_smtp"
			SMTPHost   string `json:"smtp_host"`
			SMTPPort   int    `json:"smtp_port"`
			FromAddr   string `json:"from_addr"`
			ToAddr     string `json:"to_addr"`
			Username   string `json:"username"`
		}
		if err := json.Unmarshal(params, &extra); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		plaintext, err := in.open(engine)
		if err != nil {
			return nil, err
		}
		return sendNotification(ctx, extra.NotifyKind, plaintext, testMessageText, testNotifySMTP{
			Host: extra.SMTPHost, Port: extra.SMTPPort, From: extra.FromAddr, To: extra.ToAddr, Username: extra.Username,
		})
	})

	// OpSecretsNotifySend is OpSecretsNotifyTest's real-dispatch sibling
	// (see hostagent.OpSecretsNotifySend's own doc comment): identical
	// decrypt-and-send-immediately contract, but the message comes from
	// the caller (internal/notifications' Dispatch) instead of the
	// fixed test string.
	s.Register(hostagent.OpSecretsNotifySend, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in sealedIn
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		var extra struct {
			NotifyKind string `json:"notify_kind"`
			Message    string `json:"message"`
			SMTPHost   string `json:"smtp_host"`
			SMTPPort   int    `json:"smtp_port"`
			FromAddr   string `json:"from_addr"`
			ToAddr     string `json:"to_addr"`
			Username   string `json:"username"`
		}
		if err := json.Unmarshal(params, &extra); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if extra.Message == "" {
			return nil, fmt.Errorf("message must not be empty")
		}
		plaintext, err := in.open(engine)
		if err != nil {
			return nil, err
		}
		return sendNotification(ctx, extra.NotifyKind, plaintext, extra.Message, testNotifySMTP{
			Host: extra.SMTPHost, Port: extra.SMTPPort, From: extra.FromAddr, To: extra.ToAddr, Username: extra.Username,
		})
	})

	// Replication CA: the ONLY two operations that ever touch the
	// Replication CA private key -- see internal/replication's own doc
	// comment. Both live here (not a separate file) because they need
	// this same closure's `engine`, exactly like every other
	// seal/open-backed op above.
	s.Register(hostagent.OpReplicationEnsureCA, func(ctx context.Context, params json.RawMessage) (any, error) {
		caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating CA key: %w", err)
		}
		serial, err := randomSerial()
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "Alderpoint DNS Replication CA"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().AddDate(20, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
		if err != nil {
			return nil, fmt.Errorf("creating CA certificate: %w", err)
		}
		keyDER, err := x509.MarshalECPrivateKey(caKey)
		if err != nil {
			return nil, fmt.Errorf("marshaling CA key: %w", err)
		}
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
		ciphertext, nonce, version, err := engine.seal("replication_ca_key", "replication", keyPEM)
		if err != nil {
			return nil, fmt.Errorf("sealing CA key failed")
		}
		return map[string]any{
			"ca_cert_pem":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			"ciphertext_b64": base64.StdEncoding.EncodeToString(ciphertext),
			"nonce_b64":      base64.StdEncoding.EncodeToString(nonce),
			"key_version":    version,
		}, nil
	})

	s.Register(hostagent.OpReplicationIssueCert, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			CA       sealedIn `json:"ca"`
			CACertPEM string  `json:"ca_cert_pem"`
			CN        string  `json:"cn"`
			SANs      []string `json:"sans"`
			KeyUsage  string  `json:"key_usage"` // "server" | "client"
			Days      int     `json:"days"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if in.CN == "" {
			return nil, fmt.Errorf("cn is required")
		}
		if in.KeyUsage != "server" && in.KeyUsage != "client" {
			return nil, fmt.Errorf("key_usage must be \"server\" or \"client\"")
		}
		if in.Days <= 0 {
			in.Days = 825
		}
		caKeyPEM, err := in.CA.open(engine)
		if err != nil {
			return nil, err
		}
		caKeyBlock, _ := pem.Decode([]byte(caKeyPEM))
		if caKeyBlock == nil {
			return nil, fmt.Errorf("CA key could not be decoded")
		}
		caKey, err := x509.ParseECPrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("CA key could not be parsed")
		}
		caCertBlock, _ := pem.Decode([]byte(in.CACertPEM))
		if caCertBlock == nil {
			return nil, fmt.Errorf("ca_cert_pem could not be decoded")
		}
		caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca_cert_pem could not be parsed")
		}

		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generating leaf key: %w", err)
		}
		serial, err := randomSerial()
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: in.CN},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().AddDate(0, 0, in.Days),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		if in.KeyUsage == "server" {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			for _, san := range in.SANs {
				if ip := net.ParseIP(san); ip != nil {
					tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
				} else {
					tmpl.DNSNames = append(tmpl.DNSNames, san)
				}
			}
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			return nil, fmt.Errorf("creating leaf certificate: %w", err)
		}
		keyDER, err := x509.MarshalECPrivateKey(leafKey)
		if err != nil {
			return nil, fmt.Errorf("marshaling leaf key: %w", err)
		}
		fingerprint := sha256.Sum256(der)
		return map[string]any{
			"cert_pem":    string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			"key_pem":     string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
			"fingerprint": hex.EncodeToString(fingerprint[:]),
			"serial":      serial.String(),
		}, nil
	})

	return nil
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

const testMessageText = "Alderpoint DNS test notification -- if you can see this, this provider is configured correctly."

// sealedIn is the common ciphertext-bearing input shape every "use" op
// shares.
type sealedIn struct {
	Kind          string `json:"kind"`
	OwnerRef      string `json:"owner_ref"`
	CiphertextB64 string `json:"ciphertext_b64"`
	NonceB64      string `json:"nonce_b64"`
	KeyVersion    int    `json:"key_version"`
}

func (in sealedIn) open(engine *secretsEngine) (string, error) {
	if in.Kind == "" || in.OwnerRef == "" || in.CiphertextB64 == "" || in.NonceB64 == "" {
		return "", fmt.Errorf("kind, owner_ref, ciphertext_b64, and nonce_b64 are all required")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(in.CiphertextB64)
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext encoding")
	}
	nonce, err := base64.StdEncoding.DecodeString(in.NonceB64)
	if err != nil {
		return "", fmt.Errorf("invalid nonce encoding")
	}
	return engine.open(in.Kind, in.OwnerRef, in.KeyVersion, nonce, ciphertext)
}

type testNotifySMTP struct {
	Host, From, To, Username string
	Port                     int
}

// sendTestNotification performs the ACTUAL send -- real HTTP POST for
// webhook/slack/pushover kinds, a real SMTP session for email_smtp --
// using the decrypted secret, and returns only the outcome. This is
// intentionally the single place plaintext secret material is used for
// something, and it never leaves this function as a return value.
// sendNotification is the real, shared send implementation --
// sendTestNotification (fixed message) and Dispatch's real event sends
// (a caller-supplied message) both go through this one function so
// there is exactly one place that ever holds the plaintext secret.
func sendNotification(ctx context.Context, notifyKind, secret, message string, smtp testNotifySMTP) (any, error) {
	client := &http.Client{Timeout: 10 * time.Second}

	switch notifyKind {
	case "webhook":
		if !strings.HasPrefix(secret, "https://") && !strings.HasPrefix(secret, "http://") {
			return nil, fmt.Errorf("stored webhook secret is not a valid URL")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, secret, strings.NewReader(fmt.Sprintf(`{"text":%q}`, message)))
		if err != nil {
			return nil, fmt.Errorf("building request: %w", err)
		}
		req.Header.Set("content-type", "application/json")
		return doTestRequest(client, req)

	case "slack":
		if !strings.HasPrefix(secret, "https://") {
			return nil, fmt.Errorf("stored Slack webhook secret is not a valid URL")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, secret, strings.NewReader(fmt.Sprintf(`{"text":%q}`, message)))
		if err != nil {
			return nil, fmt.Errorf("building request: %w", err)
		}
		req.Header.Set("content-type", "application/json")
		return doTestRequest(client, req)

	case "pushover":
		userKey, appToken, ok := strings.Cut(secret, ":")
		if !ok || userKey == "" || appToken == "" {
			return nil, fmt.Errorf("stored Pushover secret must be 'user_key:app_token'")
		}
		form := strings.NewReader(fmt.Sprintf("token=%s&user=%s&message=%s", appToken, userKey, message))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.pushover.net/1/messages.json", form)
		if err != nil {
			return nil, fmt.Errorf("building request: %w", err)
		}
		req.Header.Set("content-type", "application/x-www-form-urlencoded")
		return doTestRequest(client, req)

	case "email_smtp":
		if smtp.Host == "" || smtp.Port == 0 || smtp.From == "" || smtp.To == "" {
			return nil, fmt.Errorf("SMTP host, port, from_addr, and to_addr are all required")
		}
		if err := sendTestSMTP(smtp, secret, message); err != nil {
			return map[string]any{"ok": false, "detail": err.Error()}, nil
		}
		return map[string]any{"ok": true, "detail": "test message sent"}, nil

	default:
		return nil, fmt.Errorf("unknown notification kind %q", notifyKind)
	}
}

func doTestRequest(client *http.Client, req *http.Request) (any, error) {
	resp, err := client.Do(req)
	if err != nil {
		return map[string]any{"ok": false, "detail": err.Error()}, nil
	}
	defer resp.Body.Close()
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	return map[string]any{"ok": ok, "status_code": resp.StatusCode, "detail": fmt.Sprintf("HTTP %d", resp.StatusCode)}, nil
}
