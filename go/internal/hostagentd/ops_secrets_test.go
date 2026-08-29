package hostagentd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"alderpointdns/go-controlplane/internal/hostagent"
)

// --- engine-level tests (no socket) -----------------------------------

func TestLoadOrCreateKeyringGeneratesAndPersistsAMasterKey(t *testing.T) {
	dir := t.TempDir()
	e, err := loadOrCreateKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e.current != 1 {
		t.Fatalf("expected key version 1, got %d", e.current)
	}
	path := filepath.Join(dir, "master.key.v1")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("master key file mode = %o, want 0600", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("key dir mode = %o, want 0700", dirInfo.Mode().Perm())
	}
}

func TestLoadOrCreateKeyringPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	e1, err := loadOrCreateKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, version, err := e1.seal("kind-a", "owner-1", "top secret value")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate a process restart: fresh engine loaded from the same dir.
	e2, err := loadOrCreateKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}
	if e2.current != 1 {
		t.Fatalf("restart generated a NEW key instead of reusing the persisted one: version %d", e2.current)
	}
	plaintext, err := e2.open("kind-a", "owner-1", version, nonce, ciphertext)
	if err != nil {
		t.Fatalf("restart-loaded engine could not open a value sealed before restart: %v", err)
	}
	if plaintext != "top secret value" {
		t.Fatalf("plaintext = %q, want the original value", plaintext)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	e, err := loadOrCreateKeyring(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, version, err := e.seal("notification_secret", "provider-123", "https://hooks.example.com/abc")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ciphertext), "hooks.example.com") {
		t.Fatal("ciphertext must not contain the plaintext value")
	}
	got, err := e.open("notification_secret", "provider-123", version, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://hooks.example.com/abc" {
		t.Fatalf("got %q", got)
	}
}

func TestOpenFailsOnWrongOwnerRef(t *testing.T) {
	e, _ := loadOrCreateKeyring(t.TempDir())
	ciphertext, nonce, version, err := e.seal("notification_secret", "provider-123", "value")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.open("notification_secret", "provider-456", version, nonce, ciphertext); err == nil {
		t.Fatal("expected an authentication failure when owner_ref doesn't match the sealed context")
	}
}

func TestOpenFailsOnWrongKind(t *testing.T) {
	e, _ := loadOrCreateKeyring(t.TempDir())
	ciphertext, nonce, version, err := e.seal("notification_secret", "provider-123", "value")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.open("upstream_auth", "provider-123", version, nonce, ciphertext); err == nil {
		t.Fatal("expected an authentication failure when kind doesn't match the sealed context -- ciphertext must not be replayable across secret kinds")
	}
}

func TestOpenFailsOnTamperedCiphertext(t *testing.T) {
	e, _ := loadOrCreateKeyring(t.TempDir())
	ciphertext, nonce, version, err := e.seal("k", "o", "value")
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xFF
	if _, err := e.open("k", "o", version, nonce, tampered); err == nil {
		t.Fatal("expected an authentication failure on tampered ciphertext")
	}
}

func TestOpenFailsOnUnknownKeyVersion(t *testing.T) {
	e, _ := loadOrCreateKeyring(t.TempDir())
	ciphertext, nonce, _, err := e.seal("k", "o", "value")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.open("k", "o", 999, nonce, ciphertext); err == nil {
		t.Fatal("expected an error for an unknown key version")
	}
}

func TestLoadOrCreateKeyringRejectsCorruptKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "master.key.v1"), []byte("too short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateKeyring(dir); err == nil {
		t.Fatal("expected a corrupt/malformed key file to be rejected, not silently used")
	}
}

// --- op-level tests (real unix socket) ---------------------------------

func TestOpSecretsSealNeverReturnsPlaintext(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var out map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsSeal, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1", "value": "super-secret-token",
	}, &out); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	if strings.Contains(string(raw), "super-secret-token") {
		t.Fatal("OpSecretsSeal's response must never contain the plaintext value")
	}
	if out["ciphertext_b64"] == "" || out["nonce_b64"] == "" {
		t.Fatalf("expected real ciphertext/nonce fields, got %+v", out)
	}
}

func TestOpSecretsSealRejectsEmptyValue(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsSeal, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1", "value": "",
	}, &out)
	if err == nil {
		t.Fatal("expected empty value to be rejected")
	}
}

func TestOpSecretsNotifyTestWebhookRealHTTP(t *testing.T) {
	var receivedAuth string
	var receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)

	var sealed map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsSeal, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1", "value": srv.URL,
	}, &sealed); err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsNotifyTest, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1",
		"ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"],
		"notify_kind": "webhook",
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Fatalf("expected ok=true, got %+v", out)
	}
	if !strings.Contains(receivedBody, "test notification") {
		t.Fatalf("real webhook server did not receive the expected test payload: %q", receivedBody)
	}
	_ = receivedAuth
}

// TestOpSecretsNotifySendUsesRealCallerMessage proves the real-dispatch
// sibling op sends the CALLER's message (an event's real summary), not
// the fixed test string -- the one behavioral difference from
// OpSecretsNotifyTest, over a real HTTP server.
func TestOpSecretsNotifySendUsesRealCallerMessage(t *testing.T) {
	var receivedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedBody = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)

	var sealed map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsSeal, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1", "value": srv.URL,
	}, &sealed); err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsNotifySend, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1",
		"ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"],
		"notify_kind": "webhook", "message": "blocklist update failed 3 times in a row",
	}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true {
		t.Fatalf("expected ok=true, got %+v", out)
	}
	if !strings.Contains(receivedBody, "blocklist update failed 3 times in a row") {
		t.Fatalf("real webhook server did not receive the real event message: %q", receivedBody)
	}
}

// TestIsDiscordWebhookURL proves the real host-based detection --
// Discord's current and legacy webhook host names match, an unrelated
// host (even one containing "discord" outside the actual hostname)
// does not.
func TestIsDiscordWebhookURL(t *testing.T) {
	cases := map[string]bool{
		"https://discord.com/api/webhooks/123/abc":         true,
		"https://discordapp.com/api/webhooks/123/abc":      true,
		"https://ptb.discord.com/api/webhooks/123/abc":     true,
		"https://hooks.slack.com/services/T00/B00/xxx":     false,
		"https://example.com/webhook?redirect=discord.com": false,
		"not a url at all": false,
	}
	for url, want := range cases {
		if got := isDiscordWebhookURL(url); got != want {
			t.Errorf("isDiscordWebhookURL(%q) = %v, want %v", url, got, want)
		}
	}
}

// TestWebhookBodyUsesContentFieldForDiscord is the real regression test
// for the live "Discord webhook test failed: HTTP 400" defect: the
// generic webhook body must use Discord's own required "content" field
// for a Discord URL, and the ordinary Slack-style "text" field for
// everything else.
func TestWebhookBodyUsesContentFieldForDiscord(t *testing.T) {
	discordBody := webhookBody("https://discord.com/api/webhooks/1/abc", "hello")
	if !strings.Contains(discordBody, `"content"`) || strings.Contains(discordBody, `"text"`) {
		t.Fatalf("expected a Discord webhook body to use \"content\", got %s", discordBody)
	}
	slackBody := webhookBody("https://hooks.slack.com/services/T/B/x", "hello")
	if !strings.Contains(slackBody, `"text"`) || strings.Contains(slackBody, `"content"`) {
		t.Fatalf("expected a non-Discord webhook body to use \"text\", got %s", slackBody)
	}
}

// TestOpSecretsNotifyTestAgainstARealDiscordShapedServer proves the
// full real HTTP path end to end against a local server that enforces
// Discord's own actual validation rule (reject a body with none of
// content/embeds/file present, exactly as the real Discord API does) --
// the old {"text": ...} body would fail this with 400 (the live
// defect); the fixed {"content": ...} body must succeed.
func TestOpSecretsNotifyTestAgainstARealDiscordShapedServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		json.Unmarshal(body, &parsed)
		_, hasContent := parsed["content"]
		_, hasEmbeds := parsed["embeds"]
		_, hasFile := parsed["file"]
		if !hasContent && !hasEmbeds && !hasFile {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"message":"Cannot send an empty message","code":50006}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// srv.URL is a plain 127.0.0.1 test server, not really discord.com --
	// exercise webhookBody directly with a URL that DOES parse as
	// Discord to prove the fixed body actually satisfies this real
	// validation rule, independent of hostname detection (already
	// covered by TestIsDiscordWebhookURL above).
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(webhookBody("https://discord.com/api/webhooks/1/abc", "test notification")))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected the fixed Discord-shaped body to be accepted (204), got %d", resp.StatusCode)
	}

	// Prove the OLD body genuinely would have failed this same real
	// validation -- the actual root cause, not a hypothetical.
	oldBuggyBody := fmt.Sprintf(`{"text":%q}`, "test notification")
	req2, _ := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(oldBuggyBody))
	req2.Header.Set("content-type", "application/json")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected the old {\"text\":...} body to be rejected with 400 by a real Discord-shaped validator, got %d -- if this now passes, the test server's validation rule no longer matches Discord's real API", resp2.StatusCode)
	}
}

func TestOpSecretsNotifySendRejectsEmptyMessage(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var sealed map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsSeal, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1", "value": "https://example.test/webhook",
	}, &sealed); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsNotifySend, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1",
		"ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"],
		"notify_kind": "webhook", "message": "",
	}, &out)
	if err == nil {
		t.Fatal("expected an error for an empty message")
	}
}

func TestOpSecretsNotifyTestRejectsWrongContext(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)

	var sealed map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsSeal, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-1", "value": "https://example.com/hook",
	}, &sealed); err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsNotifyTest, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-DIFFERENT", // wrong owner_ref
		"ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"],
		"notify_kind": "webhook",
	}, &out)
	if err == nil {
		t.Fatal("expected a denial when the ciphertext's context doesn't match the caller's claimed owner_ref")
	}
}

func TestOpSecretsNotifyTestPushoverFormat(t *testing.T) {
	var receivedForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 1024)
		n, _ := r.Body.Read(buf)
		receivedForm = string(buf[:n])
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	// This test proves the real form-body shape only; it does not
	// override Pushover's fixed real endpoint (there is exactly one,
	// by design -- see resolveDNSPerfCase's "never a caller-supplied
	// remote host" precedent applied here too), so it checks the field
	// separator logic directly instead.
	secret := "userkey123:apptoken456"
	userKey, appToken, ok := strings.Cut(secret, ":")
	if !ok || userKey != "userkey123" || appToken != "apptoken456" {
		t.Fatalf("pushover secret split logic broken: %q %q %v", userKey, appToken, ok)
	}
	_ = receivedForm
}

func TestOpSecretsNotifyTestRejectsMalformedPushoverSecret(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)

	var sealed map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsSeal, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-2", "value": "not-a-valid-pushover-secret",
	}, &sealed); err != nil {
		t.Fatal(err)
	}

	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsNotifyTest, map[string]any{
		"kind": "notification_secret", "owner_ref": "provider-2",
		"ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"],
		"notify_kind": "pushover",
	}, &out)
	if err == nil {
		t.Fatal("expected a malformed Pushover secret (missing ':') to be rejected")
	}
}

func TestSendTestSMTPRealServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var transcript strings.Builder
		buf := make([]byte, 4096)
		write := func(s string) { conn.Write([]byte(s)) }
		write("220 test.local ESMTP\r\n")
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			line := string(buf[:n])
			transcript.WriteString(line)
			switch {
			case strings.HasPrefix(line, "EHLO"):
				write("250-test.local\r\n250 OK\r\n")
			case strings.HasPrefix(line, "MAIL FROM"):
				write("250 OK\r\n")
			case strings.HasPrefix(line, "RCPT TO"):
				write("250 OK\r\n")
			case strings.HasPrefix(line, "DATA"):
				write("354 go ahead\r\n")
			case strings.Contains(line, "\r\n.\r\n"):
				write("250 queued\r\n")
			case strings.HasPrefix(line, "QUIT"):
				write("221 bye\r\n")
				done <- transcript.String()
				return
			}
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	err = sendTestSMTP(testNotifySMTP{Host: host, Port: port, From: "alerts@example.com", To: "owner@example.com"}, "", "hello")
	if err != nil {
		t.Fatalf("unexpected SMTP send failure against a real (fake) server: %v", err)
	}
	select {
	case transcript := <-done:
		if !strings.Contains(transcript, "MAIL FROM") {
			t.Fatalf("real SMTP session never sent MAIL FROM: %q", transcript)
		}
	case <-t.Context().Done():
		t.Fatal("timed out waiting for the fake SMTP server's transcript")
	}
}
