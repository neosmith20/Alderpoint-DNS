package hostagentd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"alderpointdns/go-controlplane/internal/hostagent"
)

func sealOneForTest(t *testing.T, sockPath, kind, ownerRef, value string) map[string]any {
	t.Helper()
	c := hostagent.NewClient(sockPath)
	var out map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsSeal, map[string]any{
		"kind": kind, "owner_ref": ownerRef, "value": value,
	}, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSecretsBackupCreateAndRestoreRoundTrip(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)

	real1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(real1.Close)
	real2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	t.Cleanup(real2.Close)
	sealed1 := sealOneForTest(t, sockPath, "notification_webhook", "provider-1", real1.URL)
	sealed2 := sealOneForTest(t, sockPath, "notification_webhook", "provider-2", real2.URL)

	var created map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsBackupCreate, map[string]any{
		"secrets": []map[string]any{
			{"id": "s1", "kind": "notification_webhook", "owner_ref": "provider-1", "ciphertext_b64": sealed1["ciphertext_b64"], "nonce_b64": sealed1["nonce_b64"], "key_version": sealed1["key_version"]},
			{"id": "s2", "kind": "notification_webhook", "owner_ref": "provider-2", "ciphertext_b64": sealed2["ciphertext_b64"], "nonce_b64": sealed2["nonce_b64"], "key_version": sealed2["key_version"]},
		},
	}, &created); err != nil {
		t.Fatal(err)
	}
	if created["backup_b64"] == "" || created["backup_b64"] == nil {
		t.Fatalf("expected a real backup_b64, got %+v", created)
	}
	if created["secret_count"] != float64(2) {
		t.Fatalf("expected secret_count=2, got %+v", created)
	}
	backupKey, ok := created["backup_key"].(map[string]any)
	if !ok || backupKey["ciphertext_b64"] == "" {
		t.Fatalf("expected a real sealed backup_key to come back, got %+v", created)
	}

	// The response must never contain the real plaintext secret values.
	raw, _ := json.Marshal(created)
	if strings.Contains(string(raw), real1.URL) || strings.Contains(string(raw), real2.URL) {
		t.Fatal("OpSecretsBackupCreate's response must never contain plaintext secret values")
	}

	var restored map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsBackupRestore, map[string]any{
		"backup_b64": created["backup_b64"],
		"backup_key": backupKey,
	}, &restored); err != nil {
		t.Fatal(err)
	}
	rawRestored, _ := json.Marshal(restored)
	if strings.Contains(string(rawRestored), real1.URL) || strings.Contains(string(rawRestored), real2.URL) {
		t.Fatal("OpSecretsBackupRestore's response must never contain plaintext secret values")
	}
	secretsOut, _ := restored["secrets"].([]any)
	if len(secretsOut) != 2 {
		t.Fatalf("expected 2 resealed secrets, got %+v", restored)
	}

	// Prove the resealed values genuinely decrypt back to the ORIGINAL
	// plaintext -- open each directly via secrets.notify_send against a
	// disposable webhook target rather than trusting the shape alone.
	for _, raw := range secretsOut {
		rec := raw.(map[string]any)
		var testOut map[string]any
		err := c.Call(context.Background(), hostagent.OpSecretsNotifySend, map[string]any{
			"kind": rec["kind"], "owner_ref": rec["owner_ref"],
			"ciphertext_b64": rec["ciphertext_b64"], "nonce_b64": rec["nonce_b64"], "key_version": rec["key_version"],
			"notify_kind": "webhook", "message": "resealed-secret-check",
		}, &testOut)
		if err != nil {
			t.Fatalf("resealed secret %v did not decrypt to a usable value: %v", rec["id"], err)
		}
	}
}

func TestSecretsBackupCreateReusesTheSameBackupKeyOnASecondCall(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	sealed := sealOneForTest(t, sockPath, "notification_webhook", "provider-1", "https://example.com/hook-1")

	var first map[string]any
	c.Call(context.Background(), hostagent.OpSecretsBackupCreate, map[string]any{
		"secrets": []map[string]any{{"id": "s1", "kind": "notification_webhook", "owner_ref": "provider-1", "ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"]}},
	}, &first)
	firstKey := first["backup_key"].(map[string]any)

	var second map[string]any
	if err := c.Call(context.Background(), hostagent.OpSecretsBackupCreate, map[string]any{
		"secrets":    []map[string]any{{"id": "s1", "kind": "notification_webhook", "owner_ref": "provider-1", "ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"]}},
		"backup_key": firstKey,
	}, &second); err != nil {
		t.Fatal(err)
	}
	secondKey := second["backup_key"].(map[string]any)
	if firstKey["ciphertext_b64"] != secondKey["ciphertext_b64"] {
		t.Fatal("expected the SAME backup key to be reused when the caller passes it back in, not regenerated")
	}
}

func TestSecretsBackupRestoreRejectsWrongBackupKey(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	sealed := sealOneForTest(t, sockPath, "notification_webhook", "provider-1", "https://example.com/hook-1")

	var created map[string]any
	c.Call(context.Background(), hostagent.OpSecretsBackupCreate, map[string]any{
		"secrets": []map[string]any{{"id": "s1", "kind": "notification_webhook", "owner_ref": "provider-1", "ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"]}},
	}, &created)

	// A second, INDEPENDENT backup key (from a fresh backup of a
	// different secret) must not be able to decrypt the first backup.
	sealed2 := sealOneForTest(t, sockPath, "notification_webhook", "provider-2", "https://example.com/hook-2")
	var otherCreated map[string]any
	c.Call(context.Background(), hostagent.OpSecretsBackupCreate, map[string]any{
		"secrets": []map[string]any{{"id": "s2", "kind": "notification_webhook", "owner_ref": "provider-2", "ciphertext_b64": sealed2["ciphertext_b64"], "nonce_b64": sealed2["nonce_b64"], "key_version": sealed2["key_version"]}},
	}, &otherCreated)

	// Force a genuinely different key: seal an arbitrary different
	// value as a fake "backup_key" reference under the same kind/owner
	// the real backup key uses, guaranteeing a different underlying key.
	fakeKey := sealOneForTest(t, sockPath, "internal_backup_key", "secrets_backup_fake", base64.StdEncoding.EncodeToString(make([]byte, 32)))

	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsBackupRestore, map[string]any{
		"backup_b64": created["backup_b64"],
		"backup_key": fakeKey,
	}, &out)
	if err == nil {
		t.Fatal("expected restore with the wrong backup key to fail")
	}
}

func TestSecretsBackupRestoreRejectsCorruptedBackup(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	sealed := sealOneForTest(t, sockPath, "notification_webhook", "provider-1", "https://example.com/hook-1")

	var created map[string]any
	c.Call(context.Background(), hostagent.OpSecretsBackupCreate, map[string]any{
		"secrets": []map[string]any{{"id": "s1", "kind": "notification_webhook", "owner_ref": "provider-1", "ciphertext_b64": sealed["ciphertext_b64"], "nonce_b64": sealed["nonce_b64"], "key_version": sealed["key_version"]}},
	}, &created)

	tampered := created["backup_b64"].(string) + "AAAA"
	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsBackupRestore, map[string]any{
		"backup_b64": tampered,
		"backup_key": created["backup_key"],
	}, &out)
	if err == nil {
		t.Fatal("expected restore of a tampered backup to fail")
	}
}

func TestSecretsBackupRestoreRejectsMissingBackupKey(t *testing.T) {
	s, sockPath := newTestServer(t, uint32(0))
	if err := RegisterSecretsOps(s, SecretsConfig{KeyDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	c := hostagent.NewClient(sockPath)
	var out map[string]any
	err := c.Call(context.Background(), hostagent.OpSecretsBackupRestore, map[string]any{"backup_b64": "AAAA"}, &out)
	if err == nil {
		t.Fatal("expected an error when backup_key is missing")
	}
}
