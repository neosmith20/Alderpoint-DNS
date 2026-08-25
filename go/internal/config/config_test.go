package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidatesCurrentSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appliance.yaml")
	os.WriteFile(path, []byte(`
schema_version: 1
appliance: {name: test, timezone: UTC}
web: {listen_address: 127.0.0.1, listen_port: 8444, tls_cert_path: "", tls_key_path: ""}
blocklists: {staging_dir: /tmp/a, runtime_dir: /tmp/b, pull_timeout_seconds: 30, scheduler_tick_seconds: 30, max_concurrent_pulls: 3}
local_dns: {staging_dir: /tmp/c, runtime_dir: /tmp/d}
auth: {session_ttl_seconds: 3600, last_seen_update_interval_seconds: 60}
`), 0o644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Web.ListenPort != 8444 {
		t.Errorf("listen_port = %d, want 8444", cfg.Web.ListenPort)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appliance.yaml")
	os.WriteFile(path, []byte(`
schema_version: 1
appliance: {name: test, timezone: UTC}
web: {listen_address: 127.0.0.1, listen_port: 8444, tls_cert_path: "", tls_key_path: "", bogus_field: true}
blocklists: {staging_dir: /tmp/a, runtime_dir: /tmp/b, pull_timeout_seconds: 30, scheduler_tick_seconds: 30, max_concurrent_pulls: 3}
local_dns: {staging_dir: /tmp/c, runtime_dir: /tmp/d}
auth: {session_ttl_seconds: 3600, last_seen_update_interval_seconds: 60}
`), 0o644)

	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for unknown field web.bogus_field, got nil")
	}
}

func TestLoadRejectsWrongSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appliance.yaml")
	os.WriteFile(path, []byte("schema_version: 99\n"), 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for unsupported schema_version, got nil")
	}
}

func TestLoadOrMigrateUpgradesLegacyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appliance.yaml")
	// A "legacy" pre-versioning file: no schema_version, only a couple of
	// the fields the current schema requires.
	legacy := "appliance:\n  name: legacy-box\nweb:\n  listen_port: 9999\n"
	os.WriteFile(path, []byte(legacy), 0o644)

	cfg, migrated, err := LoadOrMigrate(path)
	if err != nil {
		t.Fatalf("LoadOrMigrate: %v", err)
	}
	if !migrated {
		t.Fatal("expected migrated=true for a legacy config")
	}
	if cfg.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("schema_version = %d, want %d", cfg.SchemaVersion, CurrentSchemaVersion)
	}
	if cfg.Appliance.Name != "legacy-box" {
		t.Errorf("appliance.name = %q, want legacy-box (preserved from legacy file)", cfg.Appliance.Name)
	}
	if cfg.Web.ListenPort != 9999 {
		t.Errorf("web.listen_port = %d, want 9999 (preserved from legacy file)", cfg.Web.ListenPort)
	}
	if cfg.Blocklists.StagingDir == "" {
		t.Error("blocklists.staging_dir should have been filled with a default")
	}

	// Re-running LoadOrMigrate on the now-upgraded file must be a no-op
	// (migrated=false) and idempotent.
	cfg2, migrated2, err := LoadOrMigrate(path)
	if err != nil {
		t.Fatalf("second LoadOrMigrate: %v", err)
	}
	if migrated2 {
		t.Error("second LoadOrMigrate should not report migrated=true")
	}
	if cfg2.Web.ListenPort != 9999 {
		t.Errorf("second load listen_port = %d, want 9999", cfg2.Web.ListenPort)
	}
}

func TestLoadOrMigrateUnsupportedFutureVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "appliance.yaml")
	os.WriteFile(path, []byte("schema_version: 5\n"), 0o644)
	if _, _, err := LoadOrMigrate(path); err == nil {
		t.Fatal("expected an error for a future schema_version with no migration path")
	}
}

func TestAtomicWriteYAMLRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.yaml")
	type doc struct {
		Value int `yaml:"value"`
	}
	if err := AtomicWriteYAML(path, doc{Value: 42}); err != nil {
		t.Fatalf("AtomicWriteYAML: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(raw) != "value: 42\n" {
		t.Errorf("got %q", string(raw))
	}
}
