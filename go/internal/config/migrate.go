package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadOrMigrate loads appliance.yaml, transparently upgrading a legacy
// (schema_version 0, pre-versioning) file to the current schema in place
// before validating it -- the YAML analogue of the SQLite migration
// runner in dbmigrate. The upgrade only ever touches the file via
// AtomicWriteYAML's temp-file+rename, so a failure partway through
// (marshal error, disk full, etc.) leaves the original file completely
// untouched -- there is nothing to "roll back" because nothing is written
// until the new content is fully valid and complete.
func LoadOrMigrate(path string) (cfg *Config, migrated bool, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read config: %w", err)
	}

	var probe struct {
		SchemaVersion *int `yaml:"schema_version"`
	}
	if err := yaml.Unmarshal(raw, &probe); err != nil {
		return nil, false, fmt.Errorf("parse config to check schema_version: %w", err)
	}

	version := 0
	if probe.SchemaVersion != nil {
		version = *probe.SchemaVersion
	}

	switch version {
	case CurrentSchemaVersion:
		cfg, err = Load(path)
		return cfg, false, err

	case 0:
		// Legacy shape: a "loose" pre-versioning map, upgraded by filling
		// in every field the current schema requires with a safe default
		// wherever it's missing, then writing schema_version: 1.
		var legacy map[string]any
		if err := yaml.Unmarshal(raw, &legacy); err != nil {
			return nil, false, fmt.Errorf("parse legacy config: %w", err)
		}
		upgraded := upgradeLegacyMap(legacy)
		if err := AtomicWriteYAML(path, upgraded); err != nil {
			return nil, false, fmt.Errorf("write migrated config (original file untouched): %w", err)
		}
		cfg, err = Load(path)
		return cfg, true, err

	default:
		return nil, false, fmt.Errorf("config schema_version %d has no migration path to %d", version, CurrentSchemaVersion)
	}
}

func upgradeLegacyMap(m map[string]any) map[string]any {
	getMap := func(key string) map[string]any {
		if v, ok := m[key].(map[string]any); ok {
			return v
		}
		v := map[string]any{}
		m[key] = v
		return v
	}
	setDefault := func(sec map[string]any, key string, def any) {
		if _, ok := sec[key]; !ok {
			sec[key] = def
		}
	}

	m["schema_version"] = CurrentSchemaVersion

	appliance := getMap("appliance")
	setDefault(appliance, "name", "alderpointdns")
	setDefault(appliance, "timezone", "UTC")

	web := getMap("web")
	setDefault(web, "listen_address", "0.0.0.0")
	// 8443 matches the real packaged systemd unit's own -addr override
	// (packaging/systemd/alderpointdns-go.service) -- kept in sync so an
	// appliance.yaml missing this field (e.g. postinst's own minimal
	// fallback template) never defaults to a value that contradicts what
	// the unit actually listens on. See config/appliance.yaml's own
	// comment on the same field for the full explanation.
	setDefault(web, "listen_port", 8443)
	setDefault(web, "tls_cert_path", "")
	setDefault(web, "tls_key_path", "")

	bl := getMap("blocklists")
	setDefault(bl, "staging_dir", "/var/lib/alderpointdns-go/blocklists/staging")
	setDefault(bl, "runtime_dir", "/var/lib/alderpointdns-go/blocklists/runtime")
	setDefault(bl, "pull_timeout_seconds", 30)
	setDefault(bl, "scheduler_tick_seconds", 30)
	setDefault(bl, "max_concurrent_pulls", 3)

	ld := getMap("local_dns")
	setDefault(ld, "staging_dir", "/var/lib/alderpointdns-go/local-dns/staging")
	setDefault(ld, "runtime_dir", "/var/lib/alderpointdns-go/local-dns/runtime")

	auth := getMap("auth")
	setDefault(auth, "session_ttl_seconds", 43200)
	setDefault(auth, "last_seen_update_interval_seconds", 60)

	return m
}
