// Package config loads and strictly validates the versioned appliance.yaml
// desired-state configuration. It is never a transactional store -- see
// docs/v2/architecture-decision-go-svelte.md "STATE RULES".
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

const CurrentSchemaVersion = 1

type Config struct {
	SchemaVersion int           `yaml:"schema_version"`
	Appliance     ApplianceSec  `yaml:"appliance"`
	Web           WebSec        `yaml:"web"`
	Blocklists    BlocklistsSec `yaml:"blocklists"`
	LocalDNS      LocalDNSSec   `yaml:"local_dns"`
	Auth          AuthSec       `yaml:"auth"`
}

type ApplianceSec struct {
	Name     string `yaml:"name"`
	Timezone string `yaml:"timezone"`
}

type WebSec struct {
	ListenAddress string `yaml:"listen_address"`
	ListenPort    int    `yaml:"listen_port"`
	TLSCertPath   string `yaml:"tls_cert_path"`
	TLSKeyPath    string `yaml:"tls_key_path"`
}

type BlocklistsSec struct {
	StagingDir           string `yaml:"staging_dir"`
	RuntimeDir           string `yaml:"runtime_dir"`
	PullTimeoutSeconds   int    `yaml:"pull_timeout_seconds"`
	SchedulerTickSeconds int    `yaml:"scheduler_tick_seconds"`
	MaxConcurrentPulls   int    `yaml:"max_concurrent_pulls"`
}

type LocalDNSSec struct {
	StagingDir string `yaml:"staging_dir"`
	RuntimeDir string `yaml:"runtime_dir"`
}

type AuthSec struct {
	SessionTTLSeconds             int `yaml:"session_ttl_seconds"`
	LastSeenUpdateIntervalSeconds int `yaml:"last_seen_update_interval_seconds"`
}

// Load reads, strictly parses (unknown fields rejected), and validates path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config (strict, unknown fields rejected): %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.SchemaVersion != CurrentSchemaVersion {
		return fmt.Errorf("unsupported schema_version %d (expected %d)", c.SchemaVersion, CurrentSchemaVersion)
	}
	if c.Web.ListenPort <= 0 || c.Web.ListenPort > 65535 {
		return fmt.Errorf("web.listen_port invalid")
	}
	if c.Blocklists.StagingDir == "" || c.Blocklists.RuntimeDir == "" {
		return fmt.Errorf("blocklists.staging_dir/runtime_dir required")
	}
	if c.Blocklists.PullTimeoutSeconds <= 0 {
		return fmt.Errorf("blocklists.pull_timeout_seconds must be positive")
	}
	if c.Blocklists.SchedulerTickSeconds <= 0 {
		return fmt.Errorf("blocklists.scheduler_tick_seconds must be positive")
	}
	if c.Blocklists.MaxConcurrentPulls <= 0 {
		return fmt.Errorf("blocklists.max_concurrent_pulls must be positive")
	}
	if c.LocalDNS.StagingDir == "" || c.LocalDNS.RuntimeDir == "" {
		return fmt.Errorf("local_dns.staging_dir/runtime_dir required")
	}
	if c.Auth.SessionTTLSeconds <= 0 {
		return fmt.Errorf("auth.session_ttl_seconds must be positive")
	}
	if c.Auth.LastSeenUpdateIntervalSeconds <= 0 {
		return fmt.Errorf("auth.last_seen_update_interval_seconds must be positive")
	}
	return nil
}

func (c *Config) SessionTTL() time.Duration {
	return time.Duration(c.Auth.SessionTTLSeconds) * time.Second
}

func (c *Config) LastSeenUpdateInterval() time.Duration {
	return time.Duration(c.Auth.LastSeenUpdateIntervalSeconds) * time.Second
}

// AtomicWriteYAML marshals v and writes it to path via a temp file +
// rename(2) so a reader never observes a partially-written config.
func AtomicWriteYAML(path string, v any) error {
	out, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".appliance-*.yaml.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
