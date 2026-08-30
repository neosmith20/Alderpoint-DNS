package replication

import (
	"context"
	"fmt"
	"strconv"
)

// Settings mirrors Python's own replication_settings key/value shape --
// a real, typed struct instead of Python's bare dict, but the same
// fields, same defaults, same meanings.
type Settings struct {
	NodeID                    string `json:"node_id"`
	Role                      string `json:"role"`
	ListenHost                string `json:"listen_host"`
	ListenPort                int    `json:"listen_port"`
	PollIntervalSeconds       int    `json:"poll_interval_seconds"`
	PrimaryAddress            string `json:"primary_address"`
	Paused                    bool   `json:"paused"`
	IncludeEncryptionSettings bool   `json:"include_encryption_settings"`
	LastAppliedGeneration     int64  `json:"last_applied_generation"`
	LastAppliedHash           string `json:"last_applied_hash"`
	LastSyncStatus            string `json:"last_sync_status"`
	LastSyncAt                string `json:"last_sync_at"`
	DriftDetected             bool   `json:"drift_detected"`
	DriftCheckedAt            string `json:"drift_checked_at"`
	CACertPEM                 string `json:"-"` // never serialized -- public but not part of the owner-facing settings shape
	CAKeyCiphertextB64        string `json:"-"`
	CAKeyNonceB64             string `json:"-"`
	CAKeyVersion              int    `json:"-"`
}

func boolFromStr(s string) bool { return s == "1" }
func strFromBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
func intFromStr(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// GetSettings loads every real stored setting, generating and
// persisting a node_id the first time this is ever called on a fresh
// database -- matching Python's own settings()/node_id() "created on
// first access, never regenerated after" contract.
func (s *Service) GetSettings(ctx context.Context) (Settings, error) {
	if err := s.ensureNodeID(ctx); err != nil {
		return Settings{}, err
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT key, value FROM replication_settings`)
	if err != nil {
		return Settings{}, err
	}
	defer rows.Close()
	raw := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return Settings{}, err
		}
		raw[k] = v
	}
	out := Settings{
		NodeID: raw["node_id"], Role: raw["role"], ListenHost: raw["listen_host"],
		ListenPort: intFromStr(raw["listen_port"]), PollIntervalSeconds: intFromStr(raw["poll_interval_seconds"]),
		PrimaryAddress: raw["primary_address"], Paused: boolFromStr(raw["paused"]),
		IncludeEncryptionSettings: boolFromStr(raw["include_encryption_settings"]),
		LastAppliedGeneration:     int64(intFromStr(raw["last_applied_generation"])),
		LastAppliedHash:           raw["last_applied_hash"], LastSyncStatus: raw["last_sync_status"],
		LastSyncAt: raw["last_sync_at"], DriftDetected: boolFromStr(raw["drift_detected"]),
		DriftCheckedAt: raw["drift_checked_at"], CACertPEM: raw["ca_cert_pem"],
		CAKeyCiphertextB64: raw["ca_key_ciphertext_b64"], CAKeyNonceB64: raw["ca_key_nonce_b64"],
		CAKeyVersion: intFromStr(raw["ca_key_version"]),
	}
	if out.Role == "" {
		out.Role = "standalone"
	}
	if out.ListenHost == "" {
		out.ListenHost = "0.0.0.0"
	}
	if out.ListenPort == 0 {
		out.ListenPort = DefaultListenPort
	}
	if out.PollIntervalSeconds == 0 {
		out.PollIntervalSeconds = DefaultPollIntervalSec
	}
	return out, nil
}

func (s *Service) ensureNodeID(ctx context.Context) error {
	var existing string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM replication_settings WHERE key='node_id'`).Scan(&existing)
	if err == nil && existing != "" {
		return nil
	}
	id, genErr := newNodeID()
	if genErr != nil {
		return genErr
	}
	_, err = s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO replication_settings (key, value) VALUES ('node_id', ?)`, id)
	return err
}

func (s *Service) setSetting(ctx context.Context, key, value string) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO replication_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

// UpdateSettings persists an arbitrary subset of the owner-editable
// settings -- role changes go through SetRole instead, which also
// starts/stops the real listener/poller.
func (s *Service) UpdateSettings(ctx context.Context, listenHost string, listenPort, pollIntervalSeconds int, includeEncryptionSettings bool) error {
	if listenPort < 1 || listenPort > 65535 {
		return fmt.Errorf("%w: listen_port must be 1-65535", ErrValidation)
	}
	if pollIntervalSeconds < 5 || pollIntervalSeconds > 3600 {
		return fmt.Errorf("%w: poll_interval_seconds must be 5-3600", ErrValidation)
	}
	for k, v := range map[string]string{
		"listen_host": listenHost, "listen_port": strconv.Itoa(listenPort),
		"poll_interval_seconds": strconv.Itoa(pollIntervalSeconds), "include_encryption_settings": strFromBool(includeEncryptionSettings),
	} {
		if err := s.setSetting(ctx, k, v); err != nil {
			return err
		}
	}
	// If the listener is already running (as primary), restart it so a
	// changed listen_host/port takes effect immediately -- otherwise an
	// owner who sets the role to primary first (starting the listener
	// on whatever the default was) and only then edits the listen
	// address would find the real listener silently still bound to the
	// stale address until an unrelated action happened to restart it.
	if s.ListenerRunning() {
		s.StopPrimaryListener()
		return s.StartPrimaryListener(ctx)
	}
	return nil
}

func (s *Service) SetPaused(ctx context.Context, paused bool) error {
	return s.setSetting(ctx, "paused", strFromBool(paused))
}
