package hostagentd

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditEntry is one line of the audit log -- every request the agent
// ever receives gets exactly one of these, whether it was authorized,
// rejected, or failed. Detail is operation-supplied and must never
// contain secret material (handlers are responsible for that, the same
// "no secrets in ... logs" requirement the API/UI layers follow).
type AuditEntry struct {
	Time       time.Time `json:"time"`
	Op         string    `json:"op"`
	PeerUID    uint32    `json:"peer_uid"`
	OK         bool      `json:"ok"`
	Detail     string    `json:"detail,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
}

// AuditLog is an append-only JSON-lines file. Never truncated, never
// rewritten -- a real audit trail, not a rotating debug log. (Log
// rotation, if ever wanted, belongs to an external tool like logrotate
// operating on this file, not to this process rewriting its own
// history.)
type AuditLog struct {
	mu   sync.Mutex
	file *os.File
}

func OpenAuditLog(path string) (*AuditLog, error) {
	if dir := parentDir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &AuditLog{file: f}, nil
}

func (a *AuditLog) Record(e AuditEntry) {
	if a == nil || a.file == nil {
		return
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.file.Write(append(line, '\n'))
}

func (a *AuditLog) Close() error {
	if a == nil || a.file == nil {
		return nil
	}
	return a.file.Close()
}
