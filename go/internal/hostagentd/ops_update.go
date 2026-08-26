// Software Updates, real, for this migration's own Go binary --
// deliberately NOT Python's apt/dpkg package (see PARITY_MATRIX.md's
// Software Updates row for why that's a separate, still-infeasible
// area: installing an arbitrary uploaded .deb is real root package
// management, one of the most destructive-capable actions this
// appliance can take, and stays out of scope here). "Keep Go-owned
// state native" -- this manages the Go control plane's own versioning
// lifecycle: check/stage/apply/rollback for its own binary, with a
// real checksum + self-reported-version verification before trusting a
// staged candidate, and a real health-check-gated rollback if a newly
// applied binary doesn't come back up healthy.
package hostagentd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"alderpointdns/go-controlplane/internal/hostagent"
)

type UpdateConfig struct {
	// CurrentBinaryPath is the live binary this agent will atomically
	// replace on apply.
	CurrentBinaryPath string
	// StagingDir holds a verified-but-not-yet-applied candidate.
	StagingDir string
	// BackupPath is where the pre-update binary is copied before being
	// replaced -- the rollback source.
	BackupPath string
	// VersionOf runs a candidate binary and returns its self-reported
	// version (`<binary> version`) -- exec'd with an explicit argv,
	// never a shell string. Overridable for tests.
	VersionOf func(ctx context.Context, path string) (string, error)
	// Restart actually restarts the live service after a binary swap.
	// Overridable for tests; the real implementation execs `systemctl
	// restart <unit>` with a fixed, configured unit name -- never a
	// caller-supplied one.
	Restart func(ctx context.Context) error
	// HealthCheck reports whether the freshly-restarted service is
	// actually healthy -- real implementation polls the service's own
	// /api/health. Overridable for tests.
	HealthCheck        func(ctx context.Context) (bool, error)
	HealthCheckTimeout time.Duration
}

func DefaultVersionOf(ctx context.Context, path string) (string, error) {
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "", err
	}
	return trimNewline(string(out)), nil
}

func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

type stagedCandidate struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Path    string `json:"-"`
}

type updateState struct {
	mu       sync.Mutex
	staged   *stagedCandidate
	previous string // path to the pre-apply backup, set once an apply has happened
}

func RegisterUpdateOps(s *Server, cfg UpdateConfig) {
	if cfg.VersionOf == nil {
		cfg.VersionOf = DefaultVersionOf
	}
	if cfg.HealthCheckTimeout <= 0 {
		cfg.HealthCheckTimeout = 15 * time.Second
	}
	st := &updateState{}

	s.Register(hostagent.OpUpdateCheck, func(ctx context.Context, params json.RawMessage) (any, error) {
		currentVersion := ""
		if cfg.VersionOf != nil && cfg.CurrentBinaryPath != "" {
			if v, err := cfg.VersionOf(ctx, cfg.CurrentBinaryPath); err == nil {
				currentVersion = v
			}
		}
		st.mu.Lock()
		defer st.mu.Unlock()
		out := map[string]any{"current_version": currentVersion, "staged": nil}
		if st.staged != nil {
			out["staged"] = map[string]any{"version": st.staged.Version, "sha256": st.staged.SHA256}
		}
		return out, nil
	})

	s.Register(hostagent.OpUpdateStage, func(ctx context.Context, params json.RawMessage) (any, error) {
		var in struct {
			ClaimedVersion string `json:"claimed_version"`
			SHA256         string `json:"sha256"`
			DataBase64     string `json:"data_base64"`
		}
		if err := json.Unmarshal(params, &in); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
		if in.ClaimedVersion == "" || in.SHA256 == "" || in.DataBase64 == "" {
			return nil, fmt.Errorf("claimed_version, sha256, and data_base64 are all required")
		}
		data, err := base64.StdEncoding.DecodeString(in.DataBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 payload: %w", err)
		}
		sum := sha256.Sum256(data)
		gotSHA := hex.EncodeToString(sum[:])
		if gotSHA != in.SHA256 {
			return nil, fmt.Errorf("checksum mismatch: expected %s, got %s -- refusing a candidate that doesn't match its own claimed checksum", in.SHA256, gotSHA)
		}

		if err := os.MkdirAll(cfg.StagingDir, 0o750); err != nil {
			return nil, fmt.Errorf("preparing staging directory: %w", err)
		}
		stagedPath := filepath.Join(cfg.StagingDir, "candidate")
		if err := os.WriteFile(stagedPath, data, 0o750); err != nil {
			return nil, fmt.Errorf("writing staged candidate: %w", err)
		}

		// Real self-reported-version verification, not trust-on-claim:
		// exec the staged candidate and require its own `version`
		// subcommand to agree with what the caller claimed before this
		// candidate is ever eligible for apply.
		reportedVersion, err := cfg.VersionOf(ctx, stagedPath)
		if err != nil {
			os.Remove(stagedPath)
			return nil, fmt.Errorf("staged candidate failed to execute (not a valid binary for this platform?): %w", err)
		}
		if reportedVersion != in.ClaimedVersion {
			os.Remove(stagedPath)
			return nil, fmt.Errorf("staged candidate's self-reported version %q does not match the claimed version %q -- refusing", reportedVersion, in.ClaimedVersion)
		}

		st.mu.Lock()
		st.staged = &stagedCandidate{Version: reportedVersion, SHA256: gotSHA, Path: stagedPath}
		st.mu.Unlock()
		return map[string]any{"status": "staged", "version": reportedVersion, "sha256": gotSHA}, nil
	})

	s.Register(hostagent.OpUpdateApply, func(ctx context.Context, params json.RawMessage) (any, error) {
		st.mu.Lock()
		candidate := st.staged
		st.mu.Unlock()
		if candidate == nil {
			return nil, fmt.Errorf("no candidate update is staged")
		}
		if cfg.CurrentBinaryPath == "" || cfg.Restart == nil || cfg.HealthCheck == nil {
			return nil, fmt.Errorf("update.apply is not configured on this agent")
		}

		// Back up the live binary first -- this is the entire rollback
		// mechanism, so it happens before anything else, and its
		// success is required before touching the live binary at all.
		if err := copyFile(cfg.CurrentBinaryPath, cfg.BackupPath); err != nil {
			return nil, fmt.Errorf("backing up the current binary before apply (refusing to proceed without a rollback path): %w", err)
		}

		if err := copyFile(candidate.Path, cfg.CurrentBinaryPath); err != nil {
			return nil, fmt.Errorf("installing the staged candidate: %w", err)
		}

		if err := cfg.Restart(ctx); err != nil {
			// The binary is already swapped but the restart itself
			// failed to even launch -- roll back immediately rather than
			// leaving a candidate installed that never got a chance to
			// prove itself healthy.
			copyFile(cfg.BackupPath, cfg.CurrentBinaryPath)
			cfg.Restart(ctx)
			return nil, fmt.Errorf("restart failed, rolled back: %w", err)
		}

		healthy, healthCtx := false, ctx
		deadline := time.Now().Add(cfg.HealthCheckTimeout)
		for time.Now().Before(deadline) {
			ok, err := cfg.HealthCheck(healthCtx)
			if err == nil && ok {
				healthy = true
				break
			}
			time.Sleep(300 * time.Millisecond)
		}

		if !healthy {
			copyFile(cfg.BackupPath, cfg.CurrentBinaryPath)
			cfg.Restart(ctx)
			st.mu.Lock()
			st.staged = nil
			st.mu.Unlock()
			return nil, fmt.Errorf("new version %s did not become healthy within %s -- automatically rolled back to the previous binary", candidate.Version, cfg.HealthCheckTimeout)
		}

		st.mu.Lock()
		st.staged = nil
		st.previous = cfg.BackupPath
		st.mu.Unlock()
		return map[string]any{"status": "applied", "version": candidate.Version}, nil
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	stat, err := in.Stat()
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, stat.Mode())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst) // atomic replace, matching this codebase's established AtomicWriteYAML/backup-write pattern
}
