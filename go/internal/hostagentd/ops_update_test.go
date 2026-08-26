package hostagentd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildTestBinary compiles a real, tiny throwaway Go program whose only
// job is to print a fixed version string when run with "version" --
// standing in for the real alderpointdns-go binary's own `version`
// subcommand (added alongside this package specifically for this
// verification) so these tests exercise the real
// build-a-binary/checksum/exec/verify pipeline end to end, not a mock.
func buildTestBinary(t *testing.T, version string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available to build a test binary")
	}
	src := filepath.Join(t.TempDir(), "main.go")
	prog := `package main
import ("fmt";"os")
func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" { fmt.Println("` + version + `"); return }
	if len(os.Args) > 1 && os.Args[1] == "fail-to-run" { os.Exit(1) }
}
`
	if err := os.WriteFile(src, []byte(prog), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "testbin")
	cmd := exec.Command("go", "build", "-o", out, src)
	cmd.Env = append(os.Environ(), "GOFLAGS=-buildvcs=false")
	if outb, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build a test binary in this environment: %v: %s", err, outb)
	}
	return out
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestUpdateStageRejectsAChecksumMismatch(t *testing.T) {
	data := []byte("not a real binary")
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterUpdateOps(s, UpdateConfig{StagingDir: t.TempDir()})
	_, err := s.handlers["update.stage"](context.Background(), json.RawMessage(`{
		"claimed_version":"1.2.3","sha256":"0000000000000000000000000000000000000000000000000000000000000000",
		"data_base64":"`+base64.StdEncoding.EncodeToString(data)+`"}`))
	if err == nil {
		t.Fatal("expected a checksum mismatch to be rejected")
	}
}

func TestUpdateStageRejectsAVersionMismatch(t *testing.T) {
	bin := buildTestBinary(t, "real-version-9.9.9")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterUpdateOps(s, UpdateConfig{StagingDir: t.TempDir()})
	params, _ := json.Marshal(map[string]string{
		"claimed_version": "a-different-version", // deliberately wrong
		"sha256":          sha256Hex(data),
		"data_base64":     base64.StdEncoding.EncodeToString(data),
	})
	_, err = s.handlers["update.stage"](context.Background(), params)
	if err == nil {
		t.Fatal("expected a claimed-vs-actual version mismatch to be rejected")
	}
}

func TestUpdateStageAcceptsARealVerifiedBinary(t *testing.T) {
	bin := buildTestBinary(t, "real-version-1.0.0")
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterUpdateOps(s, UpdateConfig{StagingDir: t.TempDir()})
	params, _ := json.Marshal(map[string]string{
		"claimed_version": "real-version-1.0.0",
		"sha256":          sha256Hex(data),
		"data_base64":     base64.StdEncoding.EncodeToString(data),
	})
	result, err := s.handlers["update.stage"](context.Background(), params)
	if err != nil {
		t.Fatalf("expected a genuinely matching binary to stage successfully, got: %v", err)
	}
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), "real-version-1.0.0") {
		t.Fatalf("expected the verified version in the result, got %s", encoded)
	}
}

func TestUpdateCheckReportsCurrentAndStagedVersions(t *testing.T) {
	currentBin := buildTestBinary(t, "current-version-1")
	candidateBin := buildTestBinary(t, "candidate-version-2")
	data, _ := os.ReadFile(candidateBin)

	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterUpdateOps(s, UpdateConfig{CurrentBinaryPath: currentBin, StagingDir: t.TempDir()})

	before, err := s.handlers["update.check"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	beforeJSON, _ := json.Marshal(before)
	if !strings.Contains(string(beforeJSON), "current-version-1") || !strings.Contains(string(beforeJSON), `"staged":null`) {
		t.Fatalf("expected current version reported and nothing staged, got %s", beforeJSON)
	}

	params, _ := json.Marshal(map[string]string{"claimed_version": "candidate-version-2", "sha256": sha256Hex(data), "data_base64": base64.StdEncoding.EncodeToString(data)})
	if _, err := s.handlers["update.stage"](context.Background(), params); err != nil {
		t.Fatal(err)
	}
	after, err := s.handlers["update.check"](context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	afterJSON, _ := json.Marshal(after)
	if !strings.Contains(string(afterJSON), "candidate-version-2") {
		t.Fatalf("expected the staged candidate's version to be reported, got %s", afterJSON)
	}
}

func TestUpdateApplyRealBinarySwapWithSuccessfulHealthCheck(t *testing.T) {
	currentBin := buildTestBinary(t, "old-version")
	candidateSrcBin := buildTestBinary(t, "new-version")
	data, _ := os.ReadFile(candidateSrcBin)

	backupPath := filepath.Join(t.TempDir(), "backup")
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	restartCalled := false
	RegisterUpdateOps(s, UpdateConfig{
		CurrentBinaryPath: currentBin, StagingDir: t.TempDir(), BackupPath: backupPath,
		Restart:     func(ctx context.Context) error { restartCalled = true; return nil },
		HealthCheck: func(ctx context.Context) (bool, error) { return true, nil }, // simulates the new version coming up healthy
	})

	params, _ := json.Marshal(map[string]string{"claimed_version": "new-version", "sha256": sha256Hex(data), "data_base64": base64.StdEncoding.EncodeToString(data)})
	if _, err := s.handlers["update.stage"](context.Background(), params); err != nil {
		t.Fatal(err)
	}
	result, err := s.handlers["update.apply"](context.Background(), nil)
	if err != nil {
		t.Fatalf("expected apply to succeed, got: %v", err)
	}
	encoded, _ := json.Marshal(result)
	if !strings.Contains(string(encoded), "new-version") {
		t.Fatalf("expected the new version in the apply result, got %s", encoded)
	}
	if !restartCalled {
		t.Fatal("expected Restart to have been called")
	}

	// The live "binary" must now really be the new version.
	out, err := exec.Command(currentBin, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(out)) != "new-version" {
		t.Fatalf("expected the live binary to actually be swapped to the new version, got %q", out)
	}
	// And a real backup of the old one must exist.
	backupOut, err := exec.Command(backupPath, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(backupOut)) != "old-version" {
		t.Fatalf("expected a real backup of the old binary, got %q", backupOut)
	}
}

func TestUpdateApplyRollsBackOnFailedHealthCheck(t *testing.T) {
	currentBin := buildTestBinary(t, "old-version")
	candidateSrcBin := buildTestBinary(t, "bad-version")
	data, _ := os.ReadFile(candidateSrcBin)

	backupPath := filepath.Join(t.TempDir(), "backup")
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	restartCount := 0
	RegisterUpdateOps(s, UpdateConfig{
		CurrentBinaryPath: currentBin, StagingDir: t.TempDir(), BackupPath: backupPath,
		Restart:            func(ctx context.Context) error { restartCount++; return nil },
		HealthCheck:        func(ctx context.Context) (bool, error) { return false, nil }, // the new version never becomes healthy
		HealthCheckTimeout: 500 * time.Millisecond,
	})

	params, _ := json.Marshal(map[string]string{"claimed_version": "bad-version", "sha256": sha256Hex(data), "data_base64": base64.StdEncoding.EncodeToString(data)})
	if _, err := s.handlers["update.stage"](context.Background(), params); err != nil {
		t.Fatal(err)
	}
	_, err := s.handlers["update.apply"](context.Background(), nil)
	if err == nil {
		t.Fatal("expected apply to report failure when the health check never passes")
	}
	if !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected the error to mention rollback, got: %v", err)
	}

	// The live binary must be back to the original version, not stuck
	// on the unhealthy candidate.
	out, execErr := exec.Command(currentBin, "version").Output()
	if execErr != nil {
		t.Fatal(execErr)
	}
	if strings.TrimSpace(string(out)) != "old-version" {
		t.Fatalf("expected automatic rollback to restore the original binary, got %q", out)
	}
	if restartCount < 2 {
		t.Fatalf("expected Restart to be called for both the failed apply and the rollback, got %d calls", restartCount)
	}
}

func TestUpdateApplyWithNothingStagedIsRejected(t *testing.T) {
	s := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	RegisterUpdateOps(s, UpdateConfig{})
	_, err := s.handlers["update.apply"](context.Background(), nil)
	if err == nil {
		t.Fatal("expected an error when nothing is staged")
	}
}
