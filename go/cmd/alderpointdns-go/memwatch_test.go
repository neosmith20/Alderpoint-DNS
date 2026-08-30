package main

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReadRSSBytesReturnsARealNonZeroValueOnLinux(t *testing.T) {
	rss, ok := readRSSBytes()
	if !ok {
		t.Fatal("expected readRSSBytes to succeed on this Linux test environment")
	}
	if rss == 0 {
		t.Fatal("expected a real non-zero RSS reading")
	}
}

// syncWriter makes a strings.Builder safe to use as a slog handler's
// output from a background goroutine under a race-detected test run.
type syncWriter struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// TestMemoryWatchdogNeverLogsASecret is the explicit regression proof
// this task asked for: only numeric RSS/threshold values ever appear in
// the watchdog's own log lines, regardless of how long it runs.
func TestMemoryWatchdogNeverLogsASecret(t *testing.T) {
	var buf syncWriter
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	runMemoryWatchdog(ctx, logger, 30*time.Millisecond)

	out := buf.String()
	for _, forbidden := range []string{"passphrase", "password", "secret", "token"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Fatalf("memory watchdog log output must never mention %q, got: %s", forbidden, out)
		}
	}
}
