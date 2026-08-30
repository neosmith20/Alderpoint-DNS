// Real memory-growth visibility, added 2026-08-29 after a live OOM
// incident (see go/AGENT_PROGRESS.md and go/OOM_DIAGNOSTICS_RUNBOOK.md)
// where the web process's RSS grew from a normal ~20-40MB idle baseline
// to ~2.9GB over about two hours with nothing in this appliance's own
// logs able to show that growth happening. This closes that gap with a
// deliberately simple, edge-detected watchdog -- the same fire-once-per-
// transition discipline internal/notifications' own health checks
// already use, so a real leak logs exactly one WARN when it crosses the
// threshold and one INFO if it ever drops back below, never one line
// per tick for an ongoing condition.
//
// Never logs anything secret: the only values ever written are process
// RSS in bytes and a fixed threshold, both plain integers.
package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// memWatchThresholdBytes is deliberately well below the live deployment's
// own container --memory=768m cap (see scripts/v2/redeploy-go-live.sh)
// but comfortably above the real, measured idle baseline (~20-40MB) --
// early warning long before a container-level OOM kill would trigger,
// not a duplicate of it.
const memWatchThresholdBytes = 300 * 1024 * 1024 // 300MB

func readRSSBytes() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// runMemoryWatchdog polls RSS on a fixed tick and logs a real WARN once
// when it crosses memWatchThresholdBytes (and once, at INFO, if it ever
// recovers below it) -- never a hard error, never a restart trigger of
// its own (the container-level --memory limit + --restart policy
// already own that; see OOM_DIAGNOSTICS_RUNBOOK.md for what an operator
// should actually DO when this fires).
func runMemoryWatchdog(ctx context.Context, logger *slog.Logger, tick time.Duration) {
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	above := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rss, ok := readRSSBytes()
			if !ok {
				continue // best-effort only -- see readRSSBytes' own doc comment on non-Linux/no-/proc environments
			}
			nowAbove := rss > memWatchThresholdBytes
			if nowAbove && !above {
				logger.Warn("memory watchdog: RSS crossed the warning threshold",
					"rss_bytes", rss, "threshold_bytes", uint64(memWatchThresholdBytes),
					"hint", "see OOM_DIAGNOSTICS_RUNBOOK.md for how to capture a heap profile now, while it's still elevated")
			} else if !nowAbove && above {
				logger.Info("memory watchdog: RSS recovered back below the warning threshold", "rss_bytes", rss)
			}
			above = nowAbove
		}
	}
}
