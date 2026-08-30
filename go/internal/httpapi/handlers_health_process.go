package httpapi

// Real process memory/goroutine visibility on GET /api/health -- added
// 2026-08-29 after a genuine, previously-unmonitored live incident: the
// web container's own RSS grew to ~2.9GB (from a normal ~20MB idle
// baseline) over about two hours and was SIGKILL'd by the kernel OOM
// killer, with nothing in this appliance's own telemetry able to show
// that growth happening in the first place -- an operator (or a future
// diagnosis session) had no way to see it coming. This is deliberately
// informational only (never demotes overall health status): there is
// no validated "this RSS means something is wrong" threshold yet, and a
// naive one would risk false alarms on a host already under real,
// legitimate memory pressure from unrelated processes (this appliance
// shares its host with build/test tooling in this environment). See
// AGENT_PROGRESS.md's 2026-08-29 OOM-incident entry for the
// investigation this closes the visibility gap for.
import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

type processStats struct {
	GoroutineCount int    `json:"goroutine_count"`
	HeapAllocBytes uint64 `json:"heap_alloc_bytes"`
	HeapSysBytes   uint64 `json:"heap_sys_bytes"`
	HeapObjects    uint64 `json:"heap_objects"`
	NumGC          uint32 `json:"num_gc"`
	// RSSBytes is read directly from /proc/self/status (Linux-only,
	// which every real deployment of this appliance is) rather than
	// derived from runtime.MemStats -- it's the actual figure the
	// kernel OOM killer scores against (goroutine stacks, non-Go
	// allocations, and pages Go's own runtime has freed but not yet
	// returned to the OS all count toward it, none of which
	// HeapAlloc/HeapSys alone would show). 0 if unreadable (e.g. a
	// non-Linux dev environment, or /proc unavailable) -- never a hard
	// error for the rest of /api/health.
	RSSBytes uint64 `json:"rss_bytes,omitempty"`
}

func currentProcessStats() processStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	out := processStats{
		GoroutineCount: runtime.NumGoroutine(),
		HeapAllocBytes: m.HeapAlloc,
		HeapSysBytes:   m.HeapSys,
		HeapObjects:    m.HeapObjects,
		NumGC:          m.NumGC,
	}
	if rss, ok := readSelfRSS(); ok {
		out.RSSBytes = rss
	}
	return out
}

// readSelfRSS reads VmRSS from /proc/self/status, in bytes. Returns
// ok=false (never a panic or error the caller must handle) if /proc
// isn't present or the expected line isn't found -- this is a
// best-effort diagnostic, not a required dependency.
func readSelfRSS() (uint64, bool) {
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
