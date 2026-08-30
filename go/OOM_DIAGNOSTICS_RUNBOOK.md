# OOM / memory-growth diagnostics runbook

Written 2026-08-29 after a real live incident: `apdns-go-live`'s RSS grew
from a normal ~20-40MB idle baseline to ~2.9GB over about two hours and
was SIGKILL'd by the kernel OOM killer. The exact leaking code path was
**not** conclusively identified that session (see `PARITY_MATRIX.md`'s
Backup & Restore-adjacent history and the OOM-incident entries in
`AGENT_PROGRESS.md` for the full investigation). This doc is what the
*next* recurrence needs so it can be pinned down for real, plus the
guards already in place so a recurrence never causes another
unattended, human-noticed-it-eventually outage.

## What's already guarding against a repeat

- `scripts/v2/redeploy-go-live.sh` runs the container with
  `--memory=768m --memory-swap=768m` (contains a leak to this one
  container, not the whole host) and `--restart=on-failure:5` (an
  OOM-kill auto-recovers in seconds, not whenever a human happens to
  notice) plus a real `--health-cmd` against `/api/health` with
  `--health-on-failure=restart`.
- `GET /api/health` carries a `process` component: `goroutine_count`,
  `heap_alloc_bytes`, `heap_sys_bytes`, `heap_objects`, `num_gc`, and
  real `rss_bytes` read from `/proc/self/status`. Check this first, no
  special access needed:

  ```sh
  curl -sk https://127.0.0.1:8443/api/health | python3 -m json.tool | grep -A8 '"process"'
  ```

- A background memory watchdog (`cmd/alderpointdns-go/memwatch.go`)
  logs a real `WARN` line (`"memory watchdog: RSS crossed the warning
  threshold"`) the moment RSS crosses 300MB (well below the 768MB
  container cap, well above the real ~20-40MB baseline), and an `INFO`
  line if it ever recovers back below. Check the container's own logs
  for this line first if you suspect growth in progress:

  ```sh
  podman logs apdns-go-live 2>&1 | grep "memory watchdog"
  ```

## If RSS starts climbing again: capture a real profile

The web binary ships an **opt-in, disabled-by-default** pprof endpoint
(`-debug-pprof-addr`, `net/http/pprof`) specifically for this. It is a
separate, unauthenticated listener from the main `:8443` one -- never
enable it bound to anything but loopback, and never leave it running
longer than the diagnostic session needs.

### 1. Enable it for one redeploy

Edit `scripts/v2/redeploy-go-live.sh`'s own `podman create` invocation
(the block with `-dns-runtime-tls-key-path ... \` near the end of the
`web` command) and add, right before `-addr 0.0.0.0:8443 \`:

```
    -debug-pprof-addr 0.0.0.0:6061 \
```

and add a loopback-only host port publish next to the existing
`-p 8443:8443` line:

```
    -p 127.0.0.1:6061:6061 \
```

`127.0.0.1:6061:6061` binds the HOST side to loopback only -- nothing
outside this machine can ever reach it, matching the flag's own doc
comment ("never bind this to a publicly-reachable address"). Re-run the
redeploy script as usual (DNS-continuity-monitored, same as any other
redeploy).

### 2. Let it run until RSS is visibly elevated again

Watch `/api/health`'s `process.rss_bytes` (or the memory watchdog's own
log line above) climb past the normal baseline before capturing --
a profile taken while RSS is still small won't show the growth.

### 3. Capture profiles

From the host (not inside the container -- the port is published to the
host's own loopback):

```sh
# Heap: what's currently allocated and NOT yet garbage collected --
# the single most useful profile for "what's leaking".
curl -s http://127.0.0.1:6061/debug/pprof/heap -o /tmp/heap.pprof

# Goroutines: a real leak often shows as thousands of stuck goroutines
# all blocked in the same place (e.g. a stalled dnstap connection read
# that never unblocks) -- this is usually the FASTEST way to find the
# actual leaking code path.
curl -s http://127.0.0.1:6061/debug/pprof/goroutine -o /tmp/goroutine.pprof

# Allocs: cumulative allocation profile since the process started --
# useful for "what's been allocated the most over time", complementary
# to the heap snapshot above.
curl -s http://127.0.0.1:6061/debug/pprof/allocs -o /tmp/allocs.pprof
```

### 4. Analyze

```sh
# Interactive text UI, ranked by cumulative bytes:
go tool pprof -top -cum /tmp/heap.pprof

# A real leak often shows up immediately as a huge goroutine count with
# many stuck in the same stack trace:
go tool pprof -top /tmp/goroutine.pprof

# A visual call graph (needs graphviz -- apt-get install graphviz):
go tool pprof -svg /tmp/heap.pprof > /tmp/heap.svg
```

Compare a heap profile taken early (low RSS) against one taken once RSS
is elevated (`go tool pprof -base /tmp/heap-early.pprof /tmp/heap-later.pprof`)
to isolate exactly what grew, not just what's currently large.

### 5. Turn pprof back off

Revert the two lines added in step 1 and redeploy again -- this flag and
port publish should never be left enabled on the live appliance outside
an active diagnostic session.

## Known leading suspect (not yet confirmed)

`internal/dnsanalytics.Writer`'s dnstap ingestion path (`writer.go`) is
the only always-running, traffic-adjacent background loop in the
process, and its own doc comment already discloses a real, previously
found issue: dnsdist's fstrm connection to it can go silently idle. The
watchdog there force-closes a stalled connection to trigger a real
reconnect -- if that reconnect cycle happens many times without the
old connection's own goroutine ever cleanly exiting, each cycle could
leak a per-connection goroutine + its read buffer. This was **not**
conclusively reproduced live in the 2026-08-29 investigation (the
numbers didn't obviously add up to gigabytes from that alone). If a
`goroutine.pprof` capture during a real recurrence shows a large count
of goroutines stuck in `dnstap.(*FrameStreamInput).ReadInto` or
similar, that confirms this suspicion -- otherwise, look elsewhere.
