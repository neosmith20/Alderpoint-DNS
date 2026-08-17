# RC5 hardware/performance spot-check (roadmap Priority 6, current-artifact re-verification)

Per roadmap Priority 5 ("use the NEW artifact for package/performance/
security evidence, do not continue validating an older package"): the
prior full 1 GiB/2 GiB study (`docs/v2/hardware-performance-1g-2g.md`)
was run against an earlier private package, before this session's real
production changes (webapp.py's listener-address fix, migration
filtering fix, replication enrollment/hostname fixes). None of those
changes touch the DNS hot path (`dnsdist`/`named` themselves, or the
compiled runtime's own query-answering logic) -- they're all in the
management API's policy-compile trigger, the migration CLI, and
replication's mTLS setup -- but a spot-check against the exact current
artifact (RC5) is still real evidence, not an assumption.

## Setup

Real 2 GiB `podman --memory` cgroup limit, real `apt-get install` of
RC5 (`sha256:56d21f13...`), real `dnsperf` load generator (a real
package, not simulated), real management HTTPS API calls throughout.

## Results

- **Clean install under the 2 GiB limit**: exit 0, all 8 services +
  the reload path unit active, 0 failed units.
- **Local-DNS fast path** (`perf-local.test` -> real `SpoofAction`,
  matching the prior session's "local-spoof" measurement): `dnsperf
  -c 8 -l 12` -- **146,993 QPS**, **0% loss**, 100% NOERROR, average
  latency **0.657 ms** (min 0.022 ms / max 4.350 ms). Directly
  comparable to and consistent with the prior session's 136k-140k QPS /
  sub-millisecond local-spoof figures -- no regression.
- **Memory**: sampled `memory.current` every 2s throughout the sustained
  run -- steady 569-579 MB, well under the 2 GiB limit, no growth trend
  (plateaued, not climbing), 0 bytes swap pressure observed.
- **Restarts/OOM**: `NRestarts=0` for `alderpointdns-v2-dnsdist`, no
  OOM entries in `dmesg`/`journalctl -k`, no failed units after the run.
- **Management responsiveness immediately after the sustained run**:
  `GET /api/system/status` -> `HTTP 200` in 20 ms.
- **Real-upstream (uncached) path**: a smaller ad-hoc run against
  never-cached `*.example.test` names (real recursive round trips to
  actual root servers) measured ~681 QPS with 3.3% loss at only 4
  concurrent clients and ~22 ms average latency -- not a regression,
  simply a different, network-round-trip-bound workload shape than the
  local-spoof fast path; consistent with the prior session's documented
  uncached p50/p95/p99 figures being an order of magnitude slower than
  the cached/local-spoof paths.

## Not re-covered this pass

The full 1 GiB profile, the packet-cache-hit tier specifically (as
opposed to local-spoof), and Argon2id-under-load were not independently
re-measured against RC5 this pass -- reasonable to skip given they
exercise the same unmodified DNS/auth code paths this session never
touched, and the local-spoof fast-path spot-check above already
confirms no regression in the numbers that would most directly reflect
a change to the hot path.

## Real finding that changes what "combined load" should mean going forward

Attempting to also stress real live analytics ingestion concurrently
with this DNS load (the prior session's own explicit recommendation)
surfaced a more significant, separate finding: **real DNS traffic
through the packaged `dnsdist` runtime is not wired to analytics
ingestion at all** -- see
`docs/v2/analytics-ingestion-not-wired-to-live-dns.md`. Zero Parquet
segments were written despite sustained real query traffic. This is an
existing, already-acknowledged gap in the code's own docstrings, not a
regression, but it means no combined "DNS load + real analytics
backlog" hardware measurement is actually possible yet against real
traffic -- only against synthetic injected events. Recommend
prioritizing that wiring before the next hardware/performance session,
since performance numbers gathered without it are measuring a lighter
real-world load than the appliance will eventually carry.
