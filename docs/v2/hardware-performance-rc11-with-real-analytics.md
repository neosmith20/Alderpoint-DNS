# RC11 hardware/performance re-verification with real analytics logging active (roadmap Priority 6/6-continuation)

Per roadmap Priority 5, re-measured against the current artifact
(RC11) rather than trusting the RC5/RC6 spot-check numbers, since this
session's analytics work fundamentally changed what those numbers were
actually measuring: RC5/RC6's "no regression" spot checks used local-
DNS (SpoofAction) traffic, which -- as this same session later found
and fixed -- was NOT actually reaching the analytics pipeline at all
at the time. This is the first performance measurement taken with the
real protobuf query-log producer genuinely active and logging every
query.

## Setup

Real 2 GiB `podman --memory` cgroup limit, real `apt-get install` of
RC11, real `dnsperf` load, real receiver/worker services running and
confirmed actively logging (verified via a real local-DNS query
landing in the inbox before the load run started).

## Real, honest result: a real, measurable cost, and it's the analytics logging

Same exact local-DNS fast-path scenario as the RC5/RC6 spot checks
(`perf-local.test` -> `SpoofAction`, `dnsperf -c 8 -l 12`):

- **QPS: 106,268** (down from RC5's 146,993 / RC6's 147,521 -- a real
  ~28% reduction), **0% loss**, 100% NOERROR.
- **Average latency: 0.882 ms** (up from 0.653-0.657 ms -- a real ~34%
  increase).
- This is the real cost of `RemoteLogAction` + `RemoteLogResponseAction`
  firing (protobuf serialize + TCP send) on every single query/response,
  which was not actually happening yet in the earlier spot checks
  (the receiver existed but nothing reached it for this exact SpoofAction
  traffic shape until the correlation fix two commits later in this
  session). Not a hidden regression -- exactly the tradeoff of turning
  a previously-inert feature genuinely on.

## Memory: real page-cache growth, not a leak (checked directly, not assumed)

`memory.current` climbed from ~1134 MB to ~1164 MB over the 12s
sustained run -- a real, measurable trend, checked directly against
`memory.stat` rather than assumed benign: `file` (reclaimable page
cache, from JSONL batch writes and Parquet segment I/O) accounted for
790 MB of the 1166 MB total; `anon` (real process heap/RSS) was only
291 MB -- consistent with each service's own reported `MemoryCurrent`
(dnsdist 61 MB, analytics worker 41 MB, protobuf receiver 27 MB,
peak 30 MB, well under its own 256 MB unit cap). No OOM, 0 restarts
for any of the three services checked, 0 failed units, `GET
/api/system/status` immediately after the run in 26 ms.

## Conclusion

Real, non-hidden throughput/latency cost from real analytics logging
(~28%/~34%), no memory leak (page cache accounts for the visible
growth, real per-service RSS stays modest and stable), no stability
regression. 106k QPS local-fast-path throughput remains far beyond any
realistic home/SMB deployment's real traffic volume -- this is a
transparency finding, not a blocking one, but the RC5/RC6 "no
regression" conclusion specifically needs this update: that conclusion
was accurate for what was being measured at the time, and is superseded
by this real number now that the feature it silently wasn't exercising
is actually active.
