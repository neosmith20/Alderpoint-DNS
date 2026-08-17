# V2 hardware/performance testing: 1 GiB / 2 GiB (roadmap Priority 3)

Real installed `alderpointdns-v2` package, exercised via real HTTP/HTTPS
API calls and real UDP DNS queries (`dnsperf`), inside a fresh
`apdns-v2-4c-accept-base:trixie` container on this session's real KVM
host, memory-constrained with `podman run --memory=1g|2g
--memory-swap=<same>` (a real cgroup `memory.max`, verified by reading
`/sys/fs/cgroup/memory.max` inside the container before testing).

## Host physical memory

This host has ~3.8-4.0 GiB total physical RAM (`free -h`,
`/proc/meminfo`). A genuinely *isolated* 4 GiB constrained profile is not
physically possible here (it would leave ~0 headroom for the host OS,
podman itself, and this session's tooling) -- consistent with prior
sessions' documented limitation. Not fabricated; 1 GiB and 2 GiB are both
real, comfortably below total host capacity.

## Real defect found and fixed during this testing

Adding 50 local DNS records back-to-back through the real, working
`/api/local-dns` endpoint (a completely ordinary bulk-import workflow,
not an edge case) reproduced a serious defect: **systemd's default
per-unit start-rate limit** (`DefaultStartLimitIntervalSec=10s` /
`DefaultStartLimitBurst=5`) applied to
`alderpointdns-v2-dnsdist-reload.service` (each local-DNS creation
independently stages/validates/promotes the compiled runtime, and the
promoted-file-changed `.path` unit restarts the live `dnsdist` process
once per promotion). After the 5th rapid reload, the reload `.service`
*and* the `.path` unit watching it both went to `failed
(Result: unit-start-limit-hit)` -- permanently, with no automatic
recovery -- so every local-DNS record added after the 5th silently never
took effect on the live server, while the API kept returning `200
"promoted"` for every single one. Direct query test: `host1.lan`
through `host5.lan` resolved; `host6.lan` through `host50.lan` all
returned `NXDOMAIN` despite being correctly present in `control.db` and
correctly compiled into the (unloaded) `dnsdist.conf` on disk.

Fixing only the reload unit's rate limit surfaced the identical failure
one layer deeper: `alderpointdns-v2-dnsdist.service` itself (the actual
DNS server process, restarted by the reload unit) has the same default
systemd limit, so raising just the reload unit's limit let all 50
restarts fire back-to-back and hit *dnsdist's own* start-limit instead --
taking live DNS answering down completely
(`failed (Result: start-limit-hit)`), which is strictly worse than the
original symptom.

Fixed by raising both units' `StartLimitIntervalSec`/`StartLimitBurst` to
a generous-but-still-bounded `60s` / `200` (not disabling the limit
outright, so a genuine runaway-restart bug still has a backstop) --
`packaging/v2/alderpointdns-v2-dnsdist-reload.service`,
`packaging/v2/alderpointdns-v2-dnsdist-reload.path`,
`packaging/v2/alderpointdns-v2-dnsdist.service`. Rebuilt and re-verified
across three package revisions until the exact same 50-record burst left
all three units `active` and all 50 records resolved
(`ok: 50 fail: 0`):

- private8 (pre-existing state, not yet retested against this defect)
- private9 (reload units fixed only) -- confirmed the deeper `dnsdist.service`
  failure
- **private10** (both units fixed) -- confirmed correct: `50/50` local
  DNS records resolve after the identical burst, all three units stay
  `active`

Current artifact for hardware/performance results below:
`alderpointdns-v2_2.0.0~private10-1_all.deb`,
SHA-256 `3bfda1f668c1a9f5d7f6efdc8b44656bc9bd75b69fe90e979a91bee426b5f552`.

Not fully solved architecturally: this still means every single small
runtime change causes a real (if now sub-second and non-fatal) full
`dnsdist` process restart, which is a live DNS availability blip each
time -- a debounced/coalesced reload (or a live-reconfiguration mechanism
that doesn't require a process restart at all) would be a real
improvement but is a larger architectural change than a rate-limit fix;
noted as a follow-up, not attempted this session.

## Test procedure (per profile)

1. Fresh container, real cgroup memory limit verified.
2. `apt-get install dnsperf <the .deb>` -- real package install.
3. Bootstrap first admin via `/api/setup`, log in via `/api/login`.
4. Burst-add 50 local DNS records via `/api/local-dns` (also the defect
   regression check).
5. `dnsperf` against three query shapes:
   - **local-spoof**: repeated queries against the 50 local DNS records
     (terminal `SpoofAction`, answered before any upstream/cache
     involvement).
   - **cache-hit**: repeated queries against 5 fixed real domains, warmed
     first so the packet cache is populated before measurement.
   - **uncached**: 1000 globally-unique subdomains (`uuid4().hex`), each
     forcing a real upstream query (real, live outbound network was
     available in this environment).
6. Sustained throughput run: 200,000-query file over the 5 cache-hit
   domains, `-c 20 -T 4 -l 15` (20 clients, 4 threads, 15s), with memory
   sampled from the host every 2.5s during the run.
7. Per-service `MemoryCurrent`/`NRestarts` and `dmesg`/`journalctl -k`
   OOM check taken after each load run.

This architecture has no separate "BIND recursive-cache" tier to
measure: `bind9-utils` is installed only for `named-checkzone` static
zone-file validation at compile time; no BIND process runs as part of the
live DNS answer path in the current design (confirmed: no
`alderpointdns-v2-bind*` unit exists, and `dnsdist_policy_runtime.py`'s
own docstring documents the real answer path as
client -> dnsdist policy/cache/upstream, with BIND only optionally in the
picture as an upstream a policy could point at, not exercised here). The
two real tiers this architecture actually has are dnsdist's own
per-effective-policy packet cache (**cache-hit**) and a live upstream
query (**uncached**), plus the local-DNS **spoof** tier that bypasses
both.

## Results: 2 GiB profile

- **Memory**: steady ~800-819 MB cgroup `memory.current` during a
  15s/2.05M-query sustained run (well under the 2 GiB limit); 0 bytes
  swap used throughout. Per-service `MemoryCurrent` after load: web 57
  MB, dnsdist 63 MB, each of the 6 lean background workers ~20 MB
  (analytics/tierb/schedule/discovery/dns-observer/replication) -- sum
  ≈242 MB actual service RSS, well below the aggregate cgroup figure
  (which also includes dnsperf's own client-side process and page
  cache/apt artifacts from the install step).
- **CPU/restarts/OOM**: 0 service restarts (`NRestarts=0` for all 8
  measured units), no OOM events in `dmesg`/`journalctl -k`.
- **Sustained throughput**: 136,586 QPS over 15s (2,048,883 queries,
  0 lost, 100% NOERROR).
- **DNS latency** (single-client, `-c 1`, so this measures answer latency
  itself, not queueing under concurrency):
  - local-spoof: p50 0.483 ms / p95 0.987 ms / p99 3.567 ms
  - packet-cache-hit: p50 0.446 ms / p95 0.873 ms / p99 25.257 ms
  - uncached (real upstream): p50 17.474 ms / p95 107.596 ms / p99 350.801 ms
- **Management responsiveness under load**: not separately re-measured
  at 2 GiB (measured at 1 GiB below); services stayed active and correct
  throughout.

## Results: 1 GiB profile

- **Memory**: steady ~807-827 MB `memory.current` during the same
  15s/2.10M-query sustained run, comfortably under the 1 GiB (1073 MB)
  limit; 0 bytes swap. Per-service `MemoryCurrent` after load:
  essentially identical to the 2 GiB profile (web 57 MB, dnsdist 62 MB,
  workers ~20 MB each) -- the appliance's actual footprint does not grow
  with the available headroom, as expected.
- **CPU/restarts/OOM**: 0 restarts, no OOM events.
- **Sustained throughput**: 139,886 QPS over 15s (2,098,377 queries,
  0 lost, 100% NOERROR) -- statistically the same as the 2 GiB profile;
  memory headroom was not the bottleneck at either size for this
  workload.
- **DNS latency**:
  - local-spoof: p50 0.313 ms / p95 0.586 ms / p99 0.678 ms
  - uncached (real upstream): p50 26.273 ms / p95 195.356 ms / p99 318.814 ms
  - (cache-hit tier not independently re-measured at 1 GiB; the
    sustained-throughput run above is itself a cache-hit-dominated
    workload at 1 GiB and shows no degradation vs. 2 GiB.)
- **Management responsiveness under load**: `GET /api/system/status`
  immediately after the sustained 140k-QPS run returned `HTTP 200` in
  88 ms.

## Supported-minimum conclusion

Evidence from this session does not show 1 GiB or 2 GiB under meaningful
stress for this workload shape (DNS traffic at real sustained ~140k QPS,
management API, all 8 background workers running, a 50-record local-DNS
burst). Both profiles: zero OOM, zero restarts, zero swap, sub-second
management responsiveness, no DNS query loss. The appliance's actual
combined service RSS (~240 MB) leaves substantial headroom at both
1 GiB and 2 GiB for this specific test shape.

This session's test did **not** include: DuckDB/Parquet aggregate-query
load, analytics backlog under a sustained high-cardinality query stream
(the dns-observer ingestion path specifically, as opposed to dnsdist
itself), Tier B prewarm running concurrently with DNS load, or replication
traffic -- all real components that were *running* throughout (confirmed
active, 0 restarts) but not independently *stressed*. The previous
session's hypothesis (2 GiB minimum / 4 GiB recommended) is **not
contradicted** by this evidence, but this evidence alone does not by
itself justify lowering the minimum below 2 GiB either, given the
untested components above -- recommend the next session specifically
stress analytics ingestion + DuckDB aggregate queries + Tier B prewarm
concurrently with DNS load before revising the supported-minimum
conclusion in either direction.
