# RC12 hardware/performance matrix re-verification (1GiB / 2GiB / 4GiB)

Roadmap item: re-run the full hardware matrix against the current
artifact rather than trusting the RC11 2GiB-only spot check
(`docs/v2/hardware-performance-rc11-with-real-analytics.md`).

## Method

Real `podman run --privileged --systemd=always --memory=<N>` container
per tier, base `localhost/apdns-v2-4c-accept-base:trixie`, fresh
`apt-get update` + `apt-get install` of the real RC12 `.deb`
(sha256 `dc96cec6f5bea7ce5bed6422e8ebf003da9f2a88e4a2a33ec3ef8b8ac2c5d1c0`),
`dnsperf`/`dnsutils` installed for load generation and verification.

For each tier: real HTTPS `/api/setup` + `/api/login` bootstrap, real
`POST /api/local-dns` creating `perf-local.test -> 127.0.0.99` (which
triggers a real recompile+promote of the live dnsdist config —
`"promoted":true`), confirmed live via `dig +short @127.0.0.1
perf-local.test A` before any load, then `dnsperf -c 8 -l 12` against
it with the real analytics receiver + worker services active
(same code path RC11's spot check measured).

## Results

| Memory limit | QPS | Avg latency | Loss | dnsdist NRestarts | dnsdist MemoryCurrent | container memory.current |
|---|---|---|---|---|---|---|
| 1 GiB | 103,690 | 0.916 ms | 0% (100% NOERROR) | 0 | 63.5 MB | 825 MB |
| 2 GiB | 104,674 | 0.903 ms | 0% (100% NOERROR) | 0 | 63.6 MB | 1031 MB |
| 4 GiB | 105,492 | 0.892 ms | 0% (100% NOERROR) | 0 | 63.5 MB | 1006 MB |

All three tiers: zero failed systemd units after install, zero service
restarts through the full load run, 100% NOERROR with zero query loss.

## Conclusion

Throughput/latency is flat across the 1/2/4 GiB tiers (~104k QPS,
~0.9ms, within the RC11 106k/0.88ms single-point measurement's noise
band) and dnsdist's own real memory footprint is a small, stable
~63.5 MB regardless of the container's memory ceiling -- confirming
the RC11 finding (real analytics logging costs ~28% QPS vs. pre-
analytics baseline, no memory leak) generalizes across the full
target hardware range rather than being an artifact of the single
2 GiB spot check. No tier shows OOM pressure or degraded stability at
the lowest supported memory tier (1 GiB).
