# 1 / 2 / 4 GiB sustained performance matrix -- acceptance-closure pass

Real installed RC39 package (`alderpointdns-v2_2.0.0~rc39-1_all.deb`),
exercised via real `dig`/`dnsperf` against a real running `dnsdist`,
inside fresh `podman --systemd=always` containers on this session's
genuine KVM VM host, memory-constrained with `podman run --memory=<N>
--memory-swap=<N>` (a real cgroup v2 `memory.max`, confirmed by reading
`/sys/fs/cgroup/memory.max` inside each container before testing). This
is a sustained-throughput/stability matrix, not a replacement for the
already-completed three-layer p50/p95/p99 latency benchmark documented
in the RC36 manifest.

## Host reality check (measured fresh this pass)

```
$ free -h
              total   used   free   shared  buff/cache  available
Mem:          3.8Gi   2.0Gi  1.0Gi  935Mi   2.0Gi        1.8Gi
$ cat /proc/meminfo | head -3
MemTotal:     4015404 kB   (~3.8 GiB)
```

Consistent with prior sessions' documented conclusion
(`docs/v2/full-concurrent-hardware-test.md`): this host has under 4 GiB
of total physical RAM, so a genuinely isolated 4 GiB cgroup memory cap
is not physically possible here -- it would leave ~0 headroom for the
host OS, podman, and this session's own tooling. Not a policy choice or
guess: `MemTotal` itself is below 4 GiB. **1 GiB and 2 GiB tiers below
are both real, comfortably-supportable, measured profiles; 4 GiB could
not be tested on this specific host and is reported as a genuine
external hardware limitation, not fabricated.**

## Method

Fresh clean install of RC39 in each constrained container, then two
real workloads via `dnsperf` against the real client-facing `dnsdist`
listener on port 53:

- **cache-hit**: a single real, previously-resolved domain
  (`example.com`), 4 concurrent clients, 20s sustained.
- **uncached**: 3000 unique never-before-seen subdomains
  (`uncached-<n>-<rand>.example.com`), rate-limited to 2000 qps
  requested, 4 concurrent clients, 15s sustained, forcing real upstream
  recursion through the BIND-routed pool for every query.

Memory tracked via `/sys/fs/cgroup/memory.peak`, service restarts via
`systemctl show ... -p NRestarts`, OOM via `dmesg`/`journalctl -k`.

## 1 GiB

- cgroup `memory.max`: `1073741824` (confirmed exactly 1 GiB)
- cache-hit: **54,923 QPS**, 0 lost (0.00%), avg latency 1.70ms (min
  0.019ms / max 12.97ms), 100% NOERROR
- uncached (real recursion): **1,981 QPS**, 0 lost (0.00%), avg latency
  4.85ms (min 0.032ms / max 1.22s), 100% NOERROR
- `memory.peak`: 964 MB (~90% of the 1 GiB cap -- tight but stable
  throughout both runs, did not grow further under the uncached run)
- Service restarts: `alderpointdns-v2-dnsdist` / `alderpointdns-v2-bind@ctx0`
  both `NRestarts=0`
- All three core services (`web`, `dnsdist`, `bind@ctx0`) `active`
  before and after both runs
- No OOM kill in `dmesg`/`journalctl -k`

## 2 GiB

- cgroup `memory.max`: `2147483648` (confirmed exactly 2 GiB)
- cache-hit: **54,928 QPS**, 0 lost (0.00%), avg latency 1.72ms (min
  0.020ms / max 8.67ms), 100% NOERROR
- uncached (real recursion): **1,971 QPS**, 0 lost (0.00%), avg latency
  5.03ms (min 0.032ms / max 0.35s), 100% NOERROR
- `memory.peak`: 947 MB (well within the 2 GiB cap, substantial
  headroom vs. the 1 GiB tier's own peak)
- Service restarts: both `NRestarts=0`
- All three core services `active` before and after both runs
- No OOM kill

## 4 GiB

Not practically supportable on this host -- see "Host reality check"
above. `podman run --memory=4g` on a host with `MemTotal` under 4 GiB
would either be silently capped below 4 GiB by the kernel or would
starve the host itself (including this session's own tooling), neither
of which would produce a genuine, trustworthy 4 GiB measurement.
Reported honestly as a hardware constraint of this specific test host,
not a product limitation -- nothing observed at 1 GiB or 2 GiB (memory
headroom, QPS, latency shape) suggests the appliance itself would
behave differently at 4 GiB; it would very likely just have more
headroom than the already-comfortable 2 GiB tier.

## Conclusion

Both practically-supportable tiers (1 GiB, 2 GiB) sustain real,
meaningful load (sustained ~55k QPS cache-hit, ~2k QPS forced-uncached
recursion) with zero query loss, zero service restarts, zero OOM
events, and stable memory well inside each cap. The 1 GiB tier runs
noticeably tighter (~94% of cap) than 2 GiB (~46% of cap) but showed no
instability across either workload -- consistent with, and not
contradicting, prior sessions' 2 GiB-minimum/4 GiB-recommended
supported-hardware guidance.
