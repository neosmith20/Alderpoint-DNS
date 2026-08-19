# V2 BIND recursive-cache backend (Gate #3 architecture correction)

## What this fixes

`docs/v2/architecture-map.md`'s owner-locked hot path (`client -> dnsdist packet cache -> compiled
policy/routing -> BIND RAM recursive cache -> upstream`) was never actually implemented in V2: every
release through RC30 forwarded straight from dnsdist to public upstreams. A Gate #3 review caught
this; investigation of the full repo/commit/doc history confirmed it was real implementation drift
(a locked, still-authoritative requirement that was simply never built, tracked across multiple
workstream handoffs as a budget-deferred gap), not a later deliberate architecture change -- no
document or commit ever descoped BIND. This is the real fix, implemented and proven end-to-end
against the actual packaged `.deb`, not documentation-only.

## Design

Real, isolated BIND instance, entirely separate from V1's own BIND backend
(`packaging/named.conf.options`, `docs/bind-backend.md`, `named.service`):

| | V1 | V2 |
|---|---|---|
| Config path | `/etc/bind/named.conf` | `/var/lib/alderpointdns-v2/compiled/bind/named.conf` |
| State dir | `/var/cache/bind` | `/var/lib/alderpointdns-v2/bind` |
| Log dir | `/var/log/alderpointdns/bind` | `/var/log/alderpointdns-v2/bind` |
| Plain loopback port | 5353 | 5453 |
| PROXYv2 port | 5354 | 5553 |
| systemd unit | `named.service` | `alderpointdns-v2-bind.service` |
| RPZ zone | `alderpointdns.rpz` | `alderpointdns-v2.rpz` |

Both listen only on loopback (`127.0.0.1`/`::1`) -- never port 53, never a non-loopback address.
The two packages `Conflict` and are never co-installed, but the disjoint ports/paths mean they could
never collide even if that constraint were ever relaxed.

`app/v2/bind_gen.py` generates a single self-contained `named.conf` (options + RPZ zone clause, no
external includes beyond the RPZ zone file itself), validated against the real installed
`named-checkconf` before promotion via `app/v2/runtime_staging.py`. Promotion is coherent with
dnsdist's own config: `stage_validate_promote_all` stages+validates every artifact (RPZ zone, BIND
`named.conf`, dnsdist `dnsdist.conf`) before promoting any of them, so a BIND validation failure
never leaves a mismatched dnsdist generation live, and vice versa.

## Update: multi-context BIND (Gate #3 acceptance closure)

RC31 (above design) only routed the single appliance-default plain
upstream selection through BIND; a Dex acceptance-closure pass correctly
flagged that as still an "accidental direct-upstream bypass" gap for
custom upstream profiles and domain-routing rules. RC33 closes this:

- Every distinct plain, non-ECS forwarder set actually in use (default
  policy, any other network's own upstream selection, any domain-routing
  rule's own endpoints) gets allocated its own real BIND context
  (`app/v2/bind_gen.BindContext`/`allocate_bind_contexts`), bounded at
  `MAX_BIND_CONTEXTS = 4`.
- **Design pivot, tried live:** the first design used BIND "views"
  matched by `match-destinations` on distinct loopback addresses
  (127.0.0.2, 127.0.0.3, ...) sharing one `named` process. Confirmed
  live that this needs the extra loopback addresses actually assigned to
  an interface first (`ip addr add ...`), which requires `CAP_NET_ADMIN`
  the live management-API's own unprivileged runtime user does not have,
  and a dynamic per-compile context count that a static systemd unit
  can't pre-provision. Abandoned before shipping, in favor of:
- **Port-based multi-instance:** one independent `named` process per
  context, all on `127.0.0.1`, each with its own disjoint port pair and
  state/log subdirectory. Zero extra infrastructure needed, confirmed
  live. `packaging/v2/alderpointdns-v2-bind@.service` is a systemd
  template unit; `alderpointdns-v2-bind-reload.service` unconditionally
  restarts all `MAX_BIND_CONTEXTS` possible instance names on every
  promotion (safe/idempotent -- each instance's own
  `ConditionPathExists` skips the ones not in the current generation).

**Real bug found and fixed during this pass's own live multi-context
acceptance testing:** `app/v2/runtime_staging.py`'s
`stage_validate_promote_all`/`stage_validate_promote` built the
previous-content backup path as `staging_root / f".{name}.previous"`
without creating intermediate directories -- fine for a flat name like
`dnsdist.conf`, but every BIND context's artifact name (`ctx0/named.conf`,
...) contains a real path separator, so the backup path needed a parent
directory that was never created. This crashed the **second** promotion
of any BIND context config (the first promotion has no prior `live_path`
to back up, masking it until this pass's own live testing actually
promoted twice). Fixed by flattening the name for the backup filename
only. Regression coverage:
`tests/v2/test_runtime_staging.py::TestArtifactNameWithSlash`.

**Verified-live technical findings on transport support through BIND:**
- **ECS:** the installed BIND 9.20 binary has **no** EDNS Client Subnet
  support at all -- confirmed via `strings` against the installed
  binary (no `client-subnet`/`ecs-zones`/`edns-client-subnet` directive
  exists anywhere in it). Categorically cannot be routed through BIND;
  ECS pools stay direct-to-upstream unconditionally.
- **DoT:** BIND 9.20 genuinely supports TLS-forwarding
  (`forwarders { <ip> port 853 tls <profile>; };`) -- proven live with a
  real, successfully answered query using the anonymous/unverified
  `ephemeral` TLS profile. Certificate-hostname-verified forwarding
  (`tls <name> { remote-hostname "..."; };`) is also accepted by
  `named-checkconf`, but a live functional test of it returned SERVFAIL
  and the root cause was not isolated within this pass's remaining time
  budget. Shipping unverified TLS peer-certificate forwarding would be a
  real security regression versus dnsdist's own existing DoT backend
  (which does verify `subjectName`), so DoT/DoH upstream profiles
  continue routing direct-to-upstream -- a genuine, bounded, time-limited
  gap, not a technical impossibility, and not silently dropped.

## Routing scope (deliberately bounded)

`dnsdist_policy_runtime.compile_multi_policy_dnsdist_config` routes a client-policy pool through
BIND (`_route_via_bind`) only when **all** of:

- the pool's upstream transport is `plain` (not DoT/DoH -- BIND 9.20 has no DoH forwarding, and
  DoT-forwarding correctness through BIND is unproven; both continue direct-to-upstream, unchanged
  from before this pass);
- ECS is not in use for the pool (BIND ECS pass-through is unproven, so ECS-using pools continue
  direct-to-upstream, unchanged from before this pass);
- the pool's exact upstream endpoint address set is identical to the appliance's single configured
  BIND forwarder set (the global/default policy's own plain upstream endpoints).

The third condition is the important safety property: a network/client with a genuinely different
custom plain upstream selection is never silently collapsed onto the shared BIND forwarder list --
it keeps going straight to its own configured endpoints, exactly as it did before this pass. This is
intentionally conservative rather than building unproven per-profile BIND views/ports this pass
didn't have time to validate; the fresh-install default case (no custom routing, no ECS, no
DoT/DoH), which is the common/"ordinary recursive resolution" case the architecture doc describes,
is fully covered.

**Known follow-up gap, not silently dropped:** per-distinct-plain-upstream-profile BIND views (so a
custom plain upstream selection could also gain a real recursive cache, not just the default one)
are not implemented. BIND's view-matching is keyed by source address/TSIG, not by which loopback
port a client connects to, so this needs either per-view source differentiation (not available here
-- all V2 backends connect from `dnsdist` on `127.0.0.1`) or a second BIND process per distinct
forwarder set. Tracked here rather than attempted half-correctly under this pass's time budget.

## Proof (real, live, against the actual packaged `.deb`)

Performed against a genuinely clean Debian 13 + systemd container (`debian:trixie`, systemd/dbus/
apparmor installed from stock repos only, then `apt-get install ./alderpointdns-v2_*.deb` with no
source-tree access), mirroring `tests/test_clean_install_container.sh`'s own proven pattern:

- All 8 packaged V2 services (`alderpointdns-v2-bind` included) reach `active` within postinst's own
  wait gate.
- `ss -lntup` shows BIND listening only on `127.0.0.1:5453`/`[::1]:5453` (plain) and
  `127.0.0.1:5553` (PROXYv2) -- never port 53, never non-loopback.
- A real client query through dnsdist (`dig @<host> example.com`) resolves correctly (`status:
  NOERROR`, `flags: ... ad`, real answer data).
- The identical domain queried directly against BIND's plain port independently resolves, and
  BIND's own JSON statistics channel (`127.0.0.1:8153`) shows a non-zero, growing `QUERY` opcode
  count after real traffic -- independent runtime evidence BIND actually processed the queries, not
  inferred from config alone.
- A direct, unproxied query against BIND's PROXYv2-only port (5553) gets no response at all --
  proves dnsdist cannot be bypassed to reach BIND's client-identity-aware listener directly.
- Failure-domain proof: stopping the web/analytics/discovery/replication/Tier B/schedule services
  leaves DNS answering; **stopping `alderpointdns-v2-bind` makes new recursive queries fail** (real
  evidence BIND is genuinely in the path, not decorative); restarting it recovers real answering
  immediately.
- Full lifecycle proven on the same install: `--reinstall`, `purge` (config/state/log directories
  and the BIND systemd units are fully removed, confirmed by direct residue check), and a clean
  reinstall afterward all work correctly.

**A real defect was found and fixed during this proof, not just a config bug:** the first packaged
unit's `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` systemd hardening (mirrored from the
existing dnsdist unit) blocked `AF_NETLINK`, which `named` needs at startup to enumerate real
interfaces even when every `listen-on` address is an explicit loopback literal. The unit reported
`active (running)` throughout -- `named` itself never crashed -- while genuinely listening on
nothing at all; only a real port/query-level check caught it, not `systemctl status`. Fixed by
adding `AF_NETLINK` to the allowed set.

## What was not (re-)measured in this pass

Three-way p50/p95/p99 latency (dnsdist packet-cache hit / BIND recursive-cache hit / fully uncached)
was not re-benchmarked live in this pass beyond what `docs/v2/cache-hit-latency-investigation.md`
and `docs/v2/v1-performance-baseline.md` already establish (dnsdist packet-cache hit ~0.05ms p50;
V1's own dnsdist->BIND cache-hit baseline ~12ms p50, which V2's own BIND tier now genuinely
participates in identically, being the same BIND binary/config pattern) -- a fresh concurrent-load
QPS benchmark specifically against this RC31 candidate was out of this pass's remaining time budget.
The bootstrap (fresh-install, no custom policy yet) dnsdist config has no packet cache wired at all
(a pre-existing, documented scope note in `app/v2/dnsdist_gen.py`, unrelated to this pass) -- cache-
survives-BIND-outage behavior applies only once real policy compiles through
`dnsdist_policy_runtime.compile_multi_policy_dnsdist_config`, which is unit-tested
(`tests/v2/test_bind_architecture_routing.py`) but not re-proven against a live multi-network
install in this pass.
