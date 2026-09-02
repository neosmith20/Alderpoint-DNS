# Live appliance boot-survival units

Added 2026-09-02 after a real outage: the host rebooted and none of
`apdns-go-live`'s processes (web container, `apdns-hostagent`, `named`,
`dnsdist`) came back, because none of them were systemd units -- they
were all ad hoc processes started by hand or by
`scripts/v2/redeploy-go-live.sh`/`scripts/v2/cutover.sh`.

These three units, installed to `/etc/systemd/system/` on the live host
and enabled (`systemctl enable`), fix that:

1. **`apdns-go-live-hostagent.service`** -- starts `apdns-hostagent`
   with its exact, committed flags (previously these lived only in
   shell history and had to be reconstructed from source during the
   2026-09-02 recovery -- this file is now the single source of truth).
2. **`apdns-go-live-web.service`** -- starts the already-created
   `apdns-go-live` podman container (`After=`/`Requires=` the hostagent
   unit; does NOT create the container -- that stays
   `redeploy-go-live.sh`'s job).
3. **`apdns-go-live-dns-promote.service`** -- a oneshot unit that
   actually launches named+dnsdist on boot. Neither of the two units
   above does this on their own: `apdns-hostagent` only *adopts* an
   already-running named/dnsdist from a prior generation's PID files (a
   no-op on a cold boot), and the web process never calls
   `dnsruntime.Orchestrator.Apply` from its own startup path -- only
   from a blocklist-refresh completion hook or the owner's "Apply
   Runtime Changes" button. Without this unit, a reboot would restore
   management (`:8443`) but silently leave DNS (`:53`) down until a
   human noticed, exactly what happened in the outage this fixes.

Ordering: `hostagent` -> `web` -> `dns-promote`, each gated on the
previous via `After=`/`Requires=`; `dns-promote` additionally waits for
the real sockets it needs (`agent.sock`, the web container's dnstap
listen socket) rather than trusting unit-start timing alone.

## Why masking `dnscrypt-proxy` is safe

The root cause of the actual DNS outage (not the reboot itself) was a
separate, pre-existing, unrelated package -- `dnscrypt-proxy.socket` /
`.service` -- auto-starting after the reboot (it's a real systemd unit;
the appliance's own processes weren't) and claiming port 53
(`127.0.2.1:53`) just enough that dnsdist's wildcard `0.0.0.0:53` bind
failed with no visible listener in `ss`/`/proc/net/udp` (real,
standard Linux port-level-not-address-level bind conflict behavior).

Confirmed unused before masking:
- The host's own `/etc/resolv.conf` (DHCP-provided) points directly at
  `1.1.1.2`/`1.0.0.2`, never at `127.0.2.1`.
- `dnscrypt-proxy-resolvconf.service` (the unit that would wire it into
  the host's own resolution) was already `inactive`.
- Its own `/etc/dnscrypt-proxy/dnscrypt-proxy.toml` has
  `listen_addresses = []` -- it doesn't even want to bind anywhere; the
  `.socket` unit's own hardcoded `Listen=` directives are what actually
  put it on the port.

It is `systemctl mask`ed (stronger than `disable` -- prevents any unit,
including a future package upgrade re-enabling it, or an admin
accidentally `systemctl start`ing it, from bringing it back) rather
than left merely disabled. `check-port53-free.sh` (still run by
`dns-promote-live.sh` -- see below for when) verifies port 53 is
genuinely free immediately before every real promote attempt and fails
with a clear message naming `dnscrypt-proxy` specifically if anything
holds it, so a *different* future port-53 squatter is caught loudly
instead of reproducing the same multi-hour diagnosis.

## Two real deploy-time defects found the first time this was exercised live

Both fixed the same session the units were added, once a real redeploy
(not just the simulated cold-start test) actually exercised them:

1. **`KillMode=process` on the hostagent unit.** `apdns-hostagent` execs
   `named`/`dnsdist` directly, so they land in
   `apdns-go-live-hostagent.service`'s own cgroup. Systemd's *default*
   `KillMode=control-group` sends the stop signal to that whole cgroup on
   `systemctl restart` -- so a routine hostagent restart killed
   `named`/`dnsdist` too, turning what should be a no-DNS-disruption
   operation (the existing `trackedProcess`/PID-file adoption logic is
   designed to pick the still-running processes back up) into a real
   outage. `KillMode=process` (only the main process) fixes it.
2. **`dns-promote-live.sh` now checks whether DNS is already healthy
   before attempting a promote.** `apdns-go-live-dns-promote.service`
   `Requires=` the hostagent unit, so *any* hostagent restart tears the
   promote unit down too, and systemd auto-restarts it. With fix #1 in
   place, `named`/`dnsdist` are still alive and fine at that point --
   but the old promote logic didn't know that, and always failed via
   `check-port53-free.sh` (dnsdist already legitimately owns `:53`),
   leaving `systemctl status` on the promote unit looking like a real
   failure even though DNS never broke. The script now asks
   `apdns-hostagent` directly (`dns_runtime.status`) whether it already
   considers both processes running, and skips the promote entirely
   (exit 0) if so -- `check-port53-free.sh` is unchanged and still runs,
   still catching a genuine rival, whenever that's not the case.

## Interaction with `redeploy-go-live.sh`

`redeploy-go-live.sh` now drives these units (`systemctl restart
apdns-go-live-hostagent.service`, stop/recreate/start the web unit)
instead of raw `kill`+`setsid`/`podman rm+create+start`, specifically so
its own manual process management can never race systemd's
`Restart=on-failure` into running two hostagent processes or two web
containers at once. See that script's own comments at each step for the
detail.

## SHA/package alignment note

Everything in this directory, plus `scripts/v2/redeploy-go-live.sh`, is
**live-ops tooling for this one ad hoc deployment only** -- none of it
is packaged into the `.deb` (`scripts/build-go-deb.sh` only packages
`go/` build output + `packaging/`, never `scripts/v2/`). That means:

- The live appliance's *app* version (`/api/health`'s `version` field)
  tracks the `go/` source tree's commit, via `redeploy-go-live.sh`
  stamping `main.Version` at build time.
- The repo's overall `git rev-parse HEAD` can be AHEAD of that live app
  version whenever only files under `scripts/v2/` (this directory,
  `redeploy-go-live.sh`) changed -- those commits affect how the live
  appliance is *supervised*, not what binary it's running, so no app
  rebuild/redeploy is implied or needed by them alone.
- The `.deb`'s embedded commit (its `Version:` field, `main.Version` in
  the packaged binary) only needs to match `go/`+`packaging/`'s state,
  never `scripts/v2/`'s -- rebuild it when either of those change, not
  on every commit to this directory.
- This live appliance was never installed via the `.deb` in the first
  place (see [[alderpointdns-owner-preview]]/`docs/v2/owner-preview.md`)
  -- these units exist because this ad hoc deployment has no systemd
  coverage of its own otherwise, a gap the packaged install (native,
  `packaging/systemd/*.service`, an entirely separate unit set) doesn't
  have to begin with.

## Not covered by this pattern

`apdns-go-live-dns-promote.service` is a one-shot **compile of current
DB state**, not a supervisor for `named`/`dnsdist` themselves -- those
two processes are supervised by `apdns-hostagent` itself
(`internal/hostagentd/ops_dnsruntime.go`'s own `trackedProcess`/adoption
logic), not by systemd directly. That's unchanged by this work and is
the existing, already-tested design.
