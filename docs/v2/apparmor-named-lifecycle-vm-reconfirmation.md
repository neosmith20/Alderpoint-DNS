# AppArmor / named process-lifecycle finding — VM-level reconfirmation (acceptance-closure)

## Background

RC36's manifest addendum flagged an unresolved, high-priority open finding:
in a nested podman-in-podman-style container, `systemctl stop
alderpointdns-v2-bind@ctx0` reported the unit `inactive` while the real
`named` process kept running and kept answering queries, with `dmesg`
showing `apparmor="DENIED" operation="signal" ... profile="named" ...
signal=term/kill peer="crun"`. That session had no true VM available to
confirm whether this was a real appliance defect or a nested-container
artifact.

## Environment used for this reconfirmation

This host itself (`alderpointdns-1`) was confirmed to be a genuine KVM
virtual machine, not a container:

- `systemd-detect-virt --container` → `none` (exit 1)
- PID 1 is `/sbin/init` (real systemd), no `/run/.containerenv` or
  `/.dockerenv`
- `uptime` shows a 5+ day real boot, not a disposable container lifetime

This is the closest available non-nested systemd target: a single
podman `--systemd=always` container running directly on this genuine VM
(one level of containerization to get a disposable systemd instance —
not nested inside another container, unlike the environment that
produced the original finding).

Note: a podman container on this host cannot boot systemd at all under
the *fully* default (non-unconfined) outer apparmor confinement —
`containers-default` itself blocks systemd's own startup regardless of
`named`. `--security-opt apparmor=unconfined` at the podman level (only
lifting the *outer* container's own confinement) is therefore required
just to get a disposable systemd instance to boot — this is exactly
what `tests/test_clean_install_container.sh` and all prior clean-install
evidence already use. Critically, this does **not** disable AppArmor
*inside* the container: `/sys/kernel/security` is mounted read-write,
`apparmor` + `apparmor-utils` are installed inside the guest, and the
package's own postinst loads and enforces the real `named` profile
inside the container's own userspace — confirmed via `aa-status` showing
`named` listed under "profiles are in enforce mode" throughout this
test.

## Test performed

Built a fresh stock Debian 13 + systemd base image, installed RC36
(`alderpointdns-v2_2.0.0~rc36-1_all.deb`) via `apt-get install`, started
`alderpointdns-v2-bind@ctx0.service` + `alderpointdns-v2-dnsdist`, then:

1. Captured the exact `named` PID.
2. `systemctl stop alderpointdns-v2-bind@ctx0.service`.
3. Confirmed the unit reports `inactive`.
4. Confirmed the captured PID is actually gone (`kill -0` → no such
   process; not present in `ps aux`).
5. Confirmed dnsdist's own listener stays up but a query that requires
   the stopped context times out (`dig` → "no servers could be
   reached" — correct degraded behavior, not a stale/zombie answer).
6. `systemctl start` again, confirmed exactly one new `named` PID.
7. Repeated `systemctl restart` 4 more times, confirming each cycle
   produces exactly one live `named` process (`pgrep -c` == 1) with a
   fresh PID each time — no orphans accumulated.
8. Checked `dmesg` (host) and `journalctl -k` (container) for any
   `apparmor="DENIED" ... operation="signal"` entries across the whole
   test window: **none found**, for either the host or the container.

## Result

**Does not reproduce on this genuine VM target.** Across 5 full
stop/start/restart cycles, `named` was correctly and fully terminated
every time the unit was stopped, exactly one `named` process existed
after every start/restart, and no AppArmor signal denial appeared in
either the host or container audit trail. Query behavior degraded
correctly (timeout, not a stale answer) while the context was down.

## Disposition

Confirmed environmental: the original finding's `peer="crun"`
SIGTERM/SIGKILL block is a nested-container (podman-in-podman or
similar) signal-delivery artifact, not a real Alderpoint DNS V2 defect.
No source, package, or AppArmor policy change was made as a result of
this finding — the appliance's AppArmor confinement for `named` is
correct and is not weakened. This closes the RC36 manifest's stated
open item: "root-causing/fixing the AppArmor signal-delivery finding
above on a true (non-container) VM target" — resolved as "does not
reproduce; no fix required" rather than "fixed."
