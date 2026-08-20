# Network Configuration (beta-rescue priority 4)

## What this restores

V1.1.1's `/system/network/apply|confirm` managed the appliance's own
host interface/address (DHCP vs static IPv4/IPv6, gateway) -- distinct
from turning Alderpoint into a router. A prior pass classified this
"not applicable to V2" on the theory that V2's `/api/networks` (CIDR-
based policy-targeting subnets) was a redesign of it. It was not: the
two are unrelated concepts, so V1's capability had no V2 equivalent at
all and needed restoring, not reclassifying away. Alderpoint remains
DNS-only: no DHCP server, NAT, firewall, or router functionality is
added here or anywhere else in V2.

## Model

`app/v2/network_config.py` wraps V1's already-tested
`app/network_config.py` wholesale (backend detection for networkd/
netplan/NetworkManager/ifupdown, validation, staged apply, and an
apply-then-auto-rollback-unless-confirmed safety model), redirected to
V2's own state namespace (`ALDERPOINTDNS_V2_STATE_ROOT/network`,
`ALDERPOINTDNS_V2_LOG_ROOT/network-rollback.log`,
`alderpointdns-v2-network-rollback` watchdog unit prefix) so V1 and V2
network-change state never collide even if both happen to be installed
on one host.

## Privilege separation

The web process (`alderpointdns-v2`, `NoNewPrivileges=true`, no root
capability, no sudoers grant) can never itself reconfigure a host
interface. `POST /api/network/apply` only validates the proposed
change and writes a JSON request marker; a root-owned systemd `.path`
unit (`alderpointdns-v2-network-apply.path`) watches that marker and
triggers a oneshot `.service` running `alderpointdns_v2_ctl.py
network-apply`, which performs the real backend-specific apply and
writes a result marker. `POST /api/network/confirm` is the same shape,
via `alderpointdns-v2-network-confirm.path/.service`. This mirrors the
convention already established for Software Updates apply
(`alderpointdns-v2-update-apply.path`) rather than inventing a sudo
escalation path.

The auto-rollback watchdog itself (`systemd-run`, scheduled from
inside the already-root `network-apply` oneshot unit) calls
`alderpointdns_v2_ctl.py network-rollback-check` directly -- also root,
via PID 1, no further escalation needed -- to revert to the
last-known-good configuration if the change is never confirmed within
about 120 seconds.

## Real defect found and fixed while restoring this

Investigating how a privileged host-networking change could work at
all in V2 (which, unlike V1, has no sudoers file) surfaced that the
already-committed DNS Cache flush (priority 3A) had the exact same gap
latently unfixed: `app/v2/cache_control.py`'s `flush_dnsdist_cache`
called `systemctl restart alderpointdns-v2-dnsdist.service` directly
from the unprivileged web process, which a real packaged install would
have silently refused. Fixed by rewriting the compiled `dnsdist.conf`
with its own unchanged content instead, riding the already-root-owned
`alderpointdns-v2-dnsdist-reload.path` watcher that a normal policy
promotion already uses -- no sudoers entry needed for cache flush at
all once fixed. See `app/v2/cache_control.py`'s own docstring and
`tests/v2/test_cache_control.py`.

## Endpoints / UI

- `GET /api/network/status` -- current interface/address/gateway/
  backend, and any pending unconfirmed change.
- `POST /api/network/apply` -- validate + stage a proposed change.
  Refused (409) while a change is already pending confirmation.
- `POST /api/network/confirm` -- cancel the auto-rollback watchdog and
  make a pending change permanent. Refused (400) with nothing pending.
- `network` page (System group): current settings table, pending-change
  confirmation banner with the rollback deadline, and the apply form
  (interface select, IPv4/IPv6 mode + address/prefix/gateway fields).
  Applying may change the browser's own route to the appliance, so the
  UI waits and polls for reconnection rather than reloading immediately
  (the same pattern already used for Software Update apply).

## Tests

`tests/v2/test_network_config.py`: wrapper path redirection (V1
globals are really retargeted, not just aliased), apply/rollback/
confirm through the wrapper mirroring V1's own `mock.patch.object`
test conventions, the `alderpointdns_v2_ctl.py` subcommands, and the
webapp routes (validation failures never touch the privileged marker,
conflict-when-pending, unauthenticated rejection).
