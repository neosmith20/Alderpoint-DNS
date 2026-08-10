# Network Configuration Guide

**System > Network Configuration** (`/system/network`)
manages the Alderpoint DNS server's **own** network interface -- its active
interface, DHCP vs static IPv4/IPv6, address, prefix length, and gateway.
This is entirely separate from **DNS Settings** (`/dns-settings`), which
controls where Alderpoint DNS *forwards* queries it doesn't answer itself
(upstream resolvers); Network Configuration never touches upstream DNS
settings, and DNS Settings never touches the server's own IP.

## Supported networking backends

Alderpoint DNS detects, rather than assumes, which of these actually owns
this host's configuration:

- **systemd-networkd**
- **NetworkManager**
- **Netplan** (Ubuntu-derived systems; Netplan itself renders to networkd or
  NetworkManager underneath, so Netplan's YAML -- not the renderer's own
  files -- is treated as the source of truth when Netplan is in use)
- **ifupdown** (classic `/etc/network/interfaces`)

If detection is ambiguous (for example, more than one backend looks
simultaneously active) or no supported backend is found, the current
network details are still shown, the detected state is reported, and every
change path refuses outright -- Alderpoint DNS will not guess at, or
rewrite, a networking configuration format it cannot positively identify.

## Making a change

The current detected values (backend, active interface, DHCP/static mode,
IPv4/IPv6 address, prefix, gateway) are always shown first, whether or not
changes are supported on this host.

1. Choose the interface and the new IPv4 (and, optionally, IPv6) settings.
2. Alderpoint DNS validates the proposal: the interface exists, address/
   prefix/gateway syntax is valid, the gateway falls within the address's
   subnet, and the address is not loopback, multicast, unspecified, or
   already in use on another local interface.
3. A confirmation summary is shown before Apply.

## What happens when you press Apply

Changing the server's own IP address can disconnect your browser.
Alderpoint DNS protects against being locked out:

1. The current, complete persistent configuration (and, for
   NetworkManager, the relevant connection-profile properties) is
   snapshotted to a root-only, group-readable rollback state file.
2. The new persistent configuration is staged for the detected backend
   (a `.network` drop-in for systemd-networkd, a netplan YAML file, an
   `nmcli` connection-profile update, or an `/etc/network/interfaces.d`
   drop-in for ifupdown).
3. An **independent rollback watchdog** is armed via
   `systemd-run --on-active=120s ... alderpointdns_compiler.py
   network-rollback-check` -- a transient systemd timer owned by PID 1,
   entirely outside the web process, the HTTP request that triggered the
   change, and your browser's connection. Killing the web app, closing
   the browser tab, or losing the connection cannot prevent the rollback.
4. The live interface is actively reconfigured through the backend's own
   supported mechanism: `networkctl reload` + `networkctl reconfigure
   <interface>`, `netplan generate` + `netplan apply`, `nmcli con mod` +
   `nmcli con up`, or a controlled `ifdown`/`ifup` cycle. Alderpoint DNS
   never uses a bare `ip link set <interface> down/up` as the primary
   mechanism -- that does not itself apply a backend's persistent IP/
   gateway configuration.

**Confirmation countdown:** navigate to Alderpoint DNS at the new address
and you'll see "Network configuration changed" with the new address,
gateway, and a **Keep Configuration** button. Confirming:

- cancels the rollback watchdog (`systemctl stop` on the transient unit),
- securely deletes the rollback state file, and
- logs the successful, now-permanent change.

**If you don't confirm within ~120 seconds**, the watchdog automatically:

1. restores the old persistent backend configuration,
2. actively reconfigures the interface back to it (not just files --
   the live kernel/interface state too),
3. removes the failed new address and brings the previous address/gateway
   back live,
4. verifies DNS/web services, and
5. logs that an automatic rollback occurred.

No reboot is required for either the change or the rollback.

## After a confirmed IP change

Alderpoint DNS audits (never silently rewrites) whether BIND, dnsdist, or
generated listener configuration still references the previous IP
literally, and reports what it finds. Only configuration that actually
depends on the server's address is regenerated/reloaded; blocklists and
Analytics History are never rebuilt as a side effect of a network change.
If the current TLS certificate encodes IP SANs, Alderpoint DNS reports
whether the new address is covered -- it does not silently regenerate or
replace an administrator's certificate.

## Privilege model

The unprivileged web process never gains general root access. Every
privileged step goes through the same narrow pattern backup/replication
already use: a fixed, argument-free sudoers entry
(`alderpointdns_compiler.py network-apply`/`network-confirm`/
`network-rollback-check`), with all actual data (interface name, proposed
addresses) flowing through a validated database row, never through argv or
a shell fragment built from request input.

## Limitations

- **Real interface reconfiguration and rollback have been exercised
  against a real NIC on a disposable Debian 13 VM (Netplan backend,
  rendering to systemd-networkd)**, in addition to the unit tests with
  every backend command mocked: a successful static IP change, confirm,
  survival past the 120s deadline, and persistence across a real reboot
  (TEST A); and an unconfirmed apply automatically rolled back by the
  independent `systemd-run` watchdog -- proven via journal logs showing
  the watchdog firing on its own schedule, not tied to the browser/HTTP
  request -- with the original address, gateway, and persistent config
  all restored, no reboot required (TEST B). This surfaced and fixed a
  real bug: `alderpointdns.service`'s `ProtectSystem=full` sandboxing
  didn't list the backend config directories (`/etc/netplan`,
  `/etc/systemd/network`, `/etc/network`) in `ReadWritePaths=`, so every
  backend's Apply failed with `EROFS` until this pass's fix (see
  CHANGELOG.md). NetworkManager and ifupdown's live-apply mechanisms
  remain covered only by mocked tests; the *persistent-config write
  path* for both is covered by the same `ReadWritePaths=` fix (their
  config directories are also listed), but their `nmcli`/`ifup`/`ifdown`
  invocations have not been exercised against a real NIC. Exercise those
  on a disposable VM before relying on them in production.
- IPv6 support (static/DHCPv6/SLAAC) is implemented for systemd-networkd
  and Netplan; NetworkManager and ifupdown IPv6 staging is more limited
  and should be verified against your specific distribution/version
  before relying on it. IPv6 itself was not exercised in the real-NIC
  test above (IPv4-only change).
- The DNS-service-awareness audit after a confirmed change reports IP
  literals found in `named.conf*`/`dnsdist.conf`; it does not currently
  attempt to detect every possible indirect dependency (e.g. an IP
  embedded in a custom included BIND file).
