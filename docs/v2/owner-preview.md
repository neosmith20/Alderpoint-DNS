# V2 Owner Preview (Build-Server Development Staging)

**Status:** development/staging environment only. It is **not** release evidence,
package proof, or a substitute for the exact-package KVM clean-install gate.
See `docs/v2/v2-roadmap.md` "Development And Release Stages" and
`docs/v2/rc-ready-gate3.md` for what still requires that separate gate.

## Purpose

Lets Alex click-test the current coherent V2 source directly on the build
server, on the real V2 backend/runtime (dnsdist, BIND, FastAPI, analytics,
background workers), without waiting for a private-RC `.deb` build and KVM
acceptance cycle for every small change. Implementation -> deploy to this
preview -> Alex clicks it -> fix -> redeploy -> repeat, only building the
next private RC once product/workflow behavior is accepted here and Dex has
re-audited.

## Existing build-server state (as found, before this preview existed)

- `alderpointdns` (V1.1.1, package version `1.1.1-1`) was installed and
  running as systemd services (`alderpointdns.service`,
  `alderpointdns-analytics.service`, plus timers), serving on the host's
  real network directly: `dnsdist` on `0.0.0.0:53/443/853`, the V1 web app
  on `127.0.0.1:3000` (fronted by dnsdist), BIND (`named`) on internal
  loopback ports. Running continuously since 2026-08-19 per `systemctl
  status`.
- No V2 install existed on this host before this preview (`/opt` had only
  `alderpointdns`, no `alderpointdns-v2`).
- Host has two network interfaces: `ens18` (172.16.43.100/24, DHCP, the
  real host address) and a `veth-host51`/`rc51client` netns pair (leftover
  test-only plumbing from prior RC51 exact-client-attribution acceptance
  work, unrelated to this preview).
- Traffic observed against V1 in `journalctl` was exclusively from
  `127.0.0.1` (redirects consistent with automated/local testing, not
  external device traffic).

**2026-08-23 correction (owner-directed):** the isolated dev-only ports
below (`18443`/`18053`/etc.) defeated the purpose of owner testing --
Alex could not point a real client's DNS at `172.16.43.100` and land on
V2, because V1 still owned the standard listener ports. Per explicit
owner instruction, V1.1.1 was removed from **active service** on this
build server (`alderpointdns.service`, `alderpointdns-analytics.service`,
their timers, `dnsdist.service`, and `named.service` stopped and
disabled) and V2's preview container was recreated publishing the
**normal** V2 appliance ports directly, so `172.16.43.100` now reaches V2
the same way a real appliance would. This did **not** touch the public V1
repo/artifacts, uninstall the V1 package, or delete `/etc/alderpointdns`
/ `/var/lib/alderpointdns` -- see
`/root/alderpointdns-v1.1.1-active-service-removal-backup-*/ROLLBACK.md`
on the build server for the exact rollback commands and a config/db
snapshot.

## Isolation approach

A dedicated, systemd-capable Podman container, on its own bridge network,
so V1 and V2 never contend for state/config directories even though (as
of 2026-08-23) they *do* now share the same listener ports -- V1 is
simply stopped, not merely isolated on different ports:

- Container: `apdns-v2-preview` (image
  `localhost/alderpointdns-clean-install-base-2613118` -- a stock
  `debian:trixie` base with `systemd systemd-sysv dbus apparmor
  apparmor-utils sudo procps iproute2` installed, reused from the existing
  `tests/test_clean_install_container.sh` pattern; nothing else
  preinstalled -- alderpointdns-v2's own real `Depends:` resolve the rest
  from Debian's stock repositories, same as a real install).
- Network: `apdns-v2-preview-net` (Podman bridge, `--disable-dns` --
  not needed for a single-container network).
- Published ports (container -> host, host binds `0.0.0.0`, reachable at
  the host's real address `172.16.43.100`) -- **normal V2 appliance
  ports**, matching what a real install would bind directly:
  - `8443/tcp` (real V2 management HTTPS, native TLS via uvicorn, not a
    reverse proxy) -> host `8443`
  - `53/udp` + `53/tcp` (real V2 dnsdist) -> host `53`
  - `853/tcp` (DoT, once enabled under Encryption) -> host `853`
  - `9443/tcp` (dnsdist's own web console, if enabled) -> host `9443`
  - The old `18443`/`18053`/`18853`/`18943` dev-only mappings are
    retired; nothing publishes them any more.
- Persistent state, bind-mounted from the host (survives container
  recreation, package upgrade-in-place, and this box rebooting -- confirmed
  live: a full `podman rm`+recreate of the container preserved the admin
  account, control.db, and secrets across it):
  - `/root/apdns-v2-preview-state/etc` -> `/etc/alderpointdns-v2`
  - `/root/apdns-v2-preview-state/var-lib` -> `/var/lib/alderpointdns-v2`
  - Everything else (`/opt/alderpointdns-v2`, systemd units, the apt
    package database) lives in the container's own writable layer and is
    *intentionally* not persisted outside it -- each deploy reinstalls it
    fresh from the newly built `.deb`, which is exactly what "deploy this
    source" means.

## Deploying

```sh
scripts/v2/dev_preview_deploy.sh              # build current clean HEAD, install, smoke-check
scripts/v2/dev_preview_deploy.sh --smoke-only # re-run just the smoke check (e.g. after a host reboot)
scripts/v2/dev_preview_deploy.sh --reset      # WIPES all preview config/state for a fresh first-run test, then deploys
```

The script:

- refuses to run against a dirty worktree (deploys only a clean, coherent
  source state);
- builds via `scripts/build-v2-deb.sh` with `--version
  2.0.0~preview<shortsha>-1`, so the exact deployed Git SHA is recorded in
  the package version string and, from there, in the installed `VERSION`
  file the management UI already displays (no code changes needed for
  this -- `alderpointdns_v2_ctl.py`/`webapp.py` already surface it; a
  version like `2.0.0~previewddb0fb25a2-1` is unambiguously not an RC and
  is never a valid Debian upgrade target for a real
  `2.0.0~rcNN-1` release line, so it can never be mistaken for one or
  accidentally offered as a Software Update candidate against a real
  install);
- installs with `apt-get install` (a real upgrade-in-place through the
  same postinst path every real install/upgrade goes through -- not a
  bespoke dev-only code path);
- fails loudly (non-zero exit, no "partial success") if the build, the
  install, the HTTPS smoke check, any of the three core systemd units, or
  a real DNS answer through the preview's own dnsdist doesn't check out;
- never touches `--reset` unless explicitly passed and typed-out
  confirmed.

## First deployment (historical -- superseded by the 2026-08-23 port
promotion above; kept for record)

- Deployed Git SHA: `ddb0fb2` (`ddb0fb25a2...`) -- the workstream 1 commit
  from this same session.
- Installed version string: `2.0.0~previewddb0fb25a2-1`.
- Smoke check: **passed**. `https://172.16.43.100:18443/api/setup/status`
  -> `200 {"setup_required": true}`; `alderpointdns-v2-web`,
  `alderpointdns-v2-dnsdist`, `alderpointdns-v2-bind@ctx0` all `active`;
  `dig @172.16.43.100 -p 18053 example.com` returned real A records
  through the preview's own dnsdist -> BIND path.
- No administrator account was created by this pass -- first-run setup is
  left for Alex's own click-through, matching the real owner-facing
  workflow rather than a pre-seeded account.

## Reaching it (current, normal ports)

- Management UI: `https://172.16.43.100:8443/` (self-signed certificate
  until a trusted one is configured under Encryption -- expect a browser
  warning, click through it).
- DNS: `172.16.43.100`, standard port `53` (both UDP and TCP) -- this can
  now be set as a device's actual default resolver for realistic
  DNS/client testing, which was the whole point of the 2026-08-23
  correction. `dig @172.16.43.100 example.com`.
- Encrypted DNS: `853/tcp` (DoT) and `9443/tcp` (dnsdist web console) are
  published the same way, matching a normal V2 appliance.

## Redeploy loop going forward

After each coherent implementation slice: focused tests -> commit -> clean
worktree -> `scripts/v2/dev_preview_deploy.sh` -> report the printed
version/SHA and smoke-check result -> Alex clicks it -> fixes land in the
same development cycle -> redeploy. No RC bump, no KVM ceremony, no
package-artifact evidence claimed from this loop -- those remain the
separate, later gates in `docs/v2/v2-roadmap.md`.
