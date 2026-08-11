# Alderpoint DNS

Alderpoint DNS is a self-hosted DNS filtering and ad-blocking appliance built
from [BIND 9](https://www.isc.org/bind/) and
[PowerDNS dnsdist](https://dnsdist.org/), with a Python (FastAPI) web admin
application on top. dnsdist is the client-facing DNS frontend; BIND is a
localhost-only validating cache/forwarder; filtering policy is compiled into
a BIND RPZ zone and reloaded through a staged, validated deployment path.

> **Status: stable release line.** The current public stable release is
> **v1.0.2**, published through GitHub Releases. Alderpoint DNS is
> functional and acceptance-tested, but several
> features are intentionally partial or narrowly scoped by design. See
> [Known limitations](#known-limitations) below and
> `docs/known-limitations.md` and `docs/hardening-review.md` for the honest
> current state before you rely on it for anything important.

**Source-available under the [PolyForm Noncommercial License
1.0.0](LICENSE).** Alderpoint DNS is not open source; commercial use
requires a separate license — see `LICENSE` and
`COMMERCIAL_LICENSING.md`. Contributions are subject to the
[Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md).

## Key features

- **DNS filtering with a custom rules engine.** Domain, subdomain, hosts-style,
  rewrite, and POSIX-ERE-safe regex block/allow rules, plus curated public
  blocklist sources, compiled into a BIND RPZ zone with deterministic
  precedence (local DNS zones, then rewrites, then explicit allows, then
  explicit blocks, then regex rules, then external blocklists). See
  `docs/filtering.md`.
- **Local DNS.** Authoritative forward/reverse zones for an internal domain
  (default `home.arpa`), with automatic PTR records, served directly by BIND
  and never forwarded upstream. See `docs/architecture.md`.
- **Encrypted resolvers.** Client-facing DoH, DoT, and DoQ/DoH3 (when the
  installed dnsdist build supports QUIC/HTTP-3 — Debian's own stock dnsdist
  package does not; `sudo alderpointdns install-enhanced-dnsdist` opts in to
  the official PowerDNS repository build that does), plus managed upstream
  resolvers over plain DNS, DoT, and DoH. See `docs/dnsdist.md` and
  `docs/configuration.md`.
- **Replication.** One-way primary-to-replica configuration sync with hashed,
  one-time, revocable enrollment tokens and mTLS client authentication.
  Promotion is manual by design; automatic failover and bidirectional conflict
  resolution are not implemented. See `docs/replication-promotion.md`.
- **Migration from AdGuard Home and Pi-hole.** Preview-first import from
  AdGuard Home (YAML or read-only API), Pi-hole text/list exports, BIND
  zones, hosts files, CSV/XLSX, and Alderpoint DNS's own JSON export, with
  unsupported source features reported explicitly rather than silently
  dropped or fabricated. AdGuard DNS Rewrites always map to Local DNS
  (Alderpoint DNS's own local-authority feature), imports are idempotent
  on re-run, and intentional public-IP Local DNS records (e.g. a VPN host)
  are reported as warnings rather than blocking conflicts. See
  `docs/migration.md`.
- **Backup and restore.** Previewable, checksummed backups using SQLite's
  online-backup API (safe under concurrent writes), optional password
  encryption for off-host archives, and a restore path that takes its own
  safety backup and rolls back automatically on a failed health check. See
  `docs/backup-recovery.md`.
- **Administration.** Server-side sessions (revocable individually or all
  at once), a recent admin audit log, in-app password change, and a
  root-only local `alderpointdns admin reset-password` recovery command
  with no web-reachable route. See `docs/web.md`.
- **Notifications.** A provider-neutral SMTP email and generic HTTP webhook
  framework (with Discord/Slack/Microsoft Teams/ntfy/Gotify/Pushover
  presets), per-event-category subscriptions and severity thresholds,
  cooldown/dedup, recovery notices, and a local delivery history.
- **Web admin UI.** A CSRF-protected, session-based admin interface
  covering DNS settings, filtering, local DNS, analytics, backup/restore,
  migration, replication, administration, notifications, and system
  status. See `docs/web.md`.

## Supported systems

Per `docs/supported-systems.md` and `docs/hardware-requirements.md`:

- **Operating systems:** Debian 12, Debian 13, Ubuntu 24.04 LTS, and Ubuntu
  26.04 LTS (once its package set matches the documented dependencies).
- **Architectures:** x86_64/amd64 and arm64/aarch64.
- **Required services:** BIND 9, PowerDNS dnsdist (DoQ/DoH3 require a dnsdist
  build with QUIC support), systemd, SQLite.
- **Not supported:** public recursive-resolver exposure without firewall
  controls, non-systemd Linux distributions, and containers that cannot run
  BIND/dnsdist with the required listeners and capabilities.
- **Minimum test hardware:** 1 vCPU, 512 MiB RAM, 1 GiB free disk after OS
  install, one private network interface. Recommended: 2 vCPU, 2 GiB RAM,
  8 GiB free disk.

## Quick start

Install the latest stable release directly from GitHub Releases.

### Already running as root

Use this on a root shell (for example, after `su -`). Minimal Debian installs
may not include `sudo` by default:

```sh
curl -fL -o alderpointdns.deb https://github.com/neosmith20/Alderpoint-DNS/releases/latest/download/alderpointdns_latest_all.deb && apt update && apt install -y ./alderpointdns.deb
```

### Using a sudo-enabled administrator account

```sh
curl -fL -o alderpointdns.deb https://github.com/neosmith20/Alderpoint-DNS/releases/latest/download/alderpointdns_latest_all.deb && sudo apt update && sudo apt install -y ./alderpointdns.deb
```

Both commands always install the current latest stable release -- the
`alderpointdns_latest_all.deb` asset is the stable, permanent latest-release
download name. Public v1.0.2 is a one-time bridge release, so its GitHub
release intentionally publishes exactly two assets:
`alderpointdns_latest_all.deb` and `SHA256SUMS`. It does not publish a
versioned v1.0.2 `.deb` asset. This lets older v1.0.0 updater logic see
exactly one compatible Alderpoint DNS package while preserving the normal
latest-release download URL.

For later normal releases, `alderpointdns_latest_all.deb` may again be
published alongside and byte-identical to that release's versioned package,
just without a version number in the filename, so these commands never need
updating. `apt install` resolves and installs BIND, dnsdist, and every other
dependency from Debian's own repositories; nothing is piped from the network
into a root shell unreviewed.

Every release also publishes a `SHA256SUMS` file alongside the `.deb`
assets. To verify the download before installing (optional, but
recommended if you're not fetching it interactively):

```sh
curl -fLO https://github.com/neosmith20/Alderpoint-DNS/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

If `apt install ./alderpointdns.deb` prints a notice like `Download is
performed unsandboxed as root because ... _apt ... Permission denied`, that's
harmless — it just means the `.deb` sits in a directory (e.g. `/root`) that
apt's unprivileged `_apt` user can't read, so apt reads it as root instead.
It does not mean the install failed.

Installing creates a dedicated `alderpointdns` service account, generates
local secrets, initializes the database, deploys generated DNS
configuration, and enables services. No default administrator account
exists — create the first one through the web UI's `/setup` page.

To install from a reviewed local source tree instead (e.g. for
development), see `docs/install.md`. Once installed, use **System >
Software Updates** in the admin UI to check for and install future
releases — it performs its own checksum, package-metadata, version, and
mandatory pre-upgrade-backup validation automatically (see
`docs/software-updates.md`); `docs/upgrade.md` also documents the
`scripts/upgrade.sh` path for upgrading a source-tree install.

## Known limitations

Honestly stated, from `docs/known-limitations.md`:

- The management UI and DNS listeners intentionally bind to VM/host
  interfaces; external firewall/VLAN rules are required to restrict who can
  reach them. Admin UI HTTPS is not implemented natively yet — use a private
  network or a trusted reverse proxy.
- The automatically generated self-signed certificate is not publicly
  trusted; replace it before relying on it for anything beyond lab use.
- Per-network policy profiles and SafeSearch enforcement are modeled in the
  schema but not fully enforced at runtime yet.
- Import compatibility is intentionally conservative: Pi-hole's live gravity
  database internals are not read directly, and AdGuard/Pi-hole per-client or
  per-group policy features are preserved only as explicit inactive findings,
  never silently approximated.
- System Status's Recent Logs is scoped to Alderpoint DNS's own four service
  units, not a general journal viewer.
- A signed apt repository is not published; releases are distributed as
  checksummed `.deb` assets on GitHub Releases, not through a trusted apt
  repository.
- Unattended (automatic) software installation is intentionally not
  implemented — Software Updates checks for new releases automatically but
  always requires an explicit administrator action to install one.
- Automatic package rollback on a failed software update is not
  implemented; the mandatory pre-upgrade backup it always takes first is
  retained for manual recovery.

See `docs/known-limitations.md` and `docs/hardening-review.md` for the
fuller list of genuine limitations and accepted risks, and
`docs/beta-readiness.md` for the pre-1.0 readiness checklist this release
satisfied.

## Documentation

- Install: `docs/install.md`
- Upgrade and Software Updates (in-app): `docs/upgrade.md` and
  `docs/software-updates.md`
- Configuration: `docs/configuration.md`
- Architecture: `docs/architecture.md`
- Filtering and custom rules: `docs/filtering.md`
- Migration from AdGuard Home / Pi-hole: `docs/migration.md`
- Backup and recovery: `docs/backup-recovery.md`
- Network Configuration: `docs/network-configuration.md`
- Replication: `docs/replication-promotion.md`
- Security posture: `docs/security.md` and `docs/hardening-review.md`
- Known limitations: `docs/known-limitations.md`
- Troubleshooting: `docs/troubleshooting.md`
- Release notes: `docs/release-notes.md` and `CHANGELOG.md`

## Contributing and security

Contributions are welcome — see `CONTRIBUTING.md` for how to run the test
suite, what pull requests should include, and the current state of the
Contributor License Agreement acceptance process. To report a security
issue, please follow `SECURITY.md` rather than opening a public issue. This
project follows the `CODE_OF_CONDUCT.md`.

## License

Alderpoint DNS is **source-available**, not open source, under the
[PolyForm Noncommercial License 1.0.0](LICENSE). You can read, run, modify,
and share it for noncommercial purposes; see `LICENSE` for the complete
terms and `COPYRIGHT` for the required copyright notice.

Commercial use — selling Alderpoint DNS, bundling it into a paid product,
offering it as a paid hosted or managed service, or commercially
redistributing it — is not granted by this license and requires a separate
agreement. See `COMMERCIAL_LICENSING.md`.

Alderpoint DNS integrates with third-party software (BIND 9, PowerDNS
dnsdist, and various Python/OS packages) that remains under its own
license; see `THIRD_PARTY_NOTICES.md`. Contributions are governed by the
[Contributor License Agreement](CONTRIBUTOR_LICENSE_AGREEMENT.md). Use of
the "Alderpoint DNS" name and branding is governed by `TRADEMARKS.md`.
