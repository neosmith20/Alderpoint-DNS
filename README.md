# Alderpoint DNS

Alderpoint DNS is a self-hosted DNS filtering and ad-blocking appliance built
from [BIND 9](https://www.isc.org/bind/) and
[PowerDNS dnsdist](https://dnsdist.org/), with a Python (FastAPI) web admin
application on top. dnsdist is the client-facing DNS frontend; BIND is a
localhost-only validating cache/forwarder; filtering policy is compiled into
a BIND RPZ zone and reloaded through a staged, validated deployment path.

> **Status: beta.** This is **v0.4.0-beta.2**, pre-release software. It is
> functional and acceptance-tested in lab conditions, but it has not had
> production-scale or adversarial-network exposure, and several features are
> intentionally partial. See [Known limitations](#known-limitations) below
> and `docs/known-limitations.md`, `docs/beta-readiness.md`, and
> `docs/hardening-review.md` for the honest current state before you rely on
> it for anything important.

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
  installed dnsdist build supports QUIC), plus managed upstream resolvers over
  plain DNS, DoT, and DoH. See `docs/dnsdist.md` and `docs/configuration.md`.
- **Replication.** One-way primary-to-replica configuration sync with hashed,
  one-time, revocable enrollment tokens and mTLS client authentication.
  Promotion is manual by design; automatic failover and bidirectional conflict
  resolution are not implemented. See `docs/replication-promotion.md`.
- **Migration from AdGuard Home and Pi-hole.** Preview-first import from
  AdGuard Home (YAML or read-only API), Pi-hole text/list exports, BIND
  zones, hosts files, CSV/XLSX, and Alderpoint DNS's own JSON export, with
  unsupported source features reported explicitly rather than silently
  dropped or fabricated. See `docs/migration.md`.
- **Backup and restore.** Previewable, checksummed backups using SQLite's
  online-backup API (safe under concurrent writes), optional password
  encryption for off-host archives, and a restore path that takes its own
  safety backup and rolls back automatically on a failed health check. See
  `docs/backup-recovery.md`.
- **Web admin UI.** A single-administrator, CSRF-protected, session-based
  admin interface covering DNS settings, filtering, local DNS, analytics,
  backup/restore, migration, replication, and system status. See
  `docs/web.md`.

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

Alderpoint DNS installs from a reviewed local source/release tree, not a
piped remote script. See `docs/install.md` for full details, package lists,
and layout. In short:

```sh
cd /path/to/alderpointdns-release
sudo ./scripts/install.sh
```

This creates a dedicated `alderpointdns` service account, installs BIND and
dnsdist, generates local secrets, initializes the database, deploys generated
DNS configuration, and enables services. No default administrator account
exists — create the first one through the web UI's `/setup` page. See
`docs/upgrade.md` for upgrading an existing installation.

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
- A signed apt repository is not published yet; beta packages are local
  `dpkg-deb` test artifacts.

See `docs/beta-readiness.md` and `docs/hardening-review.md` for the fuller
pre-release checklist and accepted beta risks.

## Documentation

- Install: `docs/install.md`
- Upgrade: `docs/upgrade.md`
- Configuration: `docs/configuration.md`
- Architecture: `docs/architecture.md`
- Filtering and custom rules: `docs/filtering.md`
- Migration from AdGuard Home / Pi-hole: `docs/migration.md`
- Backup and recovery: `docs/backup-recovery.md`
- Security posture: `docs/security.md` and `docs/hardening-review.md`
- Troubleshooting: `docs/troubleshooting.md`
- Release notes: `docs/release-notes.md`

## Contributing and security

Contributions are welcome — see `CONTRIBUTING.md` for how to run the test
suite and what pull requests should include. To report a security issue,
please follow `SECURITY.md` rather than opening a public issue. This project
follows the `CODE_OF_CONDUCT.md`.

## License

A license has not yet been finalized for Alderpoint DNS.
