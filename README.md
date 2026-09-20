# Alderpoint DNS

Alderpoint DNS is a self-hosted DNS filtering and ad-blocking appliance built around BIND 9 and PowerDNS dnsdist, with a web administration interface and Debian packaging.

> **Public status:** Alderpoint DNS **v1.1.1** is the current stable public release.
>
> A clean V2 reboot is under **private development**. Previous V2 planning and implementation are frozen and are not the architecture new work continues by default. No public V2 release, release candidate, package, or tag exists unless explicitly announced later.

Alderpoint DNS is DNS-only software. It is not a DHCP server, firewall, NAT appliance, router, gateway, or general server-management platform.

**Source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE).** Commercial use requires a separate license; see `LICENSE` and `COMMERCIAL_LICENSING.md`. Contributions are subject to the `CONTRIBUTOR_LICENSE_AGREEMENT.md`.

## Public stable feature set

The current v1.1.1 release includes:

- BIND 9 + dnsdist DNS architecture
- DNS filtering and custom block/allow rules
- curated and custom blocklist sources
- Local DNS with A/AAAA/PTR/CNAME support
- client-facing encrypted DNS where supported by the installed dnsdist build
- managed upstream resolvers over plain DNS, DoT, and DoH
- persistent clients and DNS access controls
- Query Log and dashboard analytics
- cache controls
- backup/restore
- migration/import tooling
- one-way replication with deliberate/manual promotion
- administration, audit, notifications, diagnostics, and software-update workflows
- staged validation/deployment and rollback-oriented recovery behavior

For exact behavior and current limitations, use the documentation shipped with this public release rather than inferring private V2 behavior from development activity.

## Supported systems

See `docs/supported-systems.md` and `docs/hardware-requirements.md` for the current support matrix.

The public v1.1.1 release is intended for supported Debian/Ubuntu systemd hosts with BIND 9 and dnsdist installed through package dependencies.

## Quick start

Install the latest stable release directly from GitHub Releases.

### Already running as root

```sh
curl -fL -o alderpointdns.deb https://github.com/neosmith20/Alderpoint-DNS/releases/latest/download/alderpointdns_latest_all.deb && apt update && apt install -y ./alderpointdns.deb
```

### Using a sudo-enabled administrator account

```sh
curl -fL -o alderpointdns.deb https://github.com/neosmith20/Alderpoint-DNS/releases/latest/download/alderpointdns_latest_all.deb && sudo apt update && sudo apt install -y ./alderpointdns.deb
```

The stable release also publishes `SHA256SUMS`. To verify a downloaded package:

```sh
curl -fLO https://github.com/neosmith20/Alderpoint-DNS/releases/latest/download/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

Installing creates the required Alderpoint service identity and runtime state and enables the packaged services. There is no shared default administrator password; complete first-run setup through the web interface.

## Public V1 documentation

- Install: `docs/install.md`
- Upgrade and Software Updates: `docs/upgrade.md` and `docs/software-updates.md`
- Configuration: `docs/configuration.md`
- Architecture: `docs/architecture.md`
- Filtering and custom rules: `docs/filtering.md`
- Migration/import: `docs/migration.md`
- Clients & Access: `docs/clients-and-access.md`
- Backup and recovery: `docs/backup-recovery.md`
- Network Configuration: `docs/network-configuration.md`
- Replication: `docs/replication-promotion.md`
- Security posture: `docs/security.md` and `docs/hardening-review.md`
- Known limitations: `docs/known-limitations.md`
- Troubleshooting: `docs/troubleshooting.md`
- Release notes: `docs/release-notes.md` and `CHANGELOG.md`

## V2 development status

The earlier private V2 implementation is frozen and preserved. The current V2 effort is a clean reboot and remains private while it is being built and tested.

The public repository should not be used to infer private V2 architecture, completion status, package availability, or release timing. Public v1.1.1 remains the supported release until an explicit future release decision is made.

See `V2_ROADMAP.md` only for the current public status boundary; detailed reboot planning is intentionally private.

## Contributing and security

See `CONTRIBUTING.md` for contribution guidance. Security issues should be reported according to `SECURITY.md` rather than through a public issue.

## License

Alderpoint DNS is source-available, not open source, under the PolyForm Noncommercial License 1.0.0. See `LICENSE`, `COPYRIGHT`, `COMMERCIAL_LICENSING.md`, `THIRD_PARTY_NOTICES.md`, and `TRADEMARKS.md` for the applicable terms and notices.
