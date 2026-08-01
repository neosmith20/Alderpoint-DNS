# Upgrade

Alderpoint DNS is currently beta software (v0.4.0-beta.6); upgrade paths are
tested in dry-run and lab conditions but have not seen production-scale
exposure. Use `scripts/upgrade.sh` from a reviewed release artifact to
upgrade an existing Alderpoint DNS installation.

```sh
cd /path/to/alderpointdns-release
sudo ./scripts/upgrade.sh
```

The upgrade workflow:

- Detects the current installed version from `/opt/alderpointdns/VERSION`.
- Reads the target version from the release artifact's `VERSION`.
- Requires at least 1 GiB free disk space for rollback data.
- Creates a pre-upgrade Alderpoint DNS backup when `scripts/backup.sh` is available.
- Creates a rollback snapshot of application/configuration files.
- Replaces application files while preserving persistent data under
  `/etc/alderpointdns`, `/var/lib/alderpointdns`, and `/var/log/alderpointdns`.
- Installs updated systemd units and sudoers policy.
- Validates Python syntax, BIND configuration, dnsdist configuration, and
  sudoers syntax before service restart.
- Runs database/schema initialization and validated DNS deployment.
- Restarts services in controlled order: `named`, `dnsdist`,
  `alderpointdns-analytics`, then `alderpointdns`.
- Restores the rollback snapshot if validation, migration, deployment, restart,
  or health checks fail.

Dry-run testing:

```sh
ALDERPOINTDNS_INSTALL_ROOT=/tmp/alderpointdns-upgrade-root ./scripts/upgrade.sh --dry-run --source /path/to/release --skip-service-restart
```

Persistent user data is not deleted during an upgrade. If an upgrade fails
after a database migration has run, use the pre-upgrade backup from
`/var/lib/alderpointdns/backups` for data-level recovery.

## Adding DoQ/DoH3 support to an existing install

`scripts/upgrade.sh` upgrades the Alderpoint DNS application itself; it does
not touch which dnsdist package is installed. If you're already running
Alderpoint DNS on Debian's stock dnsdist (no `dns-over-quic`/
`dns-over-http3` in `dnsdist --version`) and want DoQ/DoH3, run the opt-in
installer separately, any time after the application upgrade:

```sh
sudo alderpointdns install-enhanced-dnsdist
```

This is a distinct, explicit action from an Alderpoint DNS upgrade — it adds
the official PowerDNS third-party APT repository and installs a different
dnsdist build. It never runs automatically as part of `scripts/upgrade.sh`
or a `.deb` upgrade. See `docs/dnsdist.md` for exactly what it changes,
the signing key fingerprint it verifies, and rollback instructions.
