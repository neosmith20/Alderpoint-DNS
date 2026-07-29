# Upgrade

Use `scripts/upgrade.sh` from a reviewed release artifact to upgrade an
existing BindGuard installation.

```sh
cd /path/to/bindguard-release
sudo ./scripts/upgrade.sh
```

The upgrade workflow:

- Detects the current installed version from `/opt/bindguard/VERSION`.
- Reads the target version from the release artifact's `VERSION`.
- Requires at least 1 GiB free disk space for rollback data.
- Creates a pre-upgrade BindGuard backup when `scripts/backup.sh` is available.
- Creates a rollback snapshot of application/configuration files.
- Replaces application files while preserving persistent data under
  `/etc/bindguard`, `/var/lib/bindguard`, and `/var/log/bindguard`.
- Installs updated systemd units and sudoers policy.
- Validates Python syntax, BIND configuration, dnsdist configuration, and
  sudoers syntax before service restart.
- Runs database/schema initialization and validated DNS deployment.
- Restarts services in controlled order: `named`, `dnsdist`,
  `bindguard-analytics`, then `bindguard`.
- Restores the rollback snapshot if validation, migration, deployment, restart,
  or health checks fail.

Dry-run testing:

```sh
BINDGUARD_INSTALL_ROOT=/tmp/bindguard-upgrade-root ./scripts/upgrade.sh --dry-run --source /path/to/release --skip-service-restart
```

Persistent user data is not deleted during an upgrade. If an upgrade fails
after a database migration has run, use the pre-upgrade backup from
`/var/lib/bindguard/backups` for data-level recovery.
