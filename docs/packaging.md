# Debian Packaging

The repository contains an initial Debian packaging scaffold in
`packaging/debian`.

Package contents:

- `/opt/alderpointdns`: application code, templates, static assets, scripts, tests,
  docs, and version metadata
- `/usr/sbin/alderpointdns-diagnostics`: diagnostics command
- `/lib/systemd/system`: Alderpoint DNS service and timer units
  (`alderpointdns.service`, `alderpointdns-analytics.service`,
  `alderpointdns-backup.service`/`.timer`, and
  `alderpointdns-filter-update.service`/`.timer` for automatic filter updates)
- `/etc/sudoers.d/alderpointdns`: narrow sudo allowlist used by privileged deploy
  operations

Maintainer scripts:

- `postinst`: creates the `alderpointdns` user/group, creates persistent
  directories, initializes local secrets when missing, initializes the database,
  reloads systemd, enables the backup and filter-update timers, and applies the
  stored Filter Update Interval through
  `alderpointdns_compiler.py filter-schedule-deploy` (see
  docs/configuration.md).
- `prerm`: stops and disables Alderpoint DNS-owned services/timers on remove,
  including `alderpointdns-filter-update.timer`.
- `postrm remove`: prints where persistent data remains.
- `postrm purge`: removes `/etc/alderpointdns`, `/var/lib/alderpointdns`,
  `/var/log/alderpointdns`, and the runtime timer drop-in directories
  (`alderpointdns-backup.timer.d`, `alderpointdns-filter-update.timer.d`).

A normal uninstall must not destroy persistent data. Only `apt purge
alderpointdns` is allowed to remove configuration, database, generated DNS files,
backups, import staging, and logs.

Local test package build:

```sh
./scripts/build-deb.sh --output-dir /tmp
dpkg-deb --info /tmp/alderpointdns_0.4.0~beta4-1_all.deb
```

The `.deb` filename and package `Version:` field use the Debian pre-release
convention (`~betaN-1`), derived from the semver-style `VERSION` file
(`0.4.0-beta.4`) by `build-deb.sh` -- not the raw `VERSION` contents.

This lightweight `dpkg-deb` path validates package contents without requiring
`debhelper` on the active appliance VM.

Future repository package build command after installing build dependencies:

```sh
dpkg-buildpackage -us -uc
```

This scaffold is intended for isolated package-build testing before external
beta. It does not yet publish a signed repository or release channel.
