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
  `/var/log/alderpointdns`, Alderpoint-owned/generated systemd drop-ins and
  enablement symlinks, and runtime Python bytecode caches under the
  application tree. It removes only Alderpoint-owned files/directories, not
  shared systemd parent directories.

A normal uninstall must not destroy persistent data. Only `apt purge
alderpointdns` is allowed to remove configuration, database, generated DNS files,
backups, import staging, and logs.

Local test package build:

```sh
./scripts/build-deb.sh --output-dir /tmp
dpkg-deb --info /tmp/alderpointdns_1.0.2-1_all.deb
```

The `.deb` filename and package `Version:` field are derived from the
semver-style `VERSION` file (`1.0.2`) by `build-deb.sh`; a pre-release
`VERSION` (e.g. `1.1.0-beta.1`) would use the Debian pre-release convention
(`~betaN-1`) instead -- not the raw `VERSION` contents either way. See
`docs/versioning.md`.

## Public v1.0.2 bridge-release asset layout

v1.0.2 is a one-time bridge release for unmodified public v1.0.0 appliances.
The v1.0.0 Software Updates selector accepts a GitHub release only when it
contains exactly one compatible Alderpoint DNS `.deb` asset. It rejects the
normal "versioned package plus latest alias" layout as ambiguous.

Therefore the **PUBLIC v1.0.2 GitHub release MUST contain exactly one `.deb`**:

- `alderpointdns_latest_all.deb`
- `SHA256SUMS`

Do **not** attach `alderpointdns_1.0.2-1_all.deb` to the public v1.0.2 GitHub
release. The private/local v1.0.2 RC artifact may still use the normal
versioned filename (`alderpointdns_1.0.2-1_all.deb`) for package inspection
and acceptance.

After v1.0.2, normal public releases may return to the standard asset set:

- `alderpointdns_<version>-1_all.deb`
- `alderpointdns_latest_all.deb`
- `SHA256SUMS`

because v1.0.2 contains the corrected selector that prefers the exact
versioned package and treats `alderpointdns_latest_all.deb` as fallback only.

This lightweight `dpkg-deb` path validates package contents without requiring
`debhelper` on the active appliance VM.

Future repository package build command after installing build dependencies:

```sh
dpkg-buildpackage -us -uc
```

This scaffold is intended for isolated package-build testing. It does not
yet publish a signed repository or release channel.
