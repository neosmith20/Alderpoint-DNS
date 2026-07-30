# Debian Packaging

The repository contains an initial Debian packaging scaffold in
`packaging/debian`.

Package contents:

- `/opt/alderpointdns`: application code, templates, static assets, scripts, tests,
  docs, and version metadata
- `/usr/sbin/alderpointdns-diagnostics`: diagnostics command
- `/lib/systemd/system`: Alderpoint DNS service and timer units
- `/etc/sudoers.d/alderpointdns`: narrow sudo allowlist used by privileged deploy
  operations

Maintainer scripts:

- `postinst`: creates the `alderpointdns` user/group, creates persistent
  directories, initializes local secrets when missing, initializes the database,
  and reloads systemd.
- `prerm`: stops Alderpoint DNS-owned services/timers on remove.
- `postrm remove`: prints where persistent data remains.
- `postrm purge`: removes `/etc/alderpointdns`, `/var/lib/alderpointdns`, and
  `/var/log/alderpointdns`.

A normal uninstall must not destroy persistent data. Only `apt purge
alderpointdns` is allowed to remove configuration, database, generated DNS files,
backups, import staging, and logs.

Local test package build:

```sh
./scripts/build-deb.sh --output-dir /tmp
dpkg-deb --info /tmp/alderpointdns_0.4.0~beta2-1_all.deb
```

The `.deb` filename and package `Version:` field use the Debian pre-release
convention (`~betaN-1`), derived from the semver-style `VERSION` file
(`0.4.0-beta.2`) by `build-deb.sh` -- not the raw `VERSION` contents.

This lightweight `dpkg-deb` path validates package contents without requiring
`debhelper` on the active appliance VM.

Future repository package build command after installing build dependencies:

```sh
dpkg-buildpackage -us -uc
```

This scaffold is intended for isolated package-build testing before external
beta. It does not yet publish a signed repository or release channel.
