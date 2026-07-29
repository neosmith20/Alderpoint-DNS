# Debian Packaging

The repository contains an initial Debian packaging scaffold in
`packaging/debian`.

Package contents:

- `/opt/bindguard`: application code, templates, static assets, scripts, tests,
  docs, and version metadata
- `/usr/sbin/bindguard-diagnostics`: diagnostics command
- `/lib/systemd/system`: BindGuard service and timer units
- `/etc/sudoers.d/bindguard`: narrow sudo allowlist used by privileged deploy
  operations

Maintainer scripts:

- `postinst`: creates the `bindguard` user/group, creates persistent
  directories, initializes local secrets when missing, initializes the database,
  and reloads systemd.
- `prerm`: stops BindGuard-owned services/timers on remove.
- `postrm remove`: prints where persistent data remains.
- `postrm purge`: removes `/etc/bindguard`, `/var/lib/bindguard`, and
  `/var/log/bindguard`.

A normal uninstall must not destroy persistent data. Only `apt purge
bindguard` is allowed to remove configuration, database, generated DNS files,
backups, import staging, and logs.

Local test package build:

```sh
./scripts/build-deb.sh --output-dir /tmp
dpkg-deb --info /tmp/bindguard_0.4.0-beta.1_all.deb
```

This lightweight `dpkg-deb` path validates package contents without requiring
`debhelper` on the active appliance VM.

Future repository package build command after installing build dependencies:

```sh
dpkg-buildpackage -us -uc
```

This scaffold is intended for isolated package-build testing before external
beta. It does not yet publish a signed repository or release channel.
