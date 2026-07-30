# Migrating from BindGuard to Alderpoint DNS

BindGuard was renamed to Alderpoint DNS. This page explains how an existing
BindGuard installation gets to Alderpoint DNS, both automatically and
manually, and how to roll back if something goes wrong. See
`docs/compatibility.md` for the full old-name -> new-name reference and
deprecation timeline.

## Before you start

- **Back up first.** The automatic path already does this for you (see
  below), but if you are migrating manually, run the existing
  `scripts/backup.sh` (or the Backup and Restore page's "Create backup now")
  while the system is still running under the BindGuard names, before
  touching any files.
- Make sure the Git worktree (or however `/opt/bindguard` was deployed) is
  clean, so a failed migration can be diagnosed against a known state.
- At least 1 GiB of free disk space is required, same as any upgrade.

## Automatic path (recommended)

Run the normal upgrade tooling from a checked-out Alderpoint DNS source tree:

```sh
sudo /path/to/alderpoint-dns/scripts/upgrade.sh --source /path/to/alderpoint-dns
```

`upgrade.sh` detects a legacy BindGuard installation automatically (it looks
for `/opt/bindguard/app/webapp.py` when `/opt/alderpointdns/app/webapp.py`
does not exist yet) and migrates it instead of refusing to run or treating it
as a fresh install:

1. Takes a native backup using the *existing* `scripts/backup.sh` -- while
   the installation is still fully self-consistent under the old paths and
   old code, before anything moves.
2. Stops `bindguard.service`, `bindguard-analytics.service`,
   `bindguard-backup.timer`, `named`, and `dnsdist`.
3. Rewrites the BindGuard-era tokens in place in the live `/etc/bind/*.conf`,
   `/etc/dnsdist/dnsdist.conf`, and AppArmor local profile -- a targeted text
   substitution, not a wholesale template overwrite, so live secrets
   (dnsdist console key, webserver credentials) and any local customization
   are preserved untouched.
4. Moves `/opt/bindguard` -> `/opt/alderpointdns`, `/etc/bindguard` ->
   `/etc/alderpointdns`, `/var/lib/bindguard` -> `/var/lib/alderpointdns`, and
   `/var/log/bindguard` -> `/var/log/alderpointdns`, renaming the database
   file, compiled RPZ zone file, and TLS certificate files inside as part of
   the same move.
5. Installs the `alderpointdns.service`, `alderpointdns-analytics.service`,
   `alderpointdns-backup.service`/`.timer` units and the
   `/etc/sudoers.d/alderpointdns` rule; removes the old units and old sudoers
   file.
6. Creates compatibility symlinks (`/opt/bindguard -> /opt/alderpointdns`,
   etc. -- see `docs/compatibility.md`) so anything still pointed at the old
   paths keeps working.
7. Reloads AppArmor, restarts `named` and `dnsdist`.
8. Continues into the normal upgrade flow: replaces the application source
   with the current Alderpoint DNS release, installs the current systemd
   units, validates BIND/dnsdist config and the sudoers file, runs the
   database/RPZ deploy step, and starts `alderpointdns` and
   `alderpointdns-analytics`.

If any step from "replace application source" onward fails, `upgrade.sh`
restores its own rollback snapshot and restarts services automatically, the
same as any other upgrade.

## Manual path

If you need to do this by hand (e.g. scripting your own configuration
management instead of running `upgrade.sh`):

1. `systemctl stop bindguard.service bindguard-analytics.service bindguard-backup.timer named dnsdist`
2. Back up `/etc/bindguard`, `/var/lib/bindguard`, `/var/log/bindguard`, and
   the BindGuard source tree.
3. `mv /opt/bindguard /opt/alderpointdns`
4. `mv /etc/bindguard /etc/alderpointdns`
5. `mv /var/lib/bindguard /var/lib/alderpointdns`
6. `mv /var/lib/alderpointdns/bindguard.db /var/lib/alderpointdns/alderpointdns.db` (and the `-wal`/`-shm` sidecar files, if present)
7. `mv /var/lib/alderpointdns/compiled/bind/bindguard.rpz /var/lib/alderpointdns/compiled/bind/alderpointdns.rpz`
8. `mv /var/log/bindguard /var/log/alderpointdns`
9. In `/etc/bind/named.conf.local`, `/etc/bind/named.conf.options`,
   `/etc/dnsdist/dnsdist.conf`, and
   `/etc/apparmor.d/local/usr.sbin.named`, replace the literal strings
   `bindguard` / `BindGuard` / `BINDGUARD` with `alderpointdns` /
   `Alderpoint DNS` / `ALDERPOINTDNS` respectively. Do **not** overwrite these
   files from the packaging templates -- they carry live secrets.
10. Install the new systemd units and sudoers file from `packaging/`, remove
    the old ones, `systemctl daemon-reload`.
11. Install the new Alderpoint DNS source tree into `/opt/alderpointdns`.
12. `systemctl start named dnsdist alderpointdns alderpointdns-analytics` and
    confirm `systemctl is-active` for all four.

## Rollback procedure

If the migration fails before your application source has been replaced,
nothing under the new names is trustworthy yet -- restore from the native
backup taken in step 1:

```sh
sudo scripts/restore.sh /var/lib/alderpointdns/backups/bindguard-backup-<timestamp>.tar.gz
```

(the legacy `scripts/restore.sh`/`backup.sh` pair only understands the
current paths it was run from -- if the automatic migration already moved
directories before failing, restore the raw filesystem backup instead:
`tar -xzf pre-migration-backup.tar.gz -C /` after stopping all services, then
restart `named`, `dnsdist`, `bindguard`, and `bindguard-analytics`.)

If `upgrade.sh` itself fails *after* the legacy migration completed (i.e.
during the normal replace-application/validate/migrate/restart steps), it
already restores its own rollback snapshot automatically -- no manual action
is required beyond checking `systemctl status` for all four services.

## Legacy backup support

Backups created before the rename remain restorable indefinitely: Preview
and Restore both recognize the old `var/lib/bindguard/bindguard.db` archive
layout automatically. See docs/compatibility.md's "Backup/restore
compatibility" section for exactly what is and is not restored from a legacy
archive.
