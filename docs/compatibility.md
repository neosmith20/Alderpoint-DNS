# Compatibility: BindGuard -> Alderpoint DNS

BindGuard was renamed to **Alderpoint DNS** ahead of external beta. This page
is the reference for every identifier that changed, what still works under
the old name, and when that will stop being true. See
`docs/migrating-from-bindguard.md` for the step-by-step upgrade/rollback
procedure.

## Identifier map

| Old (BindGuard) | New (Alderpoint DNS) | Status |
| --- | --- | --- |
| `/opt/bindguard` | `/opt/alderpointdns` | Migrated; compatibility symlink left in place |
| `/etc/bindguard` | `/etc/alderpointdns` | Migrated; compatibility symlink left in place |
| `/var/lib/bindguard` | `/var/lib/alderpointdns` | Migrated; compatibility symlink left in place |
| `/var/log/bindguard` | `/var/log/alderpointdns` | Migrated; compatibility symlink left in place |
| `bindguard.service` | `alderpointdns.service` | Renamed; old unit removed after migration |
| `bindguard-analytics.service` | `alderpointdns-analytics.service` | Renamed; old unit removed after migration |
| `bindguard-backup.service`/`.timer` | `alderpointdns-backup.service`/`.timer` | Renamed; old units removed after migration |
| `bindguard-diagnostics` | `alderpointdns-diagnostics` | Old name kept as a deprecated wrapper |
| `app/bindguard_compiler.py` | `app/alderpointdns_compiler.py` | Old filename kept as a deprecated wrapper (sudoers compatibility) |
| `/etc/sudoers.d/bindguard` | `/etc/sudoers.d/alderpointdns` | Renamed; old file removed after migration |
| `BINDGUARD_*` environment variables | `ALDERPOINTDNS_*` | Old names recognized with a deprecation warning where practical (currently: `BINDGUARD_INSTALL_ROOT` in `upgrade.sh`) |
| `bindguard.db` | `alderpointdns.db` | Renamed on migration; legacy backups referencing the old filename remain restorable |
| `bindguard.rpz` (BIND RPZ zone) | `alderpointdns.rpz` | Renamed on migration |
| `bindguard-backup-*.tar.gz` archives | `alderpointdns-backup-*.tar.gz` archives | New archives use the new prefix; old archives remain restorable |
| Debian package `bindguard` | Debian package `alderpointdns` | Renamed |
| Linux system user/group `bindguard` | *(unchanged)* | **Intentionally kept** -- see below |

## The `bindguard` system user/group is intentionally kept

Alderpoint DNS's systemd units still run as `User=bindguard`/`Group=bindguard`,
and the installer/upgrade scripts still create a `bindguard` system account if
one doesn't exist. This is a deliberate choice, not an oversight: renaming a
live Linux account means re-chowning every file it owns (application source,
the SQLite database, certificates, backups) and there is no correctness
benefit to doing so -- the account name is an internal implementation detail,
never shown in the UI, API, or documentation as a product identifier. Keeping
it avoids that entire class of ownership-migration risk. It is documented
here so it reads as "known and intentional" rather than an incomplete rename.

## Compatibility wrappers

- `scripts/bindguard-diagnostics` is a thin wrapper that prints a deprecation
  warning to stderr and execs `scripts/alderpointdns-diagnostics` with the
  same arguments.
- `app/bindguard_compiler.py` is a thin wrapper that execs
  `app/alderpointdns_compiler.py` with the same arguments. It exists so an
  already-installed `/etc/sudoers.d/bindguard` file (which names this exact
  path) keeps working until a host has run the upgrade/migration flow that
  replaces it with `/etc/sudoers.d/alderpointdns`.
- Compatibility symlinks `/opt/bindguard -> /opt/alderpointdns`,
  `/etc/bindguard -> /etc/alderpointdns`, `/var/lib/bindguard ->
  /var/lib/alderpointdns`, and `/var/log/bindguard -> /var/log/alderpointdns`
  are created by the live migration (`scripts/upgrade.sh`'s legacy-detection
  path) so any external script or muscle-memory command using the old paths
  keeps resolving to the right place.

## Backup/restore compatibility

- `app/backup.py` writes new archives exclusively under Alderpoint DNS-branded
  paths and the `alderpointdns-backup-*.tar.gz` filename prefix.
- Restoring (and previewing a restore of) an archive created before the
  rename is still supported: `LEGACY_DB_ARCHIVE_RELPATH` and the related
  `LEGACY_*` constants in `app/backup.py` let `preview_restore()` and
  `restore_backup()` locate the database, compiled BIND state, downloaded
  lists, certificates, and secrets under their old `bindguard`-branded
  archive paths.
- Old-named systemd unit files and the old sudoers filename inside a legacy
  archive are **not** reinstalled during a restore -- the units and sudoers
  rule for the currently-installed product name are already correct, and
  reinstalling an obsolete unit referencing paths that no longer exist would
  do nothing useful.
- Checksum validation, secret-stripping policy, and the preview-first/
  rollback-on-failure restore flow are unchanged and apply identically to
  legacy and current archives.

## Deprecation and removal

| Deprecated identifier | Introduced | Planned removal |
| --- | --- | --- |
| `bindguard-diagnostics` wrapper | 0.4.0~beta2 | 0.6.0 |
| `app/bindguard_compiler.py` wrapper | 0.4.0~beta2 | 0.6.0 |
| `BINDGUARD_INSTALL_ROOT` env var | 0.4.0~beta2 | 0.6.0 |
| `/opt/bindguard`, `/etc/bindguard`, `/var/lib/bindguard`, `/var/log/bindguard` symlinks | 0.4.0~beta2 | 0.6.0 |
| Legacy BindGuard-branded backup archive restore support | 0.4.0~beta2 | No planned removal -- restoring old data should keep working indefinitely |

Before 0.6.0, run `alderpointdns-diagnostics --self-test-redaction` and grep
the host for any remaining use of the deprecated names (cron jobs, external
monitoring, saved shell history) before removing the wrappers and symlinks.
