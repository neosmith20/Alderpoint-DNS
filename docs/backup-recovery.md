# Backup and Recovery Guide

Alderpoint DNS is currently beta software (v0.4.0-beta.5). The backup/restore
paths described here are acceptance-tested, but keep independent copies of
anything important — see `docs/known-limitations.md`.

Routine backups:

- Use **System > Administration > Backup & Restore** (`/backup`) for
  previewable, checksummed backups. This is a dedicated workflow, separate
  from **Spreadsheet/Text Import** (`/import`) -- native `.tar.gz`/
  `.tar.gz.enc` Alderpoint DNS backups are never restored through the
  import page, and CSV/hosts/zone/Pi-hole/AdGuard data is never restored
  through the backup page.
- Keep private keys/credentials excluded unless the recovery scenario requires
  them.
- Use password encryption for backups that leave the VM.
- Scheduled backups use `alderpointdns-backup.timer`.
- Timestamps shown on this page (Backup & Restore listing, restore preview,
  Last Backup/Last Restore) display in the server's own configured local
  timezone, with a clear abbreviation/offset (e.g. "Aug 8, 2026 at 6:47 PM
  MDT") -- not UTC. This is display-only: the canonical timestamp in each
  backup's `manifest.json` and in `backup_history` stays UTC/ISO-8601, and
  restore never depends on the displayed or filename timestamp.
- A successful interactive **Create Backup** also automatically starts a
  browser download of that backup (via the same authenticated download
  route the manual **Download** button uses), in addition to -- not
  instead of -- keeping it stored and listed on the server for later
  re-download.

## Large backups and Analytics History

A long-running Alderpoint DNS install's Analytics History makes routine
backups grow over time; this is expected and supported. Migrating such a
server (e.g. onto new production DNS hardware) must never fail because of
an upload size limit tuned for spreadsheet/text data.

- Native backup uploads are **streamed to disk in ~4 MiB chunks**
  (`backup.begin_streamed_upload`), never held whole in the web process's
  memory -- a 20 MiB backup and a several-GiB backup both use the same
  bounded amount of memory to upload.
- The native backup upload limit is governed by `max_upload_mib` (default
  **4096 MiB / 4 GiB**), and the extracted/uncompressed-size ceiling by
  `max_extracted_mib` (default **16384 MiB / 16 GiB**) -- both configurable
  from the **Restore Upload Limits** panel on `/backup`, within a hard
  ceiling of 50 GiB / 200 GiB. This is a *separate* policy from the 10 MiB
  cap on the Spreadsheet/Text Import page (`app/importer.py`'s
  `MAX_UPLOAD_BYTES`), which is unaffected and unrelated.
- Free disk space is checked before an upload is accepted (and again,
  periodically, during a large streamed upload) and again before
  extraction, using the archive's actual scanned size.
- Before anything live is touched, the archive is verified to be a
  recognizable Alderpoint DNS native backup (manifest.json with the
  expected fields), checked for path traversal, symlinks, hardlinks, and
  device/fifo members, and its total extracted size is checked against the
  configured ceiling -- all before a single content byte is written to the
  extraction directory, so a compressed archive bomb cannot bypass the
  upload size limit.
- If you hit an upload limit while migrating a large, long-running server:
  raise `max_upload_mib`/`max_extracted_mib` on the *destination* server's
  Backup & Restore page first, then retry the upload.

Restore workflow:

1. Upload or select a backup from **Backup & Restore**.
2. Preview the restore -- shows when the backup was created, the source
   Alderpoint DNS version, archive size, and an Included/Not Included
   status for every component (configuration, blocklists/custom rules, DNS
   cache settings, analytics history, certificates, admin/auth data).
3. Confirm selected components.
4. Alderpoint DNS takes a safety backup before applying.
5. BIND/dnsdist configuration is validated; restored SQLite tables come
   from a consistent, checksum-verified copy.
6. Services touched by the restore are restarted.
7. DNS health checks run.
8. Failure triggers rollback to the safety backup.

Emergency recovery:

- DNS should continue through BIND/dnsdist even if the web app is down.
- Use `systemctl status named dnsdist alderpointdns alderpointdns-analytics`.
- Use `alderpointdns-diagnostics --output-dir /tmp` for a sanitized support
  bundle.
- Use `scripts/restore.sh` only for legacy whole-archive emergencies; prefer
  the native `/backup` restore path.
