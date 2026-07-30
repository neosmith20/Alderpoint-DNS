# Backup and Recovery Guide

Routine backups:

- Use `/backup` for previewable, checksummed backups.
- Keep private keys/credentials excluded unless the recovery scenario requires
  them.
- Use password encryption for backups that leave the VM.
- Scheduled backups use `alderpointdns-backup.timer`.

Restore workflow:

1. Upload or select a backup.
2. Preview the restore.
3. Confirm selected components.
4. Alderpoint DNS takes a safety backup before applying.
5. BIND/dnsdist configuration is validated.
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
