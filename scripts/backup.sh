#!/bin/sh
set -eu
umask 077

db="/var/lib/alderpointdns/alderpointdns.db"
staging_dir="/var/lib/alderpointdns/staging"
backups_dir="/var/lib/alderpointdns/backups"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="${backups_dir}/alderpointdns-backup-${stamp}.tar.gz"
tmp="${dest}.tmp"

# The live database is written continuously by the web app and analytics
# collector (WAL mode), so tarring it in place can race a checkpoint and
# either corrupt the archive or trip tar's "file changed as we read it"
# warning. Take a transactionally consistent copy first via SQLite's own
# online backup API (which correctly folds in any WAL content) and archive
# that snapshot instead of the live file. The snapshot lives under a temp
# dir that always gets cleaned up, whether this script succeeds or fails.
mkdir -p "$staging_dir"
snapshot_root="$(mktemp -d "${staging_dir}/backup-snapshot.XXXXXX")"
# Also remove the in-progress archive if this script is interrupted (signal,
# `set -eu` early exit) before the final mv below renames it into place --
# otherwise a killed run leaves a permanent, untracked orphan in the real
# backups directory. Limit cleanup to the exact temp-name patterns this script
# owns, so an empty or malformed variable cannot delete unrelated files. Once
# the mv succeeds, $tmp no longer exists, so this is a harmless no-op on the
# normal success path.
cleanup_on_exit() {
  case "${snapshot_root:-}" in
    "$staging_dir"/backup-snapshot.*) rm -rf -- "$snapshot_root" ;;
  esac
  case "${tmp:-}" in
    "$backups_dir"/alderpointdns-backup-*.tar.gz.tmp) rm -f -- "$tmp" ;;
  esac
}
trap cleanup_on_exit EXIT
trap 'cleanup_on_exit; exit 143' INT TERM HUP
snapshot_dir="$snapshot_root/var/lib/alderpointdns"
mkdir -p "$snapshot_dir"
snapshot_db="$snapshot_dir/alderpointdns.db"

python3 - "$db" "$snapshot_db" <<'PYEOF'
import sqlite3
import sys

src = sqlite3.connect(sys.argv[1])
try:
    dst = sqlite3.connect(sys.argv[2])
    try:
        src.backup(dst)
    finally:
        dst.close()
finally:
    src.close()
PYEOF

# Preserve the live database's ownership and restrictive permissions on the
# snapshot so they carry through into the archive and, later, the restore.
chown --reference="$db" "$snapshot_db"
chmod --reference="$db" "$snapshot_db"

if [ "${ALDERPOINTDNS_BACKUP_TEST_PAUSE_AFTER_TMP_CREATE:-}" ]; then
  : > "$tmp"
  sleep "$ALDERPOINTDNS_BACKUP_TEST_PAUSE_AFTER_TMP_CREATE"
fi

tar -C / -czf "$tmp" \
  etc/alderpointdns \
  etc/bind/named.conf \
  etc/bind/named.conf.options \
  etc/bind/named.conf.local \
  etc/dnsdist/dnsdist.conf \
  etc/systemd/system/alderpointdns.service \
  etc/systemd/system/alderpointdns-analytics.service \
  etc/systemd/system/dnsdist.service.d \
  etc/sudoers.d/alderpointdns \
  var/lib/alderpointdns/downloads \
  var/lib/alderpointdns/compiled \
  opt/alderpointdns \
  -C "$snapshot_root" var/lib/alderpointdns/alderpointdns.db

mv "$tmp" "$dest"
# This script always runs as root (upgrade.sh's pre-upgrade safety net), so
# the archive would otherwise be root:root and unreadable by the alderpointdns
# web process -- matching app/backup.py's harden_backup_file_permissions().
chown root:alderpointdns "$dest" 2>/dev/null || true
chmod 0640 "$dest"
echo "$dest"
