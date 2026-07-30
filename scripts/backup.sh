#!/bin/sh
set -eu

db="/var/lib/alderpointdns/alderpointdns.db"
staging_dir="/var/lib/alderpointdns/staging"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="/var/lib/alderpointdns/backups/alderpointdns-backup-${stamp}.tar.gz"
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
trap 'rm -rf "$snapshot_root"' EXIT
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
chmod 0640 "$dest"
echo "$dest"
