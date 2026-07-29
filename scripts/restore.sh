#!/bin/sh
set -eu

backup="${1:-}"
[ -n "$backup" ] || { echo "usage: $0 /var/lib/bindguard/backups/bindguard-backup-*.tar.gz" >&2; exit 2; }
[ -f "$backup" ] || { echo "backup not found: $backup" >&2; exit 2; }

case "$backup" in
  /var/lib/bindguard/backups/bindguard-backup-*.tar.gz) ;;
  *) echo "refusing to restore backup outside /var/lib/bindguard/backups" >&2; exit 2 ;;
esac

tmpdir="$(mktemp -d /var/lib/bindguard/staging/restore.XXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT

tar -C "$tmpdir" -xzf "$backup"

named-checkconf -p "$tmpdir/etc/bind/named.conf" >/dev/null
named-checkzone bindguard.rpz "$tmpdir/var/lib/bindguard/compiled/bind/bindguard.rpz" >/dev/null
dnsdist --check-config -C "$tmpdir/etc/dnsdist/dnsdist.conf" >/dev/null
visudo -cf "$tmpdir/etc/sudoers.d/bindguard" >/dev/null

tar -C / -xzf "$backup"
systemctl daemon-reload
systemctl restart named
systemctl restart dnsdist
systemctl restart bindguard-analytics
systemctl restart bindguard

echo "restored $backup"
