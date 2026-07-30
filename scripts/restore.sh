#!/bin/sh
set -eu

backup="${1:-}"
[ -n "$backup" ] || { echo "usage: $0 /var/lib/alderpointdns/backups/alderpointdns-backup-*.tar.gz" >&2; exit 2; }
[ -f "$backup" ] || { echo "backup not found: $backup" >&2; exit 2; }

case "$backup" in
  /var/lib/alderpointdns/backups/alderpointdns-backup-*.tar.gz) ;;
  *) echo "refusing to restore backup outside /var/lib/alderpointdns/backups" >&2; exit 2 ;;
esac

tmpdir="$(mktemp -d /var/lib/alderpointdns/staging/restore.XXXXXX)"
trap 'rm -rf "$tmpdir"' EXIT

tar -C "$tmpdir" -xzf "$backup"

named-checkconf -p "$tmpdir/etc/bind/named.conf" >/dev/null
named-checkzone alderpointdns.rpz "$tmpdir/var/lib/alderpointdns/compiled/bind/alderpointdns.rpz" >/dev/null
dnsdist --check-config -C "$tmpdir/etc/dnsdist/dnsdist.conf" >/dev/null
visudo -cf "$tmpdir/etc/sudoers.d/alderpointdns" >/dev/null

tar -C / -xzf "$backup"
systemctl daemon-reload
systemctl restart named
systemctl restart dnsdist
systemctl restart alderpointdns-analytics
systemctl restart alderpointdns

echo "restored $backup"
