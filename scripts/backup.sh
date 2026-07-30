#!/bin/sh
set -eu

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="/var/lib/alderpointdns/backups/alderpointdns-backup-${stamp}.tar.gz"
tmp="${dest}.tmp"

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
  var/lib/alderpointdns/alderpointdns.db \
  var/lib/alderpointdns/downloads \
  var/lib/alderpointdns/compiled \
  opt/alderpointdns

mv "$tmp" "$dest"
chmod 0640 "$dest"
echo "$dest"
