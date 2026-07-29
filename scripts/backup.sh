#!/bin/sh
set -eu

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
dest="/var/lib/bindguard/backups/bindguard-backup-${stamp}.tar.gz"
tmp="${dest}.tmp"

tar -C / -czf "$tmp" \
  etc/bindguard \
  etc/bind/named.conf \
  etc/bind/named.conf.options \
  etc/bind/named.conf.local \
  etc/dnsdist/dnsdist.conf \
  etc/systemd/system/bindguard.service \
  etc/systemd/system/bindguard-analytics.service \
  etc/systemd/system/dnsdist.service.d \
  etc/sudoers.d/bindguard \
  var/lib/bindguard/bindguard.db \
  var/lib/bindguard/downloads \
  var/lib/bindguard/compiled \
  opt/bindguard

mv "$tmp" "$dest"
chmod 0640 "$dest"
echo "$dest"
