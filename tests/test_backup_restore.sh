#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

backup="$(/opt/alderpointdns/scripts/backup.sh)"
[ -s "$backup" ] || fail "backup archive not created"
tar -tzf "$backup" | grep -q 'var/lib/alderpointdns/alderpointdns.db' || fail "backup missing database"
tar -tzf "$backup" | grep -q 'etc/dnsdist/dnsdist.conf' || fail "backup missing dnsdist config"
tar -tzf "$backup" | grep -q 'etc/systemd/system/dnsdist.service.d/alderpointdns.conf' || fail "backup missing dnsdist service drop-in"
/opt/alderpointdns/scripts/restore.sh "$backup" >/tmp/alderpointdns-restore-test.out
/opt/alderpointdns/tests/test_bind_backend.sh >/dev/null || fail "BIND failed after restore"
/opt/alderpointdns/tests/test_dnsdist_frontend.sh >/dev/null || fail "dnsdist failed after restore"
/opt/alderpointdns/tests/test_web_smoke.sh >/dev/null || fail "web failed after restore"

echo "backup and restore tests passed"
