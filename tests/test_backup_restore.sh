#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

backup="$(/opt/bindguard/scripts/backup.sh)"
[ -s "$backup" ] || fail "backup archive not created"
tar -tzf "$backup" | grep -q 'var/lib/bindguard/bindguard.db' || fail "backup missing database"
tar -tzf "$backup" | grep -q 'etc/dnsdist/dnsdist.conf' || fail "backup missing dnsdist config"
tar -tzf "$backup" | grep -q 'etc/systemd/system/dnsdist.service.d/bindguard.conf' || fail "backup missing dnsdist service drop-in"
/opt/bindguard/scripts/restore.sh "$backup" >/tmp/bindguard-restore-test.out
/opt/bindguard/tests/test_bind_backend.sh >/dev/null || fail "BIND failed after restore"
/opt/bindguard/tests/test_dnsdist_frontend.sh >/dev/null || fail "dnsdist failed after restore"
/opt/bindguard/tests/test_web_smoke.sh >/dev/null || fail "web failed after restore"

echo "backup and restore tests passed"
