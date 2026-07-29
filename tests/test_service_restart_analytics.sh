#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

before="$(python3 - <<'PY'
import sqlite3
conn = sqlite3.connect('/var/lib/bindguard/bindguard.db')
print(conn.execute('select count(*) from query_events').fetchone()[0])
PY
)"

systemctl restart named
systemctl restart bindguard-analytics
systemctl restart dnsdist
systemctl restart bindguard
systemctl is-active --quiet named || fail "named is not active after restart"
systemctl is-active --quiet dnsdist || fail "dnsdist is not active after restart"
systemctl is-active --quiet bindguard-analytics || fail "bindguard-analytics is not active after restart"
systemctl is-active --quiet bindguard || fail "bindguard is not active after restart"

dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 >/dev/null || fail "DNS failed after service restart"
sleep 3

after="$(python3 - <<'PY'
import sqlite3
conn = sqlite3.connect('/var/lib/bindguard/bindguard.db')
print(conn.execute('select count(*) from query_events').fetchone()[0])
PY
)"

[ "$after" -gt "$before" ] || fail "analytics did not record traffic after service restart"
echo "service restart analytics test passed"
