#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

before="$(python3 - <<'PY'
import sqlite3
conn = sqlite3.connect('/var/lib/alderpointdns/alderpointdns.db')
print(conn.execute('select count(*) from query_events').fetchone()[0])
PY
)"

systemctl restart named
systemctl restart alderpointdns-analytics
systemctl restart dnsdist
systemctl restart alderpointdns
systemctl is-active --quiet named || fail "named is not active after restart"
systemctl is-active --quiet dnsdist || fail "dnsdist is not active after restart"
systemctl is-active --quiet alderpointdns-analytics || fail "alderpointdns-analytics is not active after restart"
systemctl is-active --quiet alderpointdns || fail "alderpointdns is not active after restart"

after="$before"
for _ in 1 2 3 4 5 6 7 8 9 10; do
  dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 >/dev/null || fail "DNS failed after service restart"
  sleep 2
  after="$(python3 - <<'PY'
import sqlite3
conn = sqlite3.connect('/var/lib/alderpointdns/alderpointdns.db')
print(conn.execute('select count(*) from query_events').fetchone()[0])
PY
)"
  [ "$after" -gt "$before" ] && break
done

[ "$after" -gt "$before" ] || fail "analytics did not record traffic after service restart"
echo "service restart analytics test passed"
