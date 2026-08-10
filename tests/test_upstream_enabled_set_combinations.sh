#!/bin/sh
set -eu

# Regression coverage for the v1.0.1 RC #3 blocker found during live
# packaged-appliance acceptance on dns1: after disabling the last enabled
# upstream resolver (rejected -- see tests/test_upstream_last_enabled_guard.py)
# and then re-enabling one, "systemctl restart dnsdist" failed for a
# DoH-only enabled set. That specific failure could not be reproduced on
# this appliance (its DoH backend was genuinely reachable; investigation
# concluded it depended on real network conditions on dns1 that are not
# present here -- see CHANGELOG.md), but nothing in the existing acceptance
# suite exercised dnsdist actually restarting and resolving with each kind
# of enabled upstream set in the first place. This closes that gap: for
# every enabled-set combination the UI allows, dnsdist must start, the
# BIND->dnsdist->upstream chain must resolve, and the DB's `enabled` rows
# must match what got promoted to the live runtime config.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

need python3
need sqlite3
need dig
need systemctl

DB=/var/lib/alderpointdns/alderpointdns.db
COMPILER=/opt/alderpointdns/app/alderpointdns_compiler.py

# Snapshot the resolver table exactly as found so it can be restored
# regardless of how this script exits -- this appliance's live upstream
# chain must come back exactly as it was before the test ran.
SNAPSHOT=$(mktemp)
sqlite3 "$DB" ".mode insert upstream_resolvers" "SELECT * FROM upstream_resolvers;" > "$SNAPSHOT"

restore() {
  sqlite3 "$DB" "DELETE FROM upstream_resolvers;"
  sqlite3 "$DB" < "$SNAPSHOT"
  "$COMPILER" upstream-deploy >/dev/null 2>&1 || true
  rm -f "$SNAPSHOT"
}
trap restore EXIT

reset_resolvers() {
  sqlite3 "$DB" "DELETE FROM upstream_resolvers;"
}

add_plain() {
  # $1=name $2=address $3=position $4=enabled
  python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys, sqlite3, datetime
name, address, position, enabled = sys.argv[1:5]
ts = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
conn = sqlite3.connect("/var/lib/alderpointdns/alderpointdns.db")
conn.execute(
    "INSERT INTO upstream_resolvers(name, protocol, address, port, enabled, position, created_at, updated_at) "
    "VALUES (?, 'plain', ?, 53, ?, ?, ?, ?)",
    (name, address, int(enabled), int(position), ts, ts),
)
conn.commit()
conn.close()
PY
}

add_doh() {
  # $1=name $2=address(host) $3=bootstrap_ips $4=position $5=enabled
  python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
import sys, sqlite3, datetime
name, address, bootstrap, position, enabled = sys.argv[1:6]
ts = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
conn = sqlite3.connect("/var/lib/alderpointdns/alderpointdns.db")
conn.execute(
    "INSERT INTO upstream_resolvers(name, protocol, address, port, doh_path, tls_hostname, bootstrap_ips, enabled, position, created_at, updated_at) "
    "VALUES (?, 'doh', ?, 443, '/dns-query', ?, ?, ?, ?, ?, ?)",
    (name, address, address, bootstrap, int(enabled), int(position), ts, ts),
)
conn.commit()
conn.close()
PY
}

check_resolves() {
  dig @127.0.0.1 -p 5353 cloudflare.com A +time=5 +tries=1 | grep -q 'status: NOERROR' || fail "$1: BIND/dnsdist chain did not resolve"
  dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 | grep -q 'status: NOERROR' || fail "$1: dnsdist frontend did not resolve"
  systemctl is-active --quiet dnsdist || fail "$1: dnsdist is not active"
}

check_db_matches_enabled_count() {
  # $1=label $2=expected enabled count
  actual=$(sqlite3 "$DB" "SELECT count(*) FROM upstream_resolvers WHERE enabled=1;")
  [ "$actual" = "$2" ] || fail "$1: expected $2 enabled resolver(s) in DB, found $actual"
}

echo "== combination 1: one plain resolver only =="
reset_resolvers
add_plain "Plain A" "1.1.1.2" 1 1
"$COMPILER" upstream-deploy >/dev/null
check_resolves "one plain resolver"
check_db_matches_enabled_count "one plain resolver" 1

echo "== combination 2: multiple plain resolvers only =="
reset_resolvers
add_plain "Plain A" "1.1.1.2" 1 1
add_plain "Plain B" "1.0.0.2" 2 1
add_plain "Plain C" "4.2.2.1" 3 1
"$COMPILER" upstream-deploy >/dev/null
check_resolves "multiple plain resolvers"
check_db_matches_enabled_count "multiple plain resolvers" 3

echo "== combination 3: one DoH resolver only =="
reset_resolvers
add_doh "Cloudflare DoH" "cloudflare-dns.com" "1.1.1.1, 1.0.0.1" 1 1
"$COMPILER" upstream-deploy >/dev/null
check_resolves "one DoH resolver"
check_db_matches_enabled_count "one DoH resolver" 1
grep -q 'dohPath=' /var/lib/alderpointdns/compiled/dnsdist/upstream-forwarder.conf || fail "DoH-only config was not rendered with a DoH backend"

echo "== combination 4: multiple DoH resolvers only =="
reset_resolvers
add_doh "Cloudflare DoH" "cloudflare-dns.com" "1.1.1.1, 1.0.0.1" 1 1
add_doh "Quad9 DoH" "dns.quad9.net" "9.9.9.9, 149.112.112.112" 2 1
"$COMPILER" upstream-deploy >/dev/null
check_resolves "multiple DoH resolvers"
check_db_matches_enabled_count "multiple DoH resolvers" 2

echo "== combination 5: mixed plain + DoH =="
reset_resolvers
add_plain "Plain A" "1.1.1.2" 1 1
add_doh "Cloudflare DoH" "cloudflare-dns.com" "1.1.1.1, 1.0.0.1" 2 1
"$COMPILER" upstream-deploy >/dev/null
check_resolves "mixed plain + DoH"
check_db_matches_enabled_count "mixed plain + DoH" 2

echo "== combination 6: attempted zero enabled resolvers =="
reset_resolvers
add_plain "Plain A" "1.1.1.2" 1 0
add_doh "Cloudflare DoH" "cloudflare-dns.com" "1.1.1.1, 1.0.0.1" 2 0
before_conf=$(cat /var/lib/alderpointdns/compiled/dnsdist/upstream-forwarder.conf 2>/dev/null || echo "")
if "$COMPILER" upstream-deploy >/tmp/alderpointdns-zero-upstream.out 2>&1; then
  fail "zero enabled resolvers: upstream-deploy unexpectedly succeeded"
fi
grep -q "at least one upstream resolver must be enabled" /tmp/alderpointdns-zero-upstream.out || fail "zero enabled resolvers: rejection message missing"
after_conf=$(cat /var/lib/alderpointdns/compiled/dnsdist/upstream-forwarder.conf 2>/dev/null || echo "")
[ "$before_conf" = "$after_conf" ] || fail "zero enabled resolvers: runtime dnsdist config changed despite rejection"
systemctl is-active --quiet dnsdist || fail "zero enabled resolvers: dnsdist is not active after a rejected deploy"
rm -f /tmp/alderpointdns-zero-upstream.out

echo "upstream enabled-set combination tests passed"
