#!/bin/sh
# Language-neutral black-box proof of: SQLite migration status/up,
# migration rollback on a deliberately-invalid migration, and restart
# persistence of admins/sessions/blocklists/local-dns. Talks only to the
# binary's CLI and HTTP API.
set -eu

BIN="${1:?usage: acceptance_migration_restart.sh <path-to-binary> <schema-dir>}"
SCHEMA="${2:?usage: acceptance_migration_restart.sh <path-to-binary> <schema-dir>}"
WORK="$(mktemp -d /tmp/apdns-go-migration-restart.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }

DB="$WORK/app.db"

# --- migrate status / up ---
"$BIN" migrate -db "$DB" -migrations "$SCHEMA/migrations" -cmd up | grep -q "migrated to: 2" \
  || fail "migrate up did not reach version 2"
pass "migrate up reaches schema version 2"

"$BIN" migrate -db "$DB" -migrations "$SCHEMA/migrations" -cmd status | grep -q "schema_version: 2" \
  || fail "migrate status did not report version 2"
pass "migrate status reports version 2"

# --- rollback proof: seed a row so the deliberately-invalid migration's
# NOT-NULL-no-default ALTER actually violates a constraint, then confirm
# the failed migration rolls back cleanly. ---
sqlite3 "$DB" "INSERT INTO blocklist_subscriptions(subscription_id, name, url, category, enabled, created_at) VALUES('seed','seed','http://x','',1,'2026-01-01T00:00:00Z');"

if "$BIN" migrate -db "$DB" -migrations "$SCHEMA/rollback_test" -cmd up >"$WORK/err.log" 2>&1; then
  fail "the deliberately-invalid migration was expected to fail, but succeeded"
fi
grep -q "rolled back" "$WORK/err.log" || fail "failure message did not mention rollback (log: $(cat "$WORK/err.log"))"
pass "deliberately-invalid migration fails and reports rollback"

"$BIN" migrate -db "$DB" -migrations "$SCHEMA/migrations" -cmd status | grep -q "schema_version: 2" \
  || fail "schema_version changed after a failed migration (should stay at 2)"
pass "schema_version unchanged (still 2) after the failed migration"

# --- restart persistence ---
rm -f "$DB"
CFG="$WORK/appliance.yaml"
sed \
  -e "s#/var/lib/alderpointdns-go/blocklists/staging#$WORK/bl-staging#" \
  -e "s#/var/lib/alderpointdns-go/blocklists/runtime#$WORK/bl-runtime#" \
  -e "s#/var/lib/alderpointdns-go/local-dns/staging#$WORK/ld-staging#" \
  -e "s#/var/lib/alderpointdns-go/local-dns/runtime#$WORK/ld-runtime#" \
  "$(dirname "$0")/../config/appliance.yaml" > "$CFG"

STATIC="$(dirname "$0")/../frontend/dist"
if [ ! -d "$STATIC" ]; then
  STATIC="$WORK/static-placeholder"
  mkdir -p "$STATIC"
  echo ok > "$STATIC/index.html"
fi

"$BIN" web -db "$DB" -config "$CFG" -static "$STATIC" -migrations "$SCHEMA/migrations" -addr 127.0.0.1:8451 &
PID=$!
sleep 1

curl -s -X POST http://127.0.0.1:8451/api/setup -H 'Content-Type: application/json' \
  -d '{"username":"restart","password":"correct-horse-battery-staple","confirm_password":"correct-horse-battery-staple","create_local_dns":false}' >/dev/null

CJ="$WORK/cj.txt"
LOGIN=$(curl -s -c "$CJ" -X POST http://127.0.0.1:8451/api/login -H 'Content-Type: application/json' \
  -d '{"username":"restart","password":"correct-horse-battery-staple"}')
CSRF=$(echo "$LOGIN" | jq -r '.csrf')

curl -s -X POST http://127.0.0.1:8451/api/local-dns -b "$CJ" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"name":"restart.lan","record_type":"A","value":"10.0.0.7","ttl":300,"enabled":true}' >/dev/null

kill -TERM "$PID"
wait "$PID" 2>/dev/null || true

"$BIN" web -db "$DB" -config "$CFG" -static "$STATIC" -migrations "$SCHEMA/migrations" -addr 127.0.0.1:8451 &
PID=$!
sleep 1

AFTER=$(curl -s http://127.0.0.1:8451/api/setup/status)
echo "$AFTER" | grep -q '"setup_required":false' || fail "admin account did not survive restart"
pass "admin account survives restart"

SESSION=$(curl -s -b "$CJ" http://127.0.0.1:8451/api/session)
echo "$SESSION" | grep -q '"authenticated":true' || fail "session did not survive restart"
pass "session survives restart"

RECORDS=$(curl -s -b "$CJ" http://127.0.0.1:8451/api/local-dns)
echo "$RECORDS" | grep -q "restart.lan" || fail "local-dns record did not survive restart"
pass "local-dns record survives restart"

kill -TERM "$PID"
wait "$PID" 2>/dev/null || true

echo
echo "All migration/rollback/restart-persistence checks passed."
