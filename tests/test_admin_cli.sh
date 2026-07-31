#!/bin/sh
set -eu

ROOT="$(mktemp -d /tmp/alderpointdns-admin-cli-test.XXXXXX)"
trap 'rm -rf "$ROOT"' EXIT

DB_PATH="$ROOT/alderpointdns.db"
CLI="/opt/alderpointdns/scripts/alderpointdns-admin"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# --- root privilege is required -------------------------------------------
# Regardless of the uid running this test suite, invoking the CLI as an
# unprivileged account must be rejected before it ever touches the database.
if runuser -u nobody -- python3 "$CLI" admin list >"$ROOT/nonroot.out" 2>&1; then
  fail "admin list succeeded as a non-root user"
fi
grep -qi "must be run as root" "$ROOT/nonroot.out" || fail "non-root rejection message missing"

if [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: remaining alderpointdns-admin checks require root; ran non-root rejection check only" >&2
  exit 0
fi

# --- seed a fake admin + an "other" session, mirroring the web app schema --
python3 -B - "$DB_PATH" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.execute(
    "CREATE TABLE admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
)
conn.execute(
    "INSERT INTO admins(username, password_hash, created_at) VALUES ('admin', 'placeholder-not-a-real-hash', 'now')"
)
conn.execute(
    "CREATE TABLE sessions (id TEXT PRIMARY KEY, admin_id INTEGER, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT, csrf TEXT NOT NULL)"
)
conn.execute(
    "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES ('sess-1', 1, 'now', 'now', '10.0.0.5', 'browser', 'csrf-1')"
)
conn.commit()
conn.close()
PY

# --- admin list -------------------------------------------------------------
ALDERPOINTDNS_DB_PATH="$DB_PATH" python3 "$CLI" admin list | grep -q "^admin" || fail "admin list did not show the seeded account"

# --- reset-password via stdin (scripted/non-interactive path) --------------
NEW_PASSWORD="brand-new-recovered-password-789"
RESET_OUTPUT="$(printf '%s\n' "$NEW_PASSWORD" | ALDERPOINTDNS_DB_PATH="$DB_PATH" python3 "$CLI" admin reset-password)"
echo "$RESET_OUTPUT" | grep -q "Password reset for 'admin'" || fail "reset-password did not report success"
echo "$RESET_OUTPUT" | grep -q "1 active web session" || fail "reset-password did not report the revoked session count"
case "$RESET_OUTPUT" in
  *"$NEW_PASSWORD"*) fail "reset-password printed the plaintext password" ;;
esac

python3 -B - "$DB_PATH" "$NEW_PASSWORD" <<'PY'
import sqlite3
import sys

sys.path.insert(0, "/opt/alderpointdns")
from app.auth import verify_password

db_path, new_password = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
row = conn.execute("SELECT password_hash FROM admins WHERE username='admin'").fetchone()
assert verify_password(row["password_hash"], new_password), "new password does not verify with app.auth"
assert row["password_hash"] != "placeholder-not-a-real-hash"

sessions = conn.execute("SELECT count(*) FROM sessions WHERE admin_id=1").fetchone()[0]
assert sessions == 0, f"expected all sessions revoked, found {sessions}"

audit = conn.execute(
    "SELECT action, success, detail FROM admin_audit_log WHERE action='password_reset_local_recovery' ORDER BY id DESC LIMIT 1"
).fetchone()
assert audit is not None, "no audit log entry for the reset"
assert audit["success"] == 1
assert new_password not in audit["detail"]
assert "placeholder" not in audit["detail"]
print("db assertions passed")
PY

# --- revoke-sessions without changing the password --------------------------
python3 -B - "$DB_PATH" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.execute(
    "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES ('sess-2', 1, 'now', 'now', '10.0.0.6', 'browser2', 'csrf-2')"
)
conn.commit()
conn.close()
PY

REVOKE_OUTPUT="$(ALDERPOINTDNS_DB_PATH="$DB_PATH" python3 "$CLI" admin revoke-sessions)"
echo "$REVOKE_OUTPUT" | grep -q "1 active web session" || fail "revoke-sessions did not report the revoked session count"

python3 -B - "$DB_PATH" "$NEW_PASSWORD" <<'PY'
import sqlite3
import sys

sys.path.insert(0, "/opt/alderpointdns")
from app.auth import verify_password

db_path, new_password = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
sessions = conn.execute("SELECT count(*) FROM sessions WHERE admin_id=1").fetchone()[0]
assert sessions == 0, f"expected sessions revoked, found {sessions}"
row = conn.execute("SELECT password_hash FROM admins WHERE username='admin'").fetchone()
assert verify_password(row["password_hash"], new_password), "revoke-sessions must not change the password"
print("revoke-sessions assertions passed")
PY

# --- multiple admins requires --username ------------------------------------
python3 -B - "$DB_PATH" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES ('second-admin', 'placeholder-not-a-real-hash', 'now')")
conn.commit()
conn.close()
PY

if printf '%s\n' "irrelevant-password-value" | ALDERPOINTDNS_DB_PATH="$DB_PATH" python3 "$CLI" admin reset-password >"$ROOT/ambiguous.out" 2>&1; then
  fail "reset-password without --username succeeded despite multiple administrators"
fi
grep -qi "specify --username" "$ROOT/ambiguous.out" || fail "ambiguous-admin error message missing"

echo "alderpointdns-admin CLI tests passed"
