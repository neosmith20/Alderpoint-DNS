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

# Regression test for the live-database tar race (scripts/backup.sh used to
# tar var/lib/alderpointdns/alderpointdns.db directly; a writer checkpointing
# its WAL mid-archive could change the file out from under tar, producing
# "file changed as we read it" and a nonzero exit that aborted the
# acceptance suite). Hammer the real live database with committed writes for
# the duration of a real backup.sh run and confirm no race surfaces.
db=/var/lib/alderpointdns/alderpointdns.db
race_err=/tmp/alderpointdns-race-backup.err
race_count=/tmp/alderpointdns-race-writer.count
race_extract="$(mktemp -d /tmp/alderpointdns-race-extract.XXXXXX)"

cleanup_race() {
  rm -rf "$race_extract" "$race_err" "$race_count"
  python3 - "$db" <<'PYEOF' >/dev/null 2>&1 || true
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("DROP TABLE IF EXISTS backup_race_test")
conn.commit()
conn.close()
PYEOF
}
trap cleanup_race EXIT

python3 - "$db" <<'PYEOF'
import sqlite3, sys
conn = sqlite3.connect(sys.argv[1])
conn.execute("CREATE TABLE IF NOT EXISTS backup_race_test (id INTEGER PRIMARY KEY, i INTEGER)")
conn.commit()
conn.close()
PYEOF

python3 - "$db" > "$race_count" <<'PYEOF' &
import sqlite3, sys, time

conn = sqlite3.connect(sys.argv[1], timeout=30)
conn.execute("PRAGMA journal_mode=WAL")
end = time.time() + 4
i = 0
while time.time() < end:
    conn.execute("INSERT INTO backup_race_test(i) VALUES (?)", (i,))
    conn.commit()
    if i % 10 == 0:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    i += 1
conn.close()
print(i)
PYEOF
writer_pid=$!

sleep 0.2  # let the writer get going so the backup genuinely overlaps writes
set +e
race_backup="$(/opt/alderpointdns/scripts/backup.sh 2>"$race_err")"
race_rc=$?
set -e
wait "$writer_pid"

[ "$race_rc" -eq 0 ] || fail "backup.sh exited $race_rc under concurrent writes: $(cat "$race_err")"
grep -q "file changed as we read it" "$race_err" && \
  fail "backup.sh raced the live database (file changed as we read it): $(cat "$race_err")"
[ -s "$race_backup" ] || fail "race backup archive not created"

tar -C "$race_extract" -xzf "$race_backup" var/lib/alderpointdns/alderpointdns.db
race_committed="$(cat "$race_count")"
python3 - "$race_extract/var/lib/alderpointdns/alderpointdns.db" "$race_committed" <<'PYEOF'
import sqlite3, sys

conn = sqlite3.connect(sys.argv[1])
committed = int(sys.argv[2])
integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
assert integrity == "ok", f"race backup snapshot failed integrity check: {integrity}"
rows = conn.execute("SELECT count(*) FROM backup_race_test").fetchone()[0]
assert rows <= committed, f"race backup snapshot has more rows ({rows}) than were ever committed ({committed})"
conn.close()
PYEOF

echo "backup and restore tests passed"
