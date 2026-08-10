#!/bin/sh
set -eu

# Regression coverage for the v1.0.1 RC #3 continuation, revised against
# dns1's *actual* installed dnsdist.service policy:
#
#   StartLimitIntervalUSec=1min
#   StartLimitBurst=5
#
# (not systemd's generic 10s/5 default the first pass at this fix assumed
# -- a 3s restart-pacing interval is NOT safe against a 60s/5 policy: six
# restarts 3s apart still all land inside a rolling 60s window).
#
# dns1's live upstream_deployments history and dnsdist journal showed a
# burst of ordinary *sequential* upstream UI changes (each request
# returning before the next was sent, so nothing was ever truly
# concurrent) restarting dnsdist once per change, closely enough together
# to trip that real policy:
#
#   dnsdist.service: Start request repeated too quickly.
#   dnsdist.service: Failed with result 'start-limit-hit'.
#
# That protection is intentional and must not be weakened -- see
# app/webapp.py's _upstream_deploy_coordinator. The real fix is
# architectural, not just pacing: app.upstream_dns.deploy_upstreams() now
# applies ordinary upstream changes to the already-running dnsdist over its
# console (newServer()/rmServer(), an officially supported dnsdist runtime
# reconfiguration mechanism) instead of restarting the process at all --
# see deploy_upstreams()'s _console_reconcile() docstring. Pacing
# (min_interval_seconds) remains only as a backstop for whenever that isn't
# possible. This test exercises the *real* production coordinator against
# this appliance's *real* dnsdist service (not a mock) through
# app.webapp.upstream_deploy_or_raise(), the exact function every upstream
# add/edit/toggle/move/delete route calls, with more than five genuine,
# sequential desired-state changes -- not just idempotent re-deploys of the
# same state -- fired one after another exactly the way a browser sends
# them (each request completing before the next is issued).

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

need python3
need journalctl
need systemctl
need sqlite3
need dig

DB=/var/lib/alderpointdns/alderpointdns.db
SNAPSHOT=$(mktemp)
sqlite3 "$DB" ".mode insert upstream_resolvers" "SELECT * FROM upstream_resolvers;" > "$SNAPSHOT"
restore() {
  sqlite3 "$DB" "DELETE FROM upstream_resolvers;"
  sqlite3 "$DB" < "$SNAPSHOT"
  /opt/alderpointdns/app/alderpointdns_compiler.py upstream-deploy >/dev/null 2>&1 || true
  rm -f "$SNAPSHOT"
}
trap restore EXIT

WINDOW_START="$(date '+%Y-%m-%d %H:%M:%S')"

python3 -B - <<'PY' || fail "sequential burst exercise failed"
import sqlite3
import sys
import time

sys.path.insert(0, "/opt/alderpointdns")
from app import upstream_dns, webapp  # noqa: E402

coordinator = webapp._upstream_deploy_coordinator
print(f"production min_interval_seconds={coordinator._min_interval_seconds}")
if not coordinator._min_interval_seconds or coordinator._min_interval_seconds <= 0:
    print("FAIL: upstream deploy coordinator has no restart-rate limiting configured", file=sys.stderr)
    sys.exit(1)

conn = sqlite3.connect(upstream_dns.DB_PATH)
conn.row_factory = sqlite3.Row
ids = [row["id"] for row in conn.execute("SELECT id FROM upstream_resolvers ORDER BY position, id")]
conn.close()
if len(ids) < 2:
    print("FAIL: this test needs at least 2 existing upstream resolvers to toggle safely", file=sys.stderr)
    sys.exit(1)

# More than dns1's StartLimitBurst=5: 8 genuine, sequential desired-state
# changes (not idempotent re-deploys of the same state) -- toggle the
# second resolver off and back on repeatedly, each request completing
# before the next is sent, exactly like a browser.
target = ids[1]
call_count = 8
start = time.monotonic()
for i in range(call_count):
    upstream_dns.set_enabled(target, enabled=(i % 2 == 1))
    webapp.upstream_deploy_or_raise()
elapsed = time.monotonic() - start
print(f"{call_count} sequential real desired-state changes completed in {elapsed:.2f}s")

# Leave it enabled -- the shell trap restores the full original snapshot
# regardless, but this keeps the appliance healthy for the rest of this
# script's own checks too.
upstream_dns.set_enabled(target, enabled=True)
webapp.upstream_deploy_or_raise()
PY

echo "== verifying dnsdist never hit systemd's real start-limit policy during the burst =="
if journalctl -u dnsdist --since "$WINDOW_START" --no-pager | grep -q 'start-limit-hit'; then
  fail "dnsdist tripped its real StartLimitBurst=5/60s policy during the restart-rate-limiting test"
fi

echo "== verifying dnsdist restarted well under dns1's StartLimitBurst=5 for the 8-change burst =="
restart_count="$(journalctl -u dnsdist --since "$WINDOW_START" --no-pager | grep -c 'Started dnsdist.service' || true)"
echo "dnsdist restarted ${restart_count} time(s) during 8 genuine sequential desired-state changes"
[ "$restart_count" -lt 5 ] || fail "8 changes produced ${restart_count} restarts -- not safely under dns1's real StartLimitBurst=5"

echo "== verifying DB desired state matches live runtime state =="
db_enabled_addresses="$(sqlite3 "$DB" "SELECT address || ':' || port FROM upstream_resolvers WHERE enabled=1 ORDER BY address;")"
live_addresses="$(dnsdist -e "showServers()" | awk '$NF == "alderpointdns_upstreams" {print $3}' | sort)"
[ "$(echo "$db_enabled_addresses" | sort)" = "$live_addresses" ] || fail "DB enabled resolver set does not match dnsdist's live pool: DB=[$db_enabled_addresses] live=[$live_addresses]"

echo "== verifying deployment history is truthful =="
sqlite3 "$DB" "SELECT status, message FROM upstream_deployments ORDER BY id DESC LIMIT 1;" | grep -q '^deployed|' || fail "most recent deployment history entry is not truthfully 'deployed'"

echo "== verifying DNS stays available =="
systemctl is-active --quiet dnsdist || fail "dnsdist is not active after the burst"
dig @127.0.0.1 -p 5353 cloudflare.com A +time=5 +tries=1 | grep -q 'status: NOERROR' || fail "BIND/dnsdist chain did not resolve after the burst"
dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 | grep -q 'status: NOERROR' || fail "dnsdist frontend did not resolve after the burst"

echo "upstream restart rate limiting tests passed"
