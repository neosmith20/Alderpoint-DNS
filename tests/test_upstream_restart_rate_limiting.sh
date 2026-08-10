#!/bin/sh
set -eu

# Regression coverage for the v1.0.1 RC #3 continuation: dns1's live
# upstream_deployments history and dnsdist journal conclusively showed that
# a burst of ordinary, *sequential* upstream UI changes (each request
# returning before the next was sent, so nothing was ever truly
# concurrent) restarted dnsdist once per change, closely enough together
# to trip systemd's own start-rate crash-loop protection:
#
#   dnsdist.service: Start request repeated too quickly.
#   dnsdist.service: Failed with result 'start-limit-hit'.
#
# That protection is intentional and must not be weakened -- see
# app/webapp.py's _upstream_deploy_coordinator (min_interval_seconds). This
# test exercises the *real* production coordinator singleton against this
# appliance's *real* dnsdist service (not a mock), the same way
# test_upstream_enabled_set_combinations.sh exercises deploy_upstreams()
# directly -- but here through app.webapp.upstream_deploy_or_raise(), the
# exact function every upstream add/edit/toggle/move/delete route calls, so
# the actual restart-pacing logic is what's under test, not a substitute.

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
need dig

WINDOW_START="$(date '+%Y-%m-%d %H:%M:%S')"

python3 -B - <<'PY' || fail "restart-rate burst exercise failed"
import sys
import threading
import time

sys.path.insert(0, "/opt/alderpointdns")
from app import webapp  # noqa: E402

coordinator = webapp._upstream_deploy_coordinator
print(f"production min_interval_seconds={coordinator._min_interval_seconds}")
if not coordinator._min_interval_seconds or coordinator._min_interval_seconds <= 0:
    print("FAIL: upstream deploy coordinator has no restart-rate limiting configured", file=sys.stderr)
    sys.exit(1)

errors = []
errors_guard = threading.Lock()

def caller() -> None:
    try:
        # Re-deploys the appliance's *current* desired state every time --
        # idempotent, does not mutate upstream_resolvers, safe to hammer.
        webapp.upstream_deploy_or_raise()
    except BaseException as exc:  # noqa: BLE001
        with errors_guard:
            errors.append(exc)

# 10 calls, each fired ~120ms after the last -- comfortably faster than a
# human clicking a checkbox repeatedly, and the same shape as the dns1
# burst (multiple changes within single-digit seconds).
threads = [threading.Thread(target=caller) for _ in range(10)]
burst_start = time.monotonic()
for t in threads:
    t.start()
    time.sleep(0.12)
for t in threads:
    t.join(timeout=60)
burst_elapsed = time.monotonic() - burst_start

if errors:
    print(f"FAIL: {len(errors)} of 10 calls raised: {errors}", file=sys.stderr)
    sys.exit(1)

print(f"burst of 10 sequential-ish calls completed in {burst_elapsed:.2f}s with 0 errors")
PY

echo "== verifying dnsdist never hit systemd's start-rate limit during the burst =="
if journalctl -u dnsdist --since "$WINDOW_START" --no-pager | grep -q 'start-limit-hit'; then
  fail "dnsdist tripped systemd's StartLimitBurst during the restart-rate-limiting test"
fi

echo "== verifying dnsdist restarted far fewer than 10 times for the 10-call burst =="
restart_count="$(journalctl -u dnsdist --since "$WINDOW_START" --no-pager | grep -c 'Started dnsdist.service' || true)"
echo "dnsdist restarted ${restart_count} time(s) during the burst"
[ "$restart_count" -lt 10 ] || fail "10 calls produced ${restart_count} restarts -- coalescing/rate-limiting did not reduce the burst"

echo "== verifying dnsdist and DNS resolution are healthy afterward =="
systemctl is-active --quiet dnsdist || fail "dnsdist is not active after the burst"
dig @127.0.0.1 -p 5353 cloudflare.com A +time=5 +tries=1 | grep -q 'status: NOERROR' || fail "BIND/dnsdist chain did not resolve after the burst"
dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 | grep -q 'status: NOERROR' || fail "dnsdist frontend did not resolve after the burst"

echo "upstream restart rate limiting tests passed"
