#!/bin/sh
set -eu

# Regression test for a real appliance restore failure: restore_history
# ended status=interrupted, phase=restarting_services, promoted_at
# non-null -- the database had already been promoted, but the restore
# worker itself vanished right when the restore's own app_config
# component restarted alderpointdns.service. Journal timeline confirmed
# it: the worker (a `sudo alderpointdns_compiler.py backup-restore`
# process spawned as a direct child of the web request's own process
# tree) was still inside alderpointdns.service's cgroup when that same
# unit was torn down and restarted, killing it mid-restore, after the
# database had already committed but before postchecks/final status could
# run.
#
# The fix moves restore execution to its own independent systemd unit
# (packaging/alderpointdns-backup-restore.service, started via `systemctl
# start --no-block` -- see app/webapp.py's backup_restore_apply(), the
# exact pattern already used for Software Updates' install runner). This
# test proves the underlying mechanism that fix depends on, live, on this
# real systemd host: a process started as a direct child of a unit's own
# process tree is killed when that unit is restarted; a process started
# as its own, separately `systemctl start`-ed unit is not -- using
# synthetic, disposable transient/runtime-only units so it never touches
# the real alderpointdns.service or any production unit file.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

command -v systemd-run >/dev/null 2>&1 || fail "systemd-run is required"

WORK="$(mktemp -d /tmp/alderpointdns-restore-lifecycle-test.XXXXXX)"
WORKER_UNIT_FILE="/run/systemd/system/alderpointdns-lifecycle-test-worker.service"
cleanup() {
  systemctl stop alderpointdns-lifecycle-test-parent.service alderpointdns-lifecycle-test-worker.service >/dev/null 2>&1 || true
  rm -f "$WORKER_UNIT_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

DIRECT_CHILD_MARKER="$WORK/direct-child-finished"
INDEPENDENT_WORKER_MARKER="$WORK/independent-worker-finished"

# A real (if disposable, runtime-only) unit file -- /run/systemd/system/
# is the standard location for units generated/managed outside dpkg, and
# is never touched by packaging -- so `systemctl start --no-block` against
# it below has the same shape as the real fix's `systemctl start --no-block
# alderpointdns-backup-restore.service` against the real, package-installed
# unit at /lib/systemd/system/.
cat > "$WORKER_UNIT_FILE" <<EOF
[Service]
Type=oneshot
ExecStart=/bin/sh -c "sleep 3; touch '$INDEPENDENT_WORKER_MARKER'"
EOF
systemctl daemon-reload

# The "parent" unit stands in for alderpointdns.service: its ExecStart
# spawns two things before exiting immediately --
#   1. a DIRECT background child (the old, broken shape: a raw subprocess
#      of a process inside the parent unit's own cgroup)
#   2. an INDEPENDENT worker via `systemctl start --no-block` on the
#      separate unit above (the fix's shape)
# both sleep briefly and then touch their marker file. The test driver
# then stops the parent (systemd's equivalent of the app_config restart a
# real restore triggers) before either sleep completes, and checks which
# marker actually got created.
# The trailing `sleep 30` keeps the parent's main process (and therefore
# the unit itself) alive and "active" long enough for the test driver to
# explicitly stop it mid-flight below -- matching a real, long-running
# alderpointdns.service getting restarted while a restore it dispatched is
# still in progress, rather than a unit that has already exited on its
# own by the time anything tries to stop it.
systemd-run --collect --unit=alderpointdns-lifecycle-test-parent \
  /bin/sh -c "(sleep 3; touch '$DIRECT_CHILD_MARKER') & systemctl start --no-block alderpointdns-lifecycle-test-worker.service; sleep 30"

# Give both the direct child and the independent worker unit time to
# actually start before we tear the parent down -- this must not be a
# race where the parent is stopped before either one even begins.
# (A Type=oneshot unit with no RemainAfterExit reports ActiveState
# "activating" for its whole run, never plain "active" -- `systemctl
# is-active` alone would never match it.)
worker_started=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  state="$(systemctl show -p ActiveState --value alderpointdns-lifecycle-test-worker.service 2>/dev/null || true)"
  case "$state" in
    active | activating) worker_started=1; break ;;
  esac
  sleep 0.3
done
[ -n "$worker_started" ] || fail "the independent worker unit never started -- test setup itself is broken"

# Tear down the "parent" unit's cgroup -- the same lifecycle event a real
# alderpointdns.service restart is for whatever was still running inside
# it. The independent worker unit is untouched by this.
systemctl stop alderpointdns-lifecycle-test-parent.service

# Now wait long enough for the sleep 3 in *either* marker's command to
# have completed, were it going to.
sleep 4

if [ -e "$DIRECT_CHILD_MARKER" ]; then
  fail "test setup did not reproduce the bug precondition: a direct background child of the parent unit survived the parent being stopped, so this test cannot prove anything -- environment does not have real cgroup-scoped SIGKILL-on-stop behavior"
fi

[ -e "$INDEPENDENT_WORKER_MARKER" ] || \
  fail "the independent systemd unit was ALSO killed when the parent unit was stopped -- systemctl start --no-block on a separate unit does not actually survive the parent's restart on this host, so the real fix (packaging/alderpointdns-backup-restore.service) would not work either"

echo "restore worker service lifecycle test passed"
