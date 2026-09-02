#!/usr/bin/env bash
# ExecStart for apdns-go-live-dns-promote.service -- the one-shot boot
# step that actually launches named+dnsdist on the live appliance.
#
# Neither apdns-go-live-hostagent.service nor apdns-go-live-web.service
# do this themselves: apdns-hostagent only ADOPTS an already-running
# named/dnsdist from a prior generation's PID files (a no-op on a real
# cold boot, since nothing is running yet), and the "web" process only
# ever calls dnsruntime.Orchestrator.Apply from a blocklist-refresh
# completion hook or the owner's own "Apply Runtime Changes" button --
# there is no call to it anywhere in its own startup path (verified in
# cmd/alderpointdns-go/main.go's runWeb during the 2026-09-02 recovery).
# Without this unit, a rebooted appliance would come back with
# management on :8443 but DNS on :53 silently absent until a human
# noticed and promoted by hand -- exactly what happened during that
# outage.
#
# Two real, silent footguns found and fixed live during that recovery,
# both encoded here so they can never regress:
#   1. -config MUST be the HOST-oriented config (real host blocklist/
#      local-dns paths), never the container-internal
#      container-appliance.yaml redeploy-go-live.sh generates for the
#      web container's own mount namespace -- using the wrong one
#      silently compiles an EMPTY blocklist with no error at all.
#   2. -dns-runtime-dnstap-socket MUST be the real host path of the web
#      container's own dnstap LISTEN socket
#      ($GO_LIVE_HOSTAGENT_SOCKET_DIR/dnstap.sock) -- any other path
#      (e.g. under dns-staging/) compiles fine but makes dnsdist crash
#      almost immediately once FrameStreamLogger tries to dial it, with
#      no distinguishing error text ("dnsdist exited immediately after
#      start", only the version banner in dnsdist.startup.log).
set -euo pipefail

GO_LIVE_STATE=/var/lib/apdns-go-live-staging
GO_LIVE_HOSTAGENT_SOCKET_DIR=/run/apdns-go-live-hostagent
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

log() { echo "+ $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# Wait for both real sockets this promote needs -- hostagent's own
# control socket, and the web container's dnstap LISTEN socket (only
# created once that container's own process has actually started) --
# rather than a fixed sleep, matching this deployment's established
# "wait for real evidence" discipline (see redeploy-go-live.sh).
wait_for_socket() {
    local path="$1" waited=0
    while [ ! -S "$path" ]; do
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -ge 30 ] && fail "$path did not appear within 30s"
    done
}
log "waiting for apdns-hostagent socket"
wait_for_socket "$GO_LIVE_HOSTAGENT_SOCKET_DIR/agent.sock"
log "waiting for the web container's dnstap listen socket"
wait_for_socket "$GO_LIVE_HOSTAGENT_SOCKET_DIR/dnstap.sock"

log "checking port 53 is free before promoting"
"$SCRIPT_DIR/check-port53-free.sh" || fail "port 53 conflict check failed (see above)"

log "promoting DNS runtime (named + dnsdist)"
cd "$GO_LIVE_STATE"
runuser -u apdns-go-web -- ./alderpointdns-go dns-promote \
    -db "$GO_LIVE_STATE/data/app.db" \
    -config "$GO_LIVE_STATE/config/appliance.yaml" \
    -migrations "$GO_LIVE_STATE/schema/migrations" \
    -hostagent-socket "$GO_LIVE_HOSTAGENT_SOCKET_DIR/agent.sock" \
    -dns-runtime-dnsdist-addr 0.0.0.0:53 \
    -dns-runtime-bind-proxy-addr 127.0.0.1:26553 \
    -dns-runtime-dnstap-socket "$GO_LIVE_HOSTAGENT_SOCKET_DIR/dnstap.sock" \
    -dns-runtime-tls-cert-path "$GO_LIVE_STATE/certs/server.crt" \
    -dns-runtime-tls-key-path "$GO_LIVE_STATE/certs/server.key" \
    -dry-run=false
