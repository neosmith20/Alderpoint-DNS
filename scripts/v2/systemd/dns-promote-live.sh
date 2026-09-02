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
#
# A THIRD real rough edge found live (2026-09-02, first real deploy
# through these units): apdns-go-live-dns-promote.service Requires= the
# hostagent unit, so a routine `systemctl restart
# apdns-go-live-hostagent.service` (e.g. from redeploy-go-live.sh) tears
# this unit down too, and systemd restarts it automatically -- landing
# right back here with named/dnsdist already alive and fine (adopted by
# the freshly-restarted hostagent). Without the check below, that retry
# always failed via check-port53-free.sh (dnsdist already legitimately
# owns :53), leaving `systemctl status` on this unit looking like a real
# failure -- misleading operational UX, even though DNS never actually
# broke. The check below asks apdns-hostagent directly (dns_runtime.status)
# whether it ALREADY considers both named and dnsdist running before
# ever attempting a promote; only if that's not already true does this
# script go on to actually promote, where check-port53-free.sh still
# catches a genuine rival (some other, unexpected process on :53) with
# its normal clear failure.
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

log "checking whether apdns-hostagent already considers DNS runtime healthy"
# Speaks the raw hostagent wire protocol directly (one JSON line
# request, one JSON line response over the -allowed-uid-gated unix
# socket -- see internal/hostagent/protocol.go) rather than shelling
# out to a Go binary; there's no existing CLI subcommand that just
# prints dns_runtime.status, and inline here (as apdns-go-web, which is
# what -allowed-uid actually authenticates via SO_PEERCRED, not
# anything in the request body) avoids adding a whole separate script
# file under a path apdns-go-web can't traverse (/root/... is 750
# root:root).
already_healthy=0
if runuser -u apdns-go-web -- python3 -c '
import json, socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(sys.argv[1])
    s.sendall((json.dumps({"op": "dns_runtime.status", "request_id": "promote-precheck"}) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    s.close()
    resp = json.loads(buf.decode())
    result = resp.get("result") or {}
    bind_running = bool(result.get("bind_running"))
    dnsdist_running = bool(result.get("dnsdist_running"))
    ok = bool(resp.get("ok")) and bind_running and dnsdist_running
    sys.stderr.write("bind_running=%s dnsdist_running=%s\n" % (bind_running, dnsdist_running))
    sys.exit(0 if ok else 1)
except Exception as e:
    print(f"could not check: {e}", file=sys.stderr)
    sys.exit(1)
' "$GO_LIVE_HOSTAGENT_SOCKET_DIR/agent.sock"; then
    already_healthy=1
fi

if [ "$already_healthy" -eq 1 ]; then
    log "apdns-hostagent already reports named+dnsdist running (adopted from a prior generation, most likely a routine hostagent restart) -- skipping a redundant promote"
    exit 0
fi

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
