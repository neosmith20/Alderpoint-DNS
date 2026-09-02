#!/usr/bin/env bash
# ExecStartPost for apdns-go-live-web.service.
#
# Type=simple only tells systemd a unit is "active" the instant its
# ExecStart process forks -- for `podman start -a`, that's the moment
# conmon attaches, well before the web process inside the container has
# actually finished starting (bound its dnstap LISTEN socket, answered
# a real health check). Without this gate, apdns-go-live-dns-promote.service
# (After=/Requires= this unit) can start racing that startup window --
# confirmed live during the 2026-09-02 systemd rollout: the very first
# cold-start attempt failed because the dnstap socket didn't exist yet,
# and only succeeded on Restart=on-failure's automatic retry a few
# seconds later. This makes the unit's own "active" state track real
# readiness instead, so the first attempt succeeds cleanly.
set -uo pipefail

DNSTAP_SOCK=/run/apdns-go-live-hostagent/dnstap.sock
HEALTH_URL=https://127.0.0.1:8443/api/health
waited=0
while :; do
    if [ -S "$DNSTAP_SOCK" ] && curl -fsk -o /dev/null --max-time 2 "$HEALTH_URL"; then
        exit 0
    fi
    waited=$((waited + 1))
    if [ "$waited" -ge 30 ]; then
        echo "FAIL: apdns-go-live web container did not become ready (dnstap socket + /api/health) within 30s" >&2
        exit 1
    fi
    sleep 1
done
