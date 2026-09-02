#!/usr/bin/env bash
# ExecStartPre for apdns-go-live-hostagent.service.
#
# /run is tmpfs -- the socket directory apdns-hostagent binds its
# control socket in does not survive a reboot, and must exist with the
# right ownership (group-readable/writable by apdns-go-web/986, the web
# container's own UID/GID -- see redeploy-go-live.sh's own comment on
# GO_LIVE_WEB_GID for why this exact group matters: the web container
# needs to create its dnstap LISTEN socket in this same directory) and
# mode BEFORE the agent tries to bind there, every single boot.
set -euo pipefail

GO_LIVE_HOSTAGENT_SOCKET_DIR=/run/apdns-go-live-hostagent
GO_LIVE_HOSTAGENT_DIR=/root/apdns-go-live-hostagent
GO_LIVE_WEB_GID=986

mkdir -p "$GO_LIVE_HOSTAGENT_SOCKET_DIR"
chown root:"$GO_LIVE_WEB_GID" "$GO_LIVE_HOSTAGENT_SOCKET_DIR"
chmod 770 "$GO_LIVE_HOSTAGENT_SOCKET_DIR"

mkdir -p "$GO_LIVE_HOSTAGENT_DIR/audit" "$GO_LIVE_HOSTAGENT_DIR/update-staging"
