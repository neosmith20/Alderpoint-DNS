#!/usr/bin/env bash
# Ongoing, idempotent redeploy of the ALREADY-cutover live Go appliance
# (apdns-go-live on :8443/:53) -- rebuilds fresh binaries+frontend from
# whatever commit is checked out, rebuilds/reuses the real
# ca-certificates-baked container base image, and recreates the web
# container and apdns-hostagent process from that build. This is the
# real, reusable "commit -> live" path for routine redeploys; it is
# NOT cutover.sh, which is a one-shot Python->Go migration transaction
# (stops/removes the Python runtime, confirmation-gated by the literal
# "GO CUTOVER" argument) that has already run and is not safe to
# re-invoke now that Python is fully decommissioned.
#
# Existed only as ad hoc, uncommitted commands typed during a live
# incident fix before this script was written (2026-08-29, the P0/P1
# live-defect durability pass) -- a real gap: proving a fix survives
# "the committed deploy path" requires such a path to actually exist
# and be committed, not just cutover.sh's inline, one-time container-
# creation block (kept there unchanged, as history of the original
# cutover, and duplicated here deliberately rather than sourced, since
# sourcing cutover.sh would also execute its own case-dispatch).
#
# Usage: scripts/v2/redeploy-go-live.sh [--skip-build]
#   --skip-build  reuse whatever binaries/frontend-dist are already
#                 staged at $GO_LIVE_RELEASE instead of rebuilding --
#                 useful for re-running just the container-recreate +
#                 verify steps against an already-built commit.
set -uo pipefail

GO_LIVE_CONTAINER=apdns-go-live
GO_LIVE_STATE=/var/lib/apdns-go-live-staging
GO_LIVE_RELEASE="$GO_LIVE_STATE"
GO_LIVE_HOSTAGENT_DIR=/root/apdns-go-live-hostagent
GO_LIVE_HOSTAGENT_SOCKET_DIR=/run/apdns-go-live-hostagent
GO_LIVE_WEB_UID=996
GO_LIVE_WEB_GID=986   # NOT the same number as the UID -- apdns-go-web's real primary group,
                      # confirmed via `id apdns-go-web` on the host. A real bug this script's own
                      # first live run caught: --user "$UID:$UID" (using the UID twice) started
                      # the container as gid 996 instead of the real 986, so it could no longer
                      # write into /run/apdns-go-live-hostagent (group-owned by the real
                      # apdns-go-web/986 group) -- dnstap's listener socket bind failed with
                      # "permission denied", degrading analytics (DNS answering itself was
                      # unaffected, but this was still a real regression from a clean recreate).
GO_LIVE_DNSDIST_ADDR=0.0.0.0:53
GO_LIVE_BIND_PROXY_ADDR=127.0.0.1:26553
# ca-certs-curl (bumped 2026-08-29): adds curl, needed for the new
# --health-cmd below (this image otherwise has no HTTP client at all).
# A distinct tag rather than re-tagging ca-certs in place, so an
# operator can tell from `podman images` which base a given container
# was actually built from.
GO_LIVE_BASE_IMAGE="apdns-go-live-base:ca-certs-curl"
# GO_LIVE_WEB_MEMORY_LIMIT (2026-08-29, release-blocking incident fix):
# a real live OOM incident (2026-08-29, see AGENT_PROGRESS.md) SIGKILL'd
# this container after its RSS grew from a normal ~20MB idle baseline to
# ~2.9GB over about two hours -- with no cap set, the KERNEL's own
# global OOM killer had to pick a victim, and it also took out unrelated
# processes on the same host (dnsdist itself, more than once, per
# dmesg). A per-container memory limit contains any future runaway
# growth to just this container (a clean, fast, CONTAINED cgroup OOM
# kill instead of a host-wide one that can strike anything), paired with
# --restart below so recovery is automatic rather than requiring a human
# to notice and manually redeploy. 768m is generous headroom above the
# real observed idle baseline (~20-40MB) while still bounding the worst
# case to well under this host's total 3.8GB.
GO_LIVE_WEB_MEMORY_LIMIT="768m"
REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"

SKIP_BUILD=0
[ "${1:-}" = "--skip-build" ] && SKIP_BUILD=1

log() { echo "+ $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

verify_endpoint() {
    local label="$1" host="$2" port="$3" expect_status="$4"
    local code
    code=$(curl -sk --max-time 5 "https://$host:$port/api/health" -o /dev/null -w "%{http_code}")
    [ "$code" = "$expect_status" ] && log "$label health: $code (ok)" || { log "$label health: $code (WANT $expect_status)"; return 1; }
}

verify_dns() {
    local host="$1" port="$2" name="$3" proto="$4" expect_pattern="$5"
    local out
    if [ "$proto" = "tcp" ]; then
        out=$(dig +tcp +time=3 +tries=2 "@$host" -p "$port" "$name" A 2>&1)
    else
        out=$(dig +time=3 +tries=2 "@$host" -p "$port" "$name" A 2>&1)
    fi
    echo "$out" | grep -q "$expect_pattern" && log "dig $proto $name: matched '$expect_pattern' (ok)" || { log "dig $proto $name: did NOT match '$expect_pattern' -- output: $out"; return 1; }
}

verify_blocklist() {
    local host="$1" domain="$2"
    local out
    out=$(dig +time=3 +tries=2 "@$host" -p 53 "$domain" A 2>&1)
    if echo "$out" | grep -qE "status: (NXDOMAIN|REFUSED)"; then
        log "blocklist enforcement: $domain correctly blocked"
    else
        log "blocklist enforcement: $domain was NOT blocked -- output: $out"
        return 1
    fi
}

verify_upstream() {
    local host="$1" domain="$2"
    local out
    out=$(dig +short +time=3 +tries=2 "@$host" -p 53 "$domain" A 2>&1)
    if [ -n "$out" ] && ! echo "$out" | grep -qi "error\|timed out"; then
        log "upstream resolution: $domain -> $out"
    else
        log "upstream resolution FAILED for $domain: $out"
        return 1
    fi
}

FULL_SHA="$(cd "$REPO_ROOT" && git rev-parse HEAD)"
log "redeploying commit $FULL_SHA to $GO_LIVE_CONTAINER"

if [ "$SKIP_BUILD" -eq 0 ]; then
    log "building frontend"
    ( cd "$REPO_ROOT/go/frontend" && npm install >/dev/null && npm run build >/dev/null ) || fail "frontend build failed"

    log "building alderpointdns-go + apdns-hostagent (main.Version=$FULL_SHA)"
    ( cd "$REPO_ROOT/go" && CGO_ENABLED=0 go build -buildvcs=false -ldflags "-X main.Version=$FULL_SHA" -o "$GO_LIVE_RELEASE/alderpointdns-go.new" ./cmd/alderpointdns-go ) \
        || fail "building alderpointdns-go failed"
    ( cd "$REPO_ROOT/go" && CGO_ENABLED=0 go build -buildvcs=false -ldflags "-X main.Version=$FULL_SHA" -o "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent.new" ./cmd/apdns-hostagent ) \
        || fail "building apdns-hostagent failed"

    built_version="$("$GO_LIVE_RELEASE/alderpointdns-go.new" version)"
    [ "$built_version" = "$FULL_SHA" ] || fail "built alderpointdns-go self-reports '$built_version', expected '$FULL_SHA'"

    chown apdns-go-web:apdns-go-web "$GO_LIVE_RELEASE/alderpointdns-go.new"
    chmod 755 "$GO_LIVE_RELEASE/alderpointdns-go.new"
    chmod 755 "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent.new"

    rm -rf "$GO_LIVE_RELEASE/frontend-dist.new"
    cp -r "$REPO_ROOT/go/frontend/dist" "$GO_LIVE_RELEASE/frontend-dist.new"
    chown -R apdns-go-web:apdns-go-web "$GO_LIVE_RELEASE/frontend-dist.new"

    for mig in "$REPO_ROOT/go/schema/migrations/"*.sql; do
        base="$(basename "$mig")"
        [ -f "$GO_LIVE_RELEASE/schema/migrations/$base" ] || cp "$mig" "$GO_LIVE_RELEASE/schema/migrations/$base"
    done

    # Read back from disk (not the in-memory build result) before ever
    # signaling anything with these files -- matching this deployment's
    # own established discipline of never trusting a write without
    # re-reading it.
    web_sha=$(sha256sum "$GO_LIVE_RELEASE/alderpointdns-go.new" | cut -d' ' -f1)
    ha_sha=$(sha256sum "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent.new" | cut -d' ' -f1)
    [ -n "$web_sha" ] && [ -n "$ha_sha" ] || fail "failed to read back a staged binary's checksum from disk"
    log "web binary sha256 (on disk): $web_sha"
    log "hostagent binary sha256 (on disk): $ha_sha"

    [ -f "$GO_LIVE_RELEASE/alderpointdns-go" ] && mv "$GO_LIVE_RELEASE/alderpointdns-go" "$GO_LIVE_RELEASE/alderpointdns-go.prev-redeploy-$(date +%s)"
    mv "$GO_LIVE_RELEASE/alderpointdns-go.new" "$GO_LIVE_RELEASE/alderpointdns-go"
    [ -d "$GO_LIVE_RELEASE/frontend-dist" ] && rm -rf "$GO_LIVE_RELEASE/frontend-dist.prev" && mv "$GO_LIVE_RELEASE/frontend-dist" "$GO_LIVE_RELEASE/frontend-dist.prev"
    mv "$GO_LIVE_RELEASE/frontend-dist.new" "$GO_LIVE_RELEASE/frontend-dist"
    [ -f "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent" ] && cp "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent" "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent.prev-redeploy-$(date +%s)"
    mv "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent.new" "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent"
else
    log "--skip-build: reusing already-staged binaries/frontend at $GO_LIVE_RELEASE"
fi

# The container-specific config this deployment uses -- ACTUALLY
# regenerated here (previously only checked for existence + one grep,
# despite a comment on this exact line already claiming it was
# "regenerated" -- a real gap found live, 2026-08-29: cutover.sh's own
# one-time generation of this file only ever rewrote tls_cert_path/
# tls_key_path from $GO_LIVE_STATE/config/appliance.yaml -- the real,
# host-oriented source config the host-side CLI tools use, where
# HOST-absolute paths are correct -- and never rewrote
# blocklists.staging_dir/runtime_dir or local_dns.staging_dir/
# runtime_dir the same way, even though those are real filesystem
# paths the CONTAINER-internal web process also reads, and the
# container mounts $GO_LIVE_STATE at /var/lib/alderpointdns-go, not at
# its own host-absolute path. The container's own scheduler-triggered
# blocklist refresh failed every single subscription with "mkdir
# .../apdns-go-live-staging: permission denied" as a direct result (a
# path that doesn't exist inside the container's own filesystem
# namespace) -- and because dnscompile only compiles a subscription
# whose most recent refresh succeeded, ALL 20 subscriptions failing at
# once silently emptied the live blocklist enforcement entirely,
# despite their real .rpz files still sitting untouched on disk. Also
# corrected here: web.listen_port, which the source config carries as
# the historical, explicitly-banned :18443 (inert only because -addr
# always overrides it on every real launch of this binary -- fixed
# anyway rather than left as a live standing violation of that rule).
container_config="$GO_LIVE_STATE/container-appliance.yaml"
source_config="$GO_LIVE_STATE/config/appliance.yaml"
[ -f "$source_config" ] || fail "$source_config does not exist -- this script only redeploys an already-cutover appliance, it does not perform first-time setup"
sed -e 's#tls_cert_path: .*#tls_cert_path: "/etc/alderpointdns-go/certs/server.crt"#' \
    -e 's#tls_key_path: .*#tls_key_path: "/etc/alderpointdns-go/certs/server.key"#' \
    -e "s#$GO_LIVE_STATE/blocklists/#/var/lib/alderpointdns-go/blocklists/#g" \
    -e "s#$GO_LIVE_STATE/local-dns/#/var/lib/alderpointdns-go/local-dns/#g" \
    -e 's#listen_port: 18443#listen_port: 8443#' \
    "$source_config" > "$container_config" \
    || fail "generating the container-specific appliance.yaml failed"
grep -q "/etc/alderpointdns-go/certs/server.crt" "$container_config" || fail "$container_config does not contain the expected container cert path"
grep -q "/var/lib/alderpointdns-go/blocklists/" "$container_config" || fail "$container_config does not contain the expected container-mounted blocklists path"
grep -q "/var/lib/alderpointdns-go/local-dns/" "$container_config" || fail "$container_config does not contain the expected container-mounted local-dns path"
if grep -q "18443" "$container_config"; then fail "$container_config still contains the banned :18443 value"; fi
log "regenerated container-specific config: $container_config"

log "ensuring $GO_LIVE_BASE_IMAGE (debian:trixie-slim + ca-certificates + curl) exists"
if ! podman image exists "$GO_LIVE_BASE_IMAGE"; then
    # Deliberately NOT --rm: podman commit below needs the exited
    # container to still exist. A real bug caught while first running
    # this script for real: --rm auto-removes the container the instant
    # it exits, so `podman commit` always failed with "no such
    # container" -- removed explicitly, after committing, instead.
    podman rm -f apdns-go-live-base-build >/dev/null 2>&1 || true
    podman run --name apdns-go-live-base-build debian:trixie-slim \
        sh -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl && apt-get clean" \
        || fail "building the ca-certificates+curl base image failed"
    podman commit apdns-go-live-base-build "$GO_LIVE_BASE_IMAGE" >/dev/null || fail "committing the ca-certificates+curl base image failed"
    podman rm -f apdns-go-live-base-build >/dev/null 2>&1 || true
    log "built and tagged $GO_LIVE_BASE_IMAGE"
else
    log "$GO_LIVE_BASE_IMAGE already built, reusing"
fi

# --- hostagent: restart it. Since 2026-09-02 (see
# scripts/v2/systemd/README.md), apdns-go-live-hostagent.service is the
# committed source of truth for its launch flags -- prefer
# `systemctl restart` so systemd's own Restart=on-failure supervision
# is never left racing a manually kill+relaunched process (that race
# could otherwise produce two hostagent processes fighting over the
# same socket: systemd resurrecting the old flags the instant an
# external `kill` looks like an unexpected exit, while this script
# separately starts a new one of its own). Falls back to the old
# manual kill+relaunch (its own trackedProcess/PID-file adoption logic,
# internal/hostagentd/ops_dnsruntime.go, already makes that safe too --
# it adopts the still-running named/dnsdist rather than duplicating
# them) only if that unit somehow isn't installed.
if systemctl cat apdns-go-live-hostagent.service >/dev/null 2>&1; then
    log "restarting apdns-hostagent via systemd (apdns-go-live-hostagent.service)"
    systemctl restart apdns-go-live-hostagent.service || fail "systemctl restart apdns-go-live-hostagent.service failed"
    waited=0
    while [ ! -S "$GO_LIVE_HOSTAGENT_SOCKET_DIR/agent.sock" ]; do
        sleep 1
        waited=$((waited+1))
        [ "$waited" -ge 15 ] && fail "apdns-hostagent did not create its socket within 15s after systemd restart"
    done
    log "apdns-hostagent redeployed via systemd, real socket confirmed"
else
    log "WARNING: apdns-go-live-hostagent.service not installed -- falling back to manual kill+relaunch (see scripts/v2/systemd/README.md to install boot-survival units)"
    current_ha_pid="$(pgrep -f "^$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent " || true)"
    if [ -n "$current_ha_pid" ]; then
        ha_cmdline=()
        while IFS= read -r -d '' arg; do ha_cmdline+=("$arg"); done < "/proc/$current_ha_pid/cmdline"
        log "stopping current apdns-hostagent (pid $current_ha_pid)"
        kill -TERM "$current_ha_pid"
        sleep 2
    else
        fail "no running apdns-hostagent process found matching $GO_LIVE_HOSTAGENT_DIR/apdns-hostagent -- refusing to guess its flags; start it manually first"
    fi
    log "relaunching apdns-hostagent with its exact prior flags"
    setsid "${ha_cmdline[@]}" > "$GO_LIVE_HOSTAGENT_DIR/hostagent-redeploy-$(date +%s).log" 2>&1 < /dev/null &
    disown
    waited=0
    while [ ! -S "$GO_LIVE_HOSTAGENT_SOCKET_DIR/agent.sock" ]; do
        sleep 1
        waited=$((waited+1))
        [ "$waited" -ge 10 ] && fail "apdns-hostagent did not create its socket within 10s after redeploy"
    done
    log "apdns-hostagent redeployed, real socket confirmed"
fi

# --- web container: full recreate, the only way to pick up a changed
# CLI argument (podman restart cannot add a new flag to an existing
# container's entrypoint). Stop the systemd unit first (if installed)
# so it isn't left supervising a container ID this script is about to
# `rm -f` out from under it -- otherwise Restart=on-failure could try
# to restart a container that no longer exists, or fight this script's
# own podman start below. ---
WEB_UNIT_INSTALLED=0
if systemctl cat apdns-go-live-web.service >/dev/null 2>&1; then
    WEB_UNIT_INSTALLED=1
    log "stopping apdns-go-live-web.service before recreate"
    systemctl stop apdns-go-live-web.service || true
fi
log "recreating $GO_LIVE_CONTAINER"
podman rm -f "$GO_LIVE_CONTAINER" >/dev/null 2>&1 || true
podman create --name "$GO_LIVE_CONTAINER" \
    --user "$GO_LIVE_WEB_UID:$GO_LIVE_WEB_GID" \
    --restart=on-failure:5 \
    --memory="$GO_LIVE_WEB_MEMORY_LIMIT" \
    --memory-swap="$GO_LIVE_WEB_MEMORY_LIMIT" \
    --health-cmd="curl -fsk -o /dev/null https://127.0.0.1:8443/api/health || exit 1" \
    --health-interval=30s \
    --health-timeout=5s \
    --health-retries=3 \
    --health-start-period=20s \
    --health-on-failure=restart \
    -p 8443:8443 \
    -v "$GO_LIVE_RELEASE:/opt/alderpointdns-go:ro" \
    -v "$GO_LIVE_STATE:/var/lib/alderpointdns-go" \
    -v "$container_config:/etc/alderpointdns-go/appliance.yaml:ro" \
    -v "$GO_LIVE_STATE/certs:/etc/alderpointdns-go/certs:ro" \
    -v "$GO_LIVE_HOSTAGENT_SOCKET_DIR:/run/apdns-hostagent" \
    "$GO_LIVE_BASE_IMAGE" \
    /opt/alderpointdns-go/alderpointdns-go web \
    -db /var/lib/alderpointdns-go/data/app.db \
    -config /etc/alderpointdns-go/appliance.yaml \
    -static /opt/alderpointdns-go/frontend-dist \
    -migrations /opt/alderpointdns-go/schema/migrations \
    -hostagent-socket /run/apdns-hostagent/agent.sock \
    -dns-runtime-dnsdist-addr "$GO_LIVE_DNSDIST_ADDR" \
    -dns-runtime-bind-proxy-addr "$GO_LIVE_BIND_PROXY_ADDR" \
    -analytics-db /var/lib/alderpointdns-go/data/analytics.db \
    -dns-runtime-dnstap-socket "$GO_LIVE_HOSTAGENT_SOCKET_DIR/dnstap.sock" \
    -dns-runtime-dnstap-listen-socket /run/apdns-hostagent/dnstap.sock \
    -dns-runtime-tls-cert-path "$GO_LIVE_STATE/certs/server.crt" \
    -dns-runtime-tls-key-path "$GO_LIVE_STATE/certs/server.key" \
    -addr 0.0.0.0:8443 \
    || fail "creating $GO_LIVE_CONTAINER failed"
if [ "$WEB_UNIT_INSTALLED" -eq 1 ]; then
    systemctl start apdns-go-live-web.service || fail "systemctl start apdns-go-live-web.service failed"
else
    podman start "$GO_LIVE_CONTAINER" || fail "starting $GO_LIVE_CONTAINER failed"
fi
log "$GO_LIVE_CONTAINER recreated and started from the committed base image (ca-certificates baked in, not a manual post-create install)"

log "waiting for /api/health"
waited=0
until verify_endpoint go 127.0.0.1 8443 200 >/dev/null 2>&1; do
    sleep 1
    waited=$((waited+1))
    [ "$waited" -ge 20 ] && fail "$GO_LIVE_CONTAINER did not report a healthy /api/health within 20s"
done

log "=== post-redeploy verification ==="
fails=0
verify_endpoint go 127.0.0.1 8443 200 || fails=$((fails+1))
verify_dns 127.0.0.1 53 cloudflare.com udp "ANSWER SECTION" || fails=$((fails+1))
verify_dns 127.0.0.1 53 cloudflare.com tcp "ANSWER SECTION" || fails=$((fails+1))
verify_blocklist 127.0.0.1 doubleclick.net || fails=$((fails+1))
verify_upstream 127.0.0.1 cloudflare.com || fails=$((fails+1))

if [ "$fails" -gt 0 ]; then
    fail "$fails post-redeploy check(s) failed -- see log above"
fi
log "REDEPLOY COMPLETE AND VERIFIED: $GO_LIVE_CONTAINER on commit $FULL_SHA"
