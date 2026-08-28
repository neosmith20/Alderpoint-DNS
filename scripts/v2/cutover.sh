#!/usr/bin/env bash
# V2 Go/Svelte owner-preview cutover -- see CUTOVER.md for the full
# narrative, gates already rehearsed, and exact readiness statement.
# This script is the bounded, scripted execution of that runbook.
#
# Usage:
#   scripts/v2/cutover.sh preflight   # read-only checks, safe to run any time
#   scripts/v2/cutover.sh execute     # THE REAL CUTOVER -- requires GO_CUTOVER_CONFIRM=1
#   scripts/v2/cutover.sh verify      # re-run the functional checks against whichever
#                                      # side is currently live (Go or Python)
#   scripts/v2/cutover.sh rollback    # force the rollback path directly
#   scripts/v2/cutover.sh topology    # read-only: assert the final end-state topology
#                                      # (Go alone on :8443/:53, nothing on :10443/:18443)
#
# Required end state after a successful execute: ONE Go instance owning
# :8443 (management) and :53 (DNS, UDP+TCP); the old :10443 development
# preview and the temporary :18443 staging binding both fully removed;
# Python stopped (never removed -- rollback artifacts/state preserved).
# The obsolete-preview cleanup runs ONLY after the post-swap functional
# verify passes -- a failed verify rolls Python back and leaves :10443/
# :18443 untouched for investigation.
#
# `execute` refuses to run unless the environment variable
# GO_CUTOVER_CONFIRM=1 is set AND the literal string "GO CUTOVER" is
# passed as the second argument -- this is the one place Alex's
# explicit confirmation gate is enforced mechanically, not just by
# instruction.
set -uo pipefail

REAL_HOST="${CUTOVER_REAL_HOST:-127.0.0.1}"
PY_CONTAINER=apdns-v2-preview
PY_STATE_ETC=/root/apdns-v2-preview-state/etc
PY_STATE_VARLIB=/root/apdns-v2-preview-state/var-lib
PY_CONTROL_DB="$PY_STATE_VARLIB/control.db"
PY_CERT_DIR="$PY_STATE_VARLIB/certs"

GO_LIVE_CONTAINER=apdns-go-live
GO_LIVE_STATE=/var/lib/apdns-go-live-staging   # staged ahead of cutover -- see AGENT_PROGRESS.md's "Real migrated database now staged and running" checkpoint; owner setup already completed here through the real browser flow. THE EXACT database used at cutover -- never recreated, never a second database.
GO_LIVE_RELEASE="$GO_LIVE_STATE"   # the EXACT binary/frontend/schema Alex already did real browser setup against -- staged there alongside its own data. Deliberately NOT /root/apdns-go-migration-preview-release: that directory is the OLD :10443 preview's own build (a real, different, older commit was found running there during this session's own incident -- see AGENT_PROGRESS.md), and it is scheduled for removal by this same cutover anyway.
GO_LIVE_HOSTAGENT_DIR=/root/apdns-go-live-hostagent
GO_LIVE_WEB_UID=996   # same real unprivileged UID the :10443 preview already proved
STAGING_PORT=18443   # temporary -- torn down after a verified cutover, never part of the final topology

# The OLD :10443 development preview -- torn down (container removed,
# its dedicated hostagent process stopped) ONLY after the real cutover
# is fully verified. Never touched on a failed cutover/rollback.
OLD_PREVIEW_CONTAINER=apdns-go-migration-preview
OLD_PREVIEW_HOSTAGENT_DIR=/root/apdns-go-migration-hostagent
OLD_PREVIEW_PORT=10443

ROLLBACK_DIR_GLOB=/root/apdns-v2-preview-cutover-rollback-*
ERROR_BUDGET_SECONDS=90

log() { echo "+ $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

latest_rollback_dir() {
    # shellcheck disable=SC2012
    ls -dt $ROLLBACK_DIR_GLOB 2>/dev/null | head -1
}

# --- preflight ---------------------------------------------------------

cmd_preflight() {
    local rb
    rb="$(latest_rollback_dir)"
    [ -n "$rb" ] || fail "no rollback snapshot found matching $ROLLBACK_DIR_GLOB -- take one first (see ROLLBACK.md)"
    log "using rollback snapshot: $rb"
    ( cd "$rb" && sha256sum -c CHECKSUMS.txt ) || fail "rollback snapshot checksum mismatch -- do not proceed"

    local avail_kb
    avail_kb=$(df -Pk / | tail -1 | awk '{print $4}')
    [ "$avail_kb" -gt 2097152 ] || fail "less than 2GB free on / ($((avail_kb/1024))MB) -- free space before cutover"
    log "disk space ok: $((avail_kb/1024))MB free"

    local port_owner
    for p in 53 853 8443 9443; do
        port_owner=$(ss -tlnp 2>/dev/null | awk -v p=":$p\$" '$4 ~ p {print $0}')
        if [ -n "$port_owner" ] && ! echo "$port_owner" | grep -q conmon; then
            fail "port $p is owned by something other than the expected container proxy: $port_owner"
        fi
    done
    log "port ownership ok: 53/853/8443/9443 held only by $PY_CONTAINER's own proxy"

    [ -f "$PY_CONTROL_DB" ] || fail "python control.db not found at $PY_CONTROL_DB"
    # /var/tmp, not /tmp: /tmp is a small tmpfs on this host and a
    # ~160MB control.db snapshot has filled it before (a real incident
    # this session hit directly) -- /var/tmp is real disk-backed space.
    local snap
    snap=$(mktemp /var/tmp/cutover-preflight-controldb.XXXXXX)
    sqlite3 "$PY_CONTROL_DB" ".backup $snap" || fail "control.db backup failed"
    local ldns up bl
    ldns=$(sqlite3 "$snap" "SELECT COUNT(*) FROM local_dns_records" 2>/dev/null)
    up=$(sqlite3 "$snap" "SELECT COUNT(*) FROM upstream_profiles" 2>/dev/null)
    bl=$(sqlite3 "$snap" "SELECT COUNT(*) FROM blocklist_subscriptions" 2>/dev/null)
    rm -f "$snap"
    log "migrated-state validation: local_dns_records=$ldns upstream_profiles=$up blocklist_subscriptions=$bl"
    [ "${ldns:-0}" -gt 0 ] || fail "0 local_dns_records on live Python -- expected a real non-zero count (was 47 at rehearsal time); investigate before proceeding, do not assume this is fine"

    [ -f "$PY_CERT_DIR/server.crt" ] && [ -f "$PY_CERT_DIR/server.key" ] || fail "python live cert/key not found at $PY_CERT_DIR"
    local fp
    fp=$(openssl x509 -in "$PY_CERT_DIR/server.crt" -noout -fingerprint -sha256 2>/dev/null)
    log "live cert fingerprint: $fp"
    echo "$fp" | grep -q "C1:33:7B:D4:E5:DA:E4:A6:03:B1:D1:61:1B:C4:84:8C:BD:F1:D1:96:59:37:7B:9D:5F:EE:BF:F4:E8:A2:10:3F" \
        || log "WARNING: fingerprint differs from the one recorded in CUTOVER.md -- confirm this is an intentional cert rotation on Python before proceeding, not a stale runbook"

    local health_out=/var/tmp/cutover-preflight-health.json
    curl -sk --max-time 5 "https://127.0.0.1:8443/api/health" -o "$health_out" -w "%{http_code}" | grep -q "^200$" \
        || fail "python live health check did not return 200 -- do not cut over an already-unhealthy instance"
    grep -q '"status": *"ok"' "$health_out" 2>/dev/null || grep -q '"status":"ok"' "$health_out" 2>/dev/null \
        || fail "python live health body did not report status ok"
    rm -f "$health_out"
    log "python live health ok"

    # --- the exact staged Go database: must exist, must already have a
    # real owner account (created by Alex through the real browser
    # bootstrap flow) -- this script refuses to fabricate one, and
    # refuses to invent a second database.
    [ -f "$GO_LIVE_STATE/data/app.db" ] || fail "no staged database at $GO_LIVE_STATE/data/app.db -- nothing to cut over to"
    local admin_count
    admin_count=$(sqlite3 "$GO_LIVE_STATE/data/app.db" "SELECT COUNT(*) FROM admins" 2>/dev/null || echo 0)
    [ "${admin_count:-0}" -ge 1 ] || fail "staged database at $GO_LIVE_STATE/data/app.db has no owner account yet -- complete real browser setup first"
    log "staged database ok: $GO_LIVE_STATE/data/app.db has a real owner account (count=$admin_count)"

    local staged_ldns staged_up staged_bl
    staged_ldns=$(sqlite3 "$GO_LIVE_STATE/data/app.db" "SELECT COUNT(*) FROM local_dns_records" 2>/dev/null)
    staged_up=$(sqlite3 "$GO_LIVE_STATE/data/app.db" "SELECT COUNT(*) FROM upstream_profiles" 2>/dev/null)
    staged_bl=$(sqlite3 "$GO_LIVE_STATE/data/app.db" "SELECT COUNT(*) FROM blocklist_subscriptions" 2>/dev/null)
    log "staged database content: local_dns_records=$staged_ldns upstream_profiles=$staged_up blocklist_subscriptions=$staged_bl"
    [ "${staged_ldns:-0}" -gt 0 ] || fail "staged database has 0 local_dns_records -- does not look like the real migrated state"

    [ -f "$GO_LIVE_STATE/certs/server.crt" ] && [ -f "$GO_LIVE_STATE/certs/server.key" ] || fail "staged database has no imported cert at $GO_LIVE_STATE/certs"
    local staged_fp
    staged_fp=$(openssl x509 -in "$GO_LIVE_STATE/certs/server.crt" -noout -fingerprint -sha256 2>/dev/null)
    [ "$staged_fp" = "$fp" ] || fail "staged cert fingerprint ($staged_fp) does not match the live python cert ($fp) -- re-import before proceeding"
    log "staged cert matches the live python cert fingerprint"

    # --- old previews: report state, do not fail preflight on their
    # presence (they are torn down only after a verified cutover, in a
    # later phase) -- just confirm we know what's there right now.
    local old_preview_status staging_status
    old_preview_status=$(podman ps --filter "name=^${OLD_PREVIEW_CONTAINER}\$" --format '{{.Status}}' 2>/dev/null)
    log "old :$OLD_PREVIEW_PORT preview container ($OLD_PREVIEW_CONTAINER): ${old_preview_status:-not running}"
    staging_status=$(curl -sk --max-time 3 "https://127.0.0.1:$STAGING_PORT/api/setup/status" 2>/dev/null)
    log "staging :$STAGING_PORT instance: ${staging_status:-not reachable}"
    if echo "$staging_status" | grep -q '"setup_required": *true\|"setup_required":true'; then
        fail "the staging instance on :$STAGING_PORT still reports setup_required=true -- this contradicts the admin_count check above; investigate before proceeding"
    fi

    log "ALL PREFLIGHT CHECKS PASSED"
}

# --- verify (used both post-cutover and post-rollback) ------------------

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

verify_auth_enforced() {
    # This script never holds Alex's password (his own explicit
    # requirement), so it cannot prove a real authenticated session --
    # what it CAN prove automatically is that the real auth logic is
    # actually running: a login attempt with wrong credentials must be
    # rejected with 401, not silently accepted or errored past.
    local host="$1"
    local code
    code=$(curl -sk --max-time 5 -o /dev/null -w "%{http_code}" -X POST "https://$host:8443/api/login" \
        -H 'content-type: application/json' -d '{"username":"__cutover_verify_probe__","password":"definitely-wrong"}')
    [ "$code" = "401" ] && log "auth enforcement check: wrong credentials correctly rejected (401)" \
        || { log "auth enforcement check: expected 401 for wrong credentials, got $code"; return 1; }
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

cmd_verify() {
    local host="${2:-$REAL_HOST}"
    local errors=0
    verify_endpoint "management :8443" "$host" 8443 200 || errors=$((errors+1))
    verify_auth_enforced "$host" || errors=$((errors+1))
    verify_dns "$host" 53 "example.com" udp "ANSWER SECTION\|NXDOMAIN\|REFUSED" || errors=$((errors+1))
    # Stronger checks when a specific real migrated Local DNS name/IP
    # is supplied (recommended for the real execute run -- pick any one
    # of the real records confirmed by preflight's migrated-state
    # validation) -- proves the MIGRATED state specifically, not just
    # that some DNS answers.
    if [ -n "${CUTOVER_TEST_LOCAL_DNS_NAME:-}" ] && [ -n "${CUTOVER_TEST_LOCAL_DNS_IP:-}" ]; then
        verify_dns "$host" 53 "$CUTOVER_TEST_LOCAL_DNS_NAME" udp "$CUTOVER_TEST_LOCAL_DNS_IP" || errors=$((errors+1))
        verify_dns "$host" 53 "$CUTOVER_TEST_LOCAL_DNS_NAME" tcp "$CUTOVER_TEST_LOCAL_DNS_IP" || errors=$((errors+1))
    else
        log "CUTOVER_TEST_LOCAL_DNS_NAME/IP not set -- skipping the migrated-record-specific check (recommended for a real execute run)"
    fi
    # Blocklist enforcement / upstream resolution / cache-policy repeat
    # check, when a real known-blocked domain is supplied (a real
    # subscription must have been refreshed at least once for this to
    # have compiled content -- see AGENT_PROGRESS.md's rehearsal notes).
    if [ -n "${CUTOVER_TEST_BLOCKED_DOMAIN:-}" ]; then
        verify_blocklist "$host" "$CUTOVER_TEST_BLOCKED_DOMAIN" || errors=$((errors+1))
        # Repeat query -- the real cache/policy-isolation proof this
        # session's Go test suite already established at the code level
        # (74467d8): a blocked domain must never intermittently leak a
        # different (cached/allowed) answer.
        verify_blocklist "$host" "$CUTOVER_TEST_BLOCKED_DOMAIN" || errors=$((errors+1))
    else
        log "CUTOVER_TEST_BLOCKED_DOMAIN not set -- skipping the live blocklist-enforcement check (recommended for a real execute run)"
    fi
    verify_upstream "$host" "${CUTOVER_TEST_UPSTREAM_DOMAIN:-cloudflare.com}" || errors=$((errors+1))
    [ "$errors" -eq 0 ] && log "VERIFY: all checks passed" || fail "VERIFY: $errors check(s) failed"
}

# --- execute -------------------------------------------------------------

cmd_execute() {
    local confirm_word="${2:-}"
    [ "${GO_CUTOVER_CONFIRM:-0}" = "1" ] && [ "$confirm_word" = "GO CUTOVER" ] \
        || fail "refusing to execute: set GO_CUTOVER_CONFIRM=1 and pass the literal argument 'GO CUTOVER' (this is Alex's explicit confirmation gate, enforced here, not just documented)"

    cmd_preflight || fail "preflight failed -- not proceeding"

    log "=== Phase 1: prepare (Python keeps serving throughout) ==="

    if [ -f "$GO_LIVE_STATE/data/app.db" ]; then
        log "staged state already exists at $GO_LIVE_STATE/data/app.db (owner setup already completed there through the real browser flow) -- skipping migration/cert-import, using it as-is"
    else
        local snap
        snap="/var/tmp/cutover-execute-controldb-$(date -u +%Y%m%dT%H%M%SZ)"
        sqlite3 "$PY_CONTROL_DB" ".backup $snap" || fail "control.db snapshot failed"
        log "fresh control.db snapshot: $snap"

        mkdir -p "$GO_LIVE_STATE/data"
        "$GO_LIVE_RELEASE/alderpointdns-go" import-python \
            -db "$GO_LIVE_STATE/data/app.db" \
            -migrations "$GO_LIVE_RELEASE/schema/migrations" \
            -python-control-db "$snap" \
            -audit-log "$GO_LIVE_STATE/import-audit.jsonl" \
            -dry-run=false || fail "real migration into $GO_LIVE_STATE/data/app.db failed"
        log "real migration complete: $GO_LIVE_STATE/data/app.db"

        mkdir -p "$GO_LIVE_STATE/certs"
        local repo_root cert_tool
        repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
        cert_tool="/var/tmp/cutover-cert-import-$(date +%s)"
        ( cd "$repo_root/go" && go build -buildvcs=false -o "$cert_tool" ./cmd/cutover-cert-import ) \
            || fail "building cmd/cutover-cert-import failed"
        "$cert_tool" \
            "$PY_CERT_DIR/server.crt" "$PY_CERT_DIR/server.key" \
            "$GO_LIVE_STATE/certs/server.crt" "$GO_LIVE_STATE/certs/server.key" \
            || { rm -f "$cert_tool"; fail "cert import failed"; }
        rm -f "$cert_tool"
    fi
    log "real cert imported and validated"

    # The migrated app.db needs a real owner account -- Python's admins
    # table is deliberately never migrated (a different auth model
    # entirely, see internal/pymigrate's own doc comment), and the
    # account must be created through the real browser bootstrap flow
    # (internal/bootstrap), never fabricated via CLI/env-var input --
    # Alex's own explicit correction to this script's earlier design.
    local admin_count
    admin_count=$(sqlite3 "$GO_LIVE_STATE/data/app.db" "SELECT COUNT(*) FROM admins" 2>/dev/null || echo 0)
    if [ "$admin_count" -ge 1 ]; then
        log "real owner account already exists on the staged database (created via the real browser bootstrap flow) -- nothing to do here"
        # The staged instance (if still running as its own standalone
        # process on an alternate port for Alex's browser setup) must
        # release its lock on app.db and port before the real container
        # below can start -- stop it by matching its known state path,
        # never a blind pkill of every alderpointdns-go process on the
        # host.
        pkill -f "alderpointdns-go web .*-db $GO_LIVE_STATE/data/app.db" 2>/dev/null || true
        sleep 1
    else
        fail "no real owner account exists yet on $GO_LIVE_STATE/data/app.db -- Alex must complete real browser setup at the staged instance's URL (using its own one-time bootstrap token, see its startup log) before running execute. This script will not create one on Alex's behalf."
    fi

    mkdir -p "$GO_LIVE_HOSTAGENT_DIR" /var/lib/bind/apdns-go-live
    pkill -f "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent" 2>/dev/null || true
    sleep 1

    # Build the hostagent binary fresh from HEAD into place -- a prior
    # run of this script assumed a binary already existed here and
    # never put one there; the launch silently failed in the
    # background (bash reported "No such file or directory" to
    # hostagent.log, but the backgrounded `&` job's exit status was
    # never checked), so apdns-hostagent-live never actually started.
    # The web container would then have had no working hostagent
    # socket even if it had booted -- see AGENT_PROGRESS.md's incident
    # writeup for the full chain.
    local repo_root
    repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    ( cd "$repo_root/go" && go build -buildvcs=false -o "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent" ./cmd/apdns-hostagent ) \
        || fail "building apdns-hostagent for the live instance failed"
    [ -x "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent" ] || fail "apdns-hostagent binary was not produced at $GO_LIVE_HOSTAGENT_DIR/apdns-hostagent"
    log "built apdns-hostagent-live binary: $GO_LIVE_HOSTAGENT_DIR/apdns-hostagent"

    rm -f "$GO_LIVE_HOSTAGENT_DIR/agent.sock"
    "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent" \
        -socket "$GO_LIVE_HOSTAGENT_DIR/agent.sock" \
        -allowed-uid "$GO_LIVE_WEB_UID" \
        -audit-log "$GO_LIVE_HOSTAGENT_DIR/audit/audit.jsonl" \
        -bind-compiled-dir /nonexistent \
        -dns-runtime-staging-dir "$GO_LIVE_HOSTAGENT_DIR/dns-staging" \
        -dns-runtime-bind-conf /var/lib/bind/apdns-go-live/named.conf \
        -dns-runtime-dnsdist-conf "$GO_LIVE_HOSTAGENT_DIR/dns-staging/dnsdist.conf" \
        -dns-runtime-bind-dir /var/lib/bind/apdns-go-live \
        -dns-runtime-bind-plain-port 26453 -dns-runtime-bind-proxy-port 26553 \
        -dns-runtime-bind-stats-port 26153 -dns-runtime-bind-rndc-port 26653 \
        -dns-runtime-dnsdist-listen-addr "0.0.0.0:53" \
        -current-binary "$GO_LIVE_RELEASE/alderpointdns-go" \
        -update-staging-dir "$GO_LIVE_HOSTAGENT_DIR/update-staging" \
        -update-backup "$GO_LIVE_HOSTAGENT_DIR/previous-binary" \
        -web-health-url "https://127.0.0.1:8443/api/health" \
        > "$GO_LIVE_HOSTAGENT_DIR/hostagent.log" 2>&1 &
    disown
    # Wait for REAL evidence it started -- the socket file existing --
    # rather than a fixed sleep plus an unconditional log line (the
    # exact pattern that hid the previous failure).
    local waited=0
    while [ ! -S "$GO_LIVE_HOSTAGENT_DIR/agent.sock" ]; do
        sleep 1
        waited=$((waited+1))
        if [ "$waited" -ge 10 ]; then
            fail "apdns-hostagent-live did not create its socket within 10s -- see $GO_LIVE_HOSTAGENT_DIR/hostagent.log"
        fi
    done
    log "apdns-hostagent-live confirmed running, real socket at $GO_LIVE_HOSTAGENT_DIR/agent.sock"

    # Generate a CONTAINER-SPECIFIC appliance.yaml -- the staged
    # instance's own config (used while it ran as a standalone host
    # process for Alex's browser setup) has tls_cert_path/tls_key_path
    # pointing at the real HOST path
    # ($GO_LIVE_STATE/certs/server.crt), which does not exist inside
    # this container's own filesystem namespace (only
    # /etc/alderpointdns-go/certs/... does, via the mount below).
    # There is no CLI flag to override tls_cert_path/tls_key_path --
    # they are config-file-only -- so reusing the staged config
    # unmodified here would fail to find the certificate and crash the
    # container immediately (a REAL failure mode hit and root-caused
    # during this session's own first live attempt, alongside a second,
    # compounding bug: this container's own /etc/alderpointdns-go
    # directory was never mounted at all, only its certs/ subdirectory
    # -- see AGENT_PROGRESS.md's incident writeup for both).
    local container_config="$GO_LIVE_STATE/container-appliance.yaml"
    sed -e 's#tls_cert_path: .*#tls_cert_path: "/etc/alderpointdns-go/certs/server.crt"#' \
        -e 's#tls_key_path: .*#tls_key_path: "/etc/alderpointdns-go/certs/server.key"#' \
        "$GO_LIVE_STATE/config/appliance.yaml" > "$container_config" \
        || fail "generating the container-specific appliance.yaml failed"
    grep -q "/etc/alderpointdns-go/certs/server.crt" "$container_config" \
        || fail "container-specific appliance.yaml does not contain the expected container cert path -- refusing to proceed with a config that would fail the same way again"
    log "generated container-specific config: $container_config"

    podman rm -f "$GO_LIVE_CONTAINER" >/dev/null 2>&1 || true
    podman create --name "$GO_LIVE_CONTAINER" \
        --user "$GO_LIVE_WEB_UID:$GO_LIVE_WEB_UID" \
        -p 8443:8443 \
        -v "$GO_LIVE_RELEASE:/opt/alderpointdns-go:ro" \
        -v "$GO_LIVE_STATE:/var/lib/alderpointdns-go" \
        -v "$container_config:/etc/alderpointdns-go/appliance.yaml:ro" \
        -v "$GO_LIVE_STATE/certs:/etc/alderpointdns-go/certs:ro" \
        -v "$GO_LIVE_HOSTAGENT_DIR:/run/apdns-hostagent" \
        debian:trixie-slim \
        /opt/alderpointdns-go/alderpointdns-go web \
        -db /var/lib/alderpointdns-go/data/app.db \
        -config /etc/alderpointdns-go/appliance.yaml \
        -static /opt/alderpointdns-go/frontend-dist \
        -migrations /opt/alderpointdns-go/schema/migrations \
        -hostagent-socket /run/apdns-hostagent/agent.sock \
        -dns-runtime-dnsdist-addr 127.0.0.1:53 \
        -dns-runtime-bind-proxy-addr 127.0.0.1:26553 \
        -addr 0.0.0.0:8443 \
        || fail "creating $GO_LIVE_CONTAINER failed"
    log "$GO_LIVE_CONTAINER created (not started yet)"

    log "=== Phase 2: the real interruption starts now ==="
    local t0 t1
    t0=$(date +%s)
    podman stop "$PY_CONTAINER" || fail "stopping $PY_CONTAINER failed -- ABORT, do not proceed to start Go, investigate why Python would not stop"
    log "python stopped at $(date -u +%H:%M:%S)"

    podman start "$GO_LIVE_CONTAINER" || { log "starting $GO_LIVE_CONTAINER failed"; cmd_rollback; exit 1; }
    sleep 3

    # Promote the real DNS runtime now that :53 is free. This script
    # NEVER accepts or handles the owner password, in any form (Alex's
    # explicit requirement) -- so it cannot log in and trigger Apply
    # itself. Two ways this legitimately happens instead:
    #   (a) Alex keeps his own already-authenticated browser tab open
    #       through the swap (pointed at the real :8443 URL) and clicks
    #       Apply himself the moment it responds -- his real session
    #       cookie (stored in app.db, unaffected by this swap) is still
    #       valid; or
    #   (b) Alex logs in fresh post-swap through the real UI and clicks
    #       Apply.
    # Either way, this script only polls for the real effect (DNS
    # actually answering) within the error budget below -- it never
    # needs to be the one that triggered the promotion.
    echo ""
    echo "ACTION REQUIRED NOW: click Apply in the real UI (Encryption or DNS Runtime page) at https://<real-host>:8443/ -- this script will not do it for you and does not handle your password. You have $ERROR_BUDGET_SECONDS seconds."

    while true; do
        t1=$(date +%s)
        if [ $((t1 - t0)) -gt "$ERROR_BUDGET_SECONDS" ]; then
            log "ERROR BUDGET EXCEEDED ($ERROR_BUDGET_SECONDS s) -- rolling back"
            cmd_rollback
            exit 1
        fi
        if cmd_verify _ 127.0.0.1 >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    t1=$(date +%s)
    log "=== Interruption window: $((t1 - t0)) seconds ==="

    if ! cmd_verify _ 127.0.0.1; then
        log "post-swap verification failed -- rolling back (obsolete-preview cleanup will NOT run)"
        cmd_rollback
        exit 1
    fi

    log "=== Cutover verified. Proceeding to remove the obsolete :$OLD_PREVIEW_PORT preview and the :$STAGING_PORT staging binding. ==="
    cmd_cleanup_obsolete_previews
    cmd_final_topology

    log "CUTOVER COMPLETE. Python stopped (not removed) at $PY_CONTAINER -- rollback artifacts preserved. Go live at $GO_LIVE_CONTAINER on :8443/:53. :$OLD_PREVIEW_PORT and :$STAGING_PORT are gone."
}

# --- cleanup of obsolete preview instances (ONLY after a verified cutover) ---
#
# Never called on a failed verify/rollback path. Removes RUNNING
# instances only -- never touches Python's real state/rollback
# artifacts, never touches the staged database's own data (it is now
# the live database, still in place under GO_LIVE_STATE).

cmd_cleanup_obsolete_previews() {
    log "=== Cleanup: removing the obsolete :$OLD_PREVIEW_PORT preview and the temporary :$STAGING_PORT staging binding ==="

    podman stop "$OLD_PREVIEW_CONTAINER" >/dev/null 2>&1 || true
    podman rm "$OLD_PREVIEW_CONTAINER" >/dev/null 2>&1 || true
    log "removed container: $OLD_PREVIEW_CONTAINER"

    pkill -f "$OLD_PREVIEW_HOSTAGENT_DIR/apdns-hostagent" 2>/dev/null || true
    sleep 1
    log "stopped the :$OLD_PREVIEW_PORT preview's own dedicated hostagent process"

    # The staging instance's own process was already stopped in Phase 1
    # (it had to release its lock on app.db/cert before the real
    # container could start) -- this is a defensive re-check, not the
    # primary stop point.
    pkill -f "alderpointdns-go web .*-addr 0.0.0.0:$STAGING_PORT" 2>/dev/null || true
    sleep 1

    local leftover
    leftover=$(ss -tlnp 2>/dev/null | grep -E ":$OLD_PREVIEW_PORT |:$STAGING_PORT ")
    if [ -n "$leftover" ]; then
        fail "cleanup incomplete -- something is still listening on :$OLD_PREVIEW_PORT or :$STAGING_PORT: $leftover"
    fi
    log "confirmed: nothing listening on :$OLD_PREVIEW_PORT or :$STAGING_PORT"
}

cmd_final_topology() {
    log "=== Final topology check ==="
    local errors=0

    local go_live_status py_status
    go_live_status=$(podman ps --filter "name=^${GO_LIVE_CONTAINER}\$" --format '{{.Status}}' 2>/dev/null)
    py_status=$(podman ps -a --filter "name=^${PY_CONTAINER}\$" --format '{{.Status}}' 2>/dev/null)
    echo "$go_live_status" | grep -qi "^Up" && log "podman: $GO_LIVE_CONTAINER is Up" || { log "podman: $GO_LIVE_CONTAINER is NOT up ($go_live_status)"; errors=$((errors+1)); }
    echo "$py_status" | grep -qi "^Exited" && log "podman: $PY_CONTAINER is Exited (stopped, preserved)" || { log "podman: $PY_CONTAINER is not in the expected Exited state ($py_status)"; errors=$((errors+1)); }

    if podman ps -a --filter "name=^${OLD_PREVIEW_CONTAINER}\$" --format '{{.Names}}' 2>/dev/null | grep -q .; then
        log "podman: $OLD_PREVIEW_CONTAINER still exists -- expected fully removed"
        errors=$((errors+1))
    else
        log "podman: $OLD_PREVIEW_CONTAINER confirmed removed"
    fi

    local p8443 p53tcp p53udp p10443 p18443
    p8443=$(ss -tlnp 2>/dev/null | grep -c ":8443 ")
    p53tcp=$(ss -tlnp 2>/dev/null | grep -c ":53 ")
    p53udp=$(ss -ulnp 2>/dev/null | grep -c ":53 ")
    p10443=$(ss -tlnp 2>/dev/null | grep -c ":$OLD_PREVIEW_PORT ")
    p18443=$(ss -tlnp 2>/dev/null | grep -c ":$STAGING_PORT ")

    [ "$p8443" -ge 1 ] && log "listener check: :8443 tcp present" || { log "listener check: :8443 tcp MISSING"; errors=$((errors+1)); }
    [ "$p53tcp" -ge 1 ] && log "listener check: :53 tcp present" || { log "listener check: :53 tcp MISSING"; errors=$((errors+1)); }
    [ "$p53udp" -ge 1 ] && log "listener check: :53 udp present" || { log "listener check: :53 udp MISSING"; errors=$((errors+1)); }
    [ "$p10443" -eq 0 ] && log "listener check: :$OLD_PREVIEW_PORT confirmed absent" || { log "listener check: :$OLD_PREVIEW_PORT still has a listener"; errors=$((errors+1)); }
    [ "$p18443" -eq 0 ] && log "listener check: :$STAGING_PORT confirmed absent" || { log "listener check: :$STAGING_PORT still has a listener"; errors=$((errors+1)); }

    [ "$errors" -eq 0 ] && log "FINAL TOPOLOGY: matches the required end state" || fail "FINAL TOPOLOGY: $errors check(s) failed"
}

# --- rollback -------------------------------------------------------------

cmd_rollback() {
    log "=== ROLLBACK ==="
    podman stop "$GO_LIVE_CONTAINER" >/dev/null 2>&1 || true
    pkill -f "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent" 2>/dev/null || true

    podman start "$PY_CONTAINER" || fail "CRITICAL: rollback could not restart $PY_CONTAINER -- see ROLLBACK.md for manual recovery, do not retry blindly"
    sleep 3

    if cmd_verify _ 127.0.0.1; then
        log "ROLLBACK VERIFIED: python live and healthy again"
    else
        fail "CRITICAL: rollback restarted $PY_CONTAINER but verification still failing -- follow ROLLBACK.md's manual steps now, this script will not retry blindly"
    fi
}

case "${1:-}" in
    preflight) cmd_preflight ;;
    execute) cmd_execute "$@" ;;
    verify) cmd_verify "$@" ;;
    rollback) cmd_rollback ;;
    topology) cmd_final_topology ;;
    *) echo "usage: $0 {preflight|execute|verify|rollback|topology}"; exit 2 ;;
esac
