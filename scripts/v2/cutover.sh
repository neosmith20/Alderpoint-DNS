#!/usr/bin/env bash
# V2 Go/Svelte owner-preview cutover -- see CUTOVER.md for the full
# narrative, gates already rehearsed, and exact readiness statement.
# This script is the bounded, scripted execution of that runbook.
#
# Usage:
#   scripts/v2/cutover.sh preflight   # read-only checks, safe to run any time
#   scripts/v2/cutover.sh execute     # THE REAL CUTOVER -- requires GO_CUTOVER_CONFIRM=1
#   scripts/v2/cutover.sh verify      # re-run the post-swap checks against whichever
#                                      # side is currently live (Go or Python)
#   scripts/v2/cutover.sh rollback    # force the rollback path directly
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
GO_LIVE_STATE=/root/apdns-go-live-state
GO_LIVE_RELEASE=/root/apdns-go-migration-preview-release   # same release artifact :10443 already validated
GO_LIVE_HOSTAGENT_DIR=/root/apdns-go-live-hostagent
GO_LIVE_WEB_UID=996   # same real unprivileged UID the :10443 preview already proved

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

cmd_verify() {
    local host="${2:-$REAL_HOST}"
    local errors=0
    verify_endpoint "management :8443" "$host" 8443 200 || errors=$((errors+1))
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
    [ "$errors" -eq 0 ] && log "VERIFY: all checks passed" || fail "VERIFY: $errors check(s) failed"
}

# --- execute -------------------------------------------------------------

cmd_execute() {
    local confirm_word="${2:-}"
    [ "${GO_CUTOVER_CONFIRM:-0}" = "1" ] && [ "$confirm_word" = "GO CUTOVER" ] \
        || fail "refusing to execute: set GO_CUTOVER_CONFIRM=1 and pass the literal argument 'GO CUTOVER' (this is Alex's explicit confirmation gate, enforced here, not just documented)"

    cmd_preflight || fail "preflight failed -- not proceeding"

    log "=== Phase 1: prepare (Python keeps serving throughout) ==="
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
    log "real cert imported and validated"

    # The migrated app.db has NO owner account -- Python's admins table
    # is deliberately never migrated (a different auth model entirely,
    # see internal/pymigrate's own doc comment). Complete real owner
    # setup now, on a TEMPORARY local-only port, while Python still
    # holds :8443 -- never fabricate a password on Alex's behalf.
    podman rm -f "${GO_LIVE_CONTAINER}-setup" >/dev/null 2>&1 || true
    podman run -d --name "${GO_LIVE_CONTAINER}-setup" \
        --user "$GO_LIVE_WEB_UID:$GO_LIVE_WEB_UID" \
        -p 127.0.0.1:18443:8443 \
        -v "$GO_LIVE_RELEASE:/opt/alderpointdns-go:ro" \
        -v "$GO_LIVE_STATE:/var/lib/alderpointdns-go" \
        -v "$GO_LIVE_STATE/certs:/etc/alderpointdns-go/certs:ro" \
        debian:trixie-slim \
        /opt/alderpointdns-go/alderpointdns-go web \
        -db /var/lib/alderpointdns-go/data/app.db \
        -config /etc/alderpointdns-go/appliance.yaml \
        -static /opt/alderpointdns-go/frontend-dist \
        -migrations /opt/alderpointdns-go/schema/migrations \
        -addr 0.0.0.0:8443 \
        || fail "starting the temporary setup container failed"
    sleep 3
    local setup_status
    setup_status=$(curl -sk --max-time 5 https://127.0.0.1:18443/api/setup/status)
    if echo "$setup_status" | grep -q '"setup_required": *true\|"setup_required":true'; then
        if [ -n "${CUTOVER_OWNER_USER:-}" ] && [ -n "${CUTOVER_OWNER_PASS:-}" ]; then
            curl -sk --max-time 5 -X POST https://127.0.0.1:18443/api/setup -H 'content-type: application/json' \
                -d "{\"username\":\"${CUTOVER_OWNER_USER}\",\"password\":\"${CUTOVER_OWNER_PASS}\",\"confirm_password\":\"${CUTOVER_OWNER_PASS}\"}" \
                | grep -q '"status": *"created"\|"status":"created"' \
                || fail "owner setup via CUTOVER_OWNER_USER/CUTOVER_OWNER_PASS failed"
            log "owner account created non-interactively (credentials never logged)"
        else
            echo ""
            echo "ACTION REQUIRED: complete owner setup now at https://<this-host>:18443/"
            echo "(reachable from localhost only -- SSH tunnel or console access needed)"
            echo "Press Enter once setup is complete to continue..."
            read -r _
            setup_status=$(curl -sk --max-time 5 https://127.0.0.1:18443/api/setup/status)
            echo "$setup_status" | grep -q '"setup_required": *false\|"setup_required":false' \
                || fail "setup still not complete -- aborting rather than proceeding without an owner account"
        fi
    else
        log "owner account already exists on this app.db (re-run of a prior attempt) -- skipping setup"
    fi
    podman stop "${GO_LIVE_CONTAINER}-setup" >/dev/null 2>&1
    podman rm "${GO_LIVE_CONTAINER}-setup" >/dev/null 2>&1
    log "temporary setup container stopped; real owner account now persisted in $GO_LIVE_STATE/data/app.db"

    mkdir -p "$GO_LIVE_HOSTAGENT_DIR" /var/lib/bind/apdns-go-live
    pkill -f "$GO_LIVE_HOSTAGENT_DIR/apdns-hostagent" 2>/dev/null || true
    sleep 1
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
    sleep 2
    log "apdns-hostagent-live started, socket at $GO_LIVE_HOSTAGENT_DIR/agent.sock"

    podman rm -f "$GO_LIVE_CONTAINER" >/dev/null 2>&1 || true
    podman create --name "$GO_LIVE_CONTAINER" \
        --user "$GO_LIVE_WEB_UID:$GO_LIVE_WEB_UID" \
        -p 8443:8443 \
        -v "$GO_LIVE_RELEASE:/opt/alderpointdns-go:ro" \
        -v "$GO_LIVE_STATE:/var/lib/alderpointdns-go" \
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

    # Promote the real DNS runtime now that :53 is free. The owner
    # account already exists (Phase 1's setup step) -- log in with it
    # to get a real authenticated session, then call the same real
    # POST /api/dns-runtime/apply the Encryption/DNS-Runtime page's own
    # Apply button uses. If CUTOVER_OWNER_USER/PASS were not provided,
    # this step is skipped and Alex must click Apply in the UI himself
    # within the error budget below -- the verify loop keeps polling
    # either way, it does not require this script to be the one that
    # triggered the promotion.
    if [ -n "${CUTOVER_OWNER_USER:-}" ] && [ -n "${CUTOVER_OWNER_PASS:-}" ]; then
        local cookie_jar login_resp csrf
        cookie_jar=$(mktemp /var/tmp/cutover-execute-cookies.XXXXXX)
        login_resp=$(curl -sk -c "$cookie_jar" -X POST "https://127.0.0.1:8443/api/login" -H 'content-type: application/json' \
            -d "{\"username\":\"${CUTOVER_OWNER_USER}\",\"password\":\"${CUTOVER_OWNER_PASS}\"}")
        csrf=$(echo "$login_resp" | grep -o '"csrf": *"[^"]*"' | sed 's/.*"csrf": *"//;s/"$//')
        if [ -n "$csrf" ]; then
            curl -sk -b "$cookie_jar" -H "X-CSRF-Token: $csrf" -X POST "https://127.0.0.1:8443/api/dns-runtime/apply" || true
            log "dns-runtime/apply triggered"
        else
            log "WARNING: login after cutover did not return a CSRF token -- Alex must trigger Apply manually within the error budget"
        fi
        rm -f "$cookie_jar"
    else
        log "no CUTOVER_OWNER_USER/PASS provided -- Alex must click Apply in the real UI now, within the error budget below"
    fi

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
        log "post-swap verification failed -- rolling back"
        cmd_rollback
        exit 1
    fi

    log "CUTOVER COMPLETE. Python stopped (not removed) at $PY_CONTAINER. Go live at $GO_LIVE_CONTAINER."
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
    *) echo "usage: $0 {preflight|execute|verify|rollback}"; exit 2 ;;
esac
