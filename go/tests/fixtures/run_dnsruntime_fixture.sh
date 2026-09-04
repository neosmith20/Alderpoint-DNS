#!/bin/bash
# Disposable, real named+dnsdist+apdns-hostagent+web fixture for
# hostagent_smoke.mjs's 5 checks that need a full DNS-runtime-configured
# hostagent (DNS Runtime apply, Safe DNS Benchmark) -- the gap disclosed
# in that file's own header comment. Modeled directly on
# cmd/apdns-hostagent/main_test.go's TestHostagentRestartDoesNotKillLiveDNS
# (same real binaries, same -allowed-uid/apdns-browsertest pattern, same
# real named/rndc/dnsdist topology) plus the "web" subcommand's own real
# flag set, so the browser can drive the actual owner-facing HTTP app
# against a fully-wired backend instead of a synthetic stand-in.
#
# Usage:
#   run_dnsruntime_fixture.sh up      -- build + start everything, print
#                                         "BASE_URL=... " env lines on
#                                         stdout, then exit 0 once healthy
#   run_dnsruntime_fixture.sh down    -- stop everything and remove all
#                                         fixture state (named/dnsdist/
#                                         hostagent/web, work dirs)
#
# State (PIDs, paths) is kept in $STATE_FILE so "up" and "down" can be
# separate invocations from the calling script/session.
set -euo pipefail

REPO_GO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/var/tmp/apdns-hostagent-dnsruntime-fixture
STATE_FILE="$WORK/state.sh"
CLIENT_USER=apdns-browsertest

free_port() {
  while true; do
    local p=$(( (RANDOM % 20000) + 20000 ))
    if ! ss -ltn "( sport = :$p )" 2>/dev/null | grep -q "$p" && ! ss -lun "( sport = :$p )" 2>/dev/null | grep -q "$p"; then
      echo "$p"
      return
    fi
  done
}

cmd="${1:-}"

case "$cmd" in
  up)
    for bin in named rndc dnsdist dig curl sqlite3; do
      command -v "$bin" >/dev/null || { echo "missing required binary: $bin" >&2; exit 1; }
    done
    if [ "$(id -u)" != "0" ]; then echo "must run as root" >&2; exit 1; fi
    if ! id "$CLIENT_USER" >/dev/null 2>&1; then echo "missing system account: $CLIENT_USER" >&2; exit 1; fi
    CLIENT_UID="$(id -u "$CLIENT_USER")"

    rm -rf "$WORK"
    mkdir -p "$WORK"
    chmod 0777 "$WORK"

    echo "building hostagent + main binaries..." >&2
    HOSTAGENT_BIN="$WORK/apdns-hostagent"
    MAIN_BIN="$WORK/alderpointdns-go"
    ( cd "$REPO_GO_ROOT" && go build -buildvcs=false -o "$HOSTAGENT_BIN" ./cmd/apdns-hostagent )
    ( cd "$REPO_GO_ROOT" && go build -buildvcs=false -o "$MAIN_BIN" ./cmd/alderpointdns-go )
    chmod 0755 "$HOSTAGENT_BIN" "$MAIN_BIN"

    BIND_DIR="/var/lib/bind/dnsruntime-fixture-$$"
    mkdir -p "$BIND_DIR"

    STAGING_DIR="$WORK/dns-staging"
    SECRETS_DIR="$WORK/secrets-key"
    SOCK="$WORK/agent.sock"
    AUDIT_LOG="$WORK/audit.jsonl"
    mkdir -p "$STAGING_DIR" "$SECRETS_DIR"

    DNSDIST_PORT="$(free_port)"
    BIND_PLAIN_PORT="$(free_port)"
    BIND_PROXY_PORT="$(free_port)"
    BIND_STATS_PORT="$(free_port)"
    BIND_RNDC_PORT="$(free_port)"
    DNSDIST_LISTEN_ADDR="127.0.0.1:$DNSDIST_PORT"

    echo "starting real apdns-hostagent (named+dnsdist DNS-runtime-wired)..." >&2
    "$HOSTAGENT_BIN" \
      -socket "$SOCK" \
      -allowed-uid "$CLIENT_UID" \
      -audit-log "$AUDIT_LOG" \
      -secrets-key-dir "$SECRETS_DIR" \
      -dns-runtime-staging-dir "$STAGING_DIR" \
      -dns-runtime-bind-conf "$BIND_DIR/named.conf" \
      -dns-runtime-dnsdist-conf "$STAGING_DIR/dnsdist.conf" \
      -dns-runtime-bind-dir "$BIND_DIR" \
      -dns-runtime-bind-plain-port "$BIND_PLAIN_PORT" \
      -dns-runtime-bind-proxy-port "$BIND_PROXY_PORT" \
      -dns-runtime-bind-stats-port "$BIND_STATS_PORT" \
      -dns-runtime-bind-rndc-port "$BIND_RNDC_PORT" \
      -dns-runtime-dnsdist-listen-addr "$DNSDIST_LISTEN_ADDR" \
      -bind-compiled-dir "$BIND_DIR" \
      -current-binary "$MAIN_BIN" \
      > "$WORK/hostagent.log" 2>&1 &
    HOSTAGENT_PID=$!
    disown "$HOSTAGENT_PID" 2>/dev/null || true

    for i in $(seq 1 100); do
      [ -S "$SOCK" ] && break
      sleep 0.05
    done
    [ -S "$SOCK" ] || { echo "hostagent socket never appeared; log:" >&2; cat "$WORK/hostagent.log" >&2; exit 1; }
    chmod 0666 "$SOCK"

    # A real self-signed management TLS cert -- same directory convention
    # as a real deployment (packaging/go-deb's postinst generates one at
    # first boot), and REQUIRED for a real end-to-end DNSCrypt proof:
    # handleDNSCryptRotate (internal/httpapi/handlers_encryption.go)
    # gates entirely on -config's web.tls_cert_path being set (DNSCrypt
    # key material reuses that same directory), so a plain-HTTP fixture
    # genuinely cannot provision DNSCrypt at all, not just "won't serve
    # HTTPS".
    CERT_DIR="$WORK/certs"
    mkdir -p "$CERT_DIR"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout "$CERT_DIR/web.key" -out "$CERT_DIR/web.crt" -days 3 \
      -subj "/CN=apdns-dnsruntime-fixture" -addext "subjectAltName=IP:127.0.0.1" \
      >/dev/null 2>&1
    chmod 0644 "$CERT_DIR/web.key" "$CERT_DIR/web.crt"
    # RotateDNSCrypt (internal/dnstransports) writes DNSCrypt provider/
    # cert key material into this SAME directory directly from the web
    # process itself (unprivileged apdns-browsertest, not through the
    # hostagent) -- needs real write access, not just read+traverse.
    chmod 0777 "$CERT_DIR"

    # Fixture config + DB + migrations, all under the world-writable work
    # dir so the unprivileged web process (below) can use them.
    CFG="$WORK/appliance.yaml"
    sed \
      -e "s#/var/lib/alderpointdns-go/blocklists/staging#$WORK/blocklists/staging#" \
      -e "s#/var/lib/alderpointdns-go/blocklists/runtime#$WORK/blocklists/runtime#" \
      -e "s#/var/lib/alderpointdns-go/local-dns/staging#$WORK/local-dns/staging#" \
      -e "s#/var/lib/alderpointdns-go/local-dns/runtime#$WORK/local-dns/runtime#" \
      -e "s#tls_cert_path: \"\"#tls_cert_path: \"$CERT_DIR/web.crt\"#" \
      -e "s#tls_key_path: \"\"#tls_key_path: \"$CERT_DIR/web.key\"#" \
      "$REPO_GO_ROOT/config/appliance.yaml" > "$CFG"
    MIGRATIONS_DIR="$WORK/migrations"
    cp -r "$REPO_GO_ROOT/schema/migrations" "$MIGRATIONS_DIR"
    # The repo checkout itself is root:root, group-only-readable
    # (drwxr-x---) above go/frontend -- unreachable for the unprivileged
    # apdns-browsertest client the web process runs as (matching the real
    # deployment's own web-process UID boundary). Copy the compiled
    # frontend into the world-traversable work dir instead of pointing
    # -static at the repo path directly.
    STATIC_DIR="$WORK/frontend-dist"
    cp -r "$REPO_GO_ROOT/frontend/dist" "$STATIC_DIR"
    chmod -R a+rX "$STATIC_DIR"
    DB="$WORK/app.db"
    ANALYTICS_DB="$WORK/analytics.db"
    DNSTAP_SOCK="$WORK/dnstap.sock"
    WEB_PORT="$(free_port)"
    WEB_ADDR="127.0.0.1:$WEB_PORT"

    echo "starting real web control-plane process (as $CLIENT_USER, DNS-runtime-wired)..." >&2
    runuser -u "$CLIENT_USER" -- "$MAIN_BIN" web \
      -db "$DB" \
      -config "$CFG" \
      -static "$STATIC_DIR" \
      -migrations "$MIGRATIONS_DIR" \
      -addr "$WEB_ADDR" \
      -analytics-db "$ANALYTICS_DB" \
      -dns-runtime-dnstap-socket "$DNSTAP_SOCK" \
      -dns-runtime-dnstap-listen-socket "$DNSTAP_SOCK" \
      -backups-dir "$WORK/backups" \
      -bootstrap-token-path "$WORK/bootstrap-token" \
      -hostagent-socket "$SOCK" \
      -dns-runtime-dnsdist-addr "$DNSDIST_LISTEN_ADDR" \
      -dns-runtime-bind-proxy-addr "127.0.0.1:$BIND_PROXY_PORT" \
      -dns-perf-bind-plain-addr "127.0.0.1:$BIND_PLAIN_PORT" \
      -dns-perf-report-path "$WORK/dns-performance/latest-report.json" \
      -replication-cert-dir "$WORK/replication-certs" \
      -secret-backups-dir "$WORK/secret-backups" \
      > "$WORK/web.log" 2>&1 &
    WEB_PID=$!
    disown "$WEB_PID" 2>/dev/null || true

    BASE_URL="https://$WEB_ADDR"
    ok=""
    for i in $(seq 1 100); do
      if curl -fskS "$BASE_URL/api/health" >/dev/null 2>&1; then ok=1; break; fi
      sleep 0.1
    done
    if [ -z "$ok" ]; then
      echo "web process never became healthy; log:" >&2
      cat "$WORK/web.log" >&2
      exit 1
    fi

    cat > "$STATE_FILE" <<EOF
HOSTAGENT_PID=$HOSTAGENT_PID
WEB_PID=$WEB_PID
BIND_DIR="$BIND_DIR"
STAGING_DIR="$STAGING_DIR"
BASE_URL="$BASE_URL"
DNSDIST_PORT=$DNSDIST_PORT
EOF
    echo "BASE_URL=$BASE_URL"
    echo "DNSDIST_PORT=$DNSDIST_PORT"
    echo "WORK=$WORK"
    ;;

  down)
    if [ -f "$STATE_FILE" ]; then
      # shellcheck disable=SC1090
      . "$STATE_FILE"
      # $WEB_PID is the `runuser` wrapper's own PID, not the actual
      # `alderpointdns-go web` process it execs -- a real leak this
      # closes: `kill -9` on runuser does NOT kill its child, so every
      # prior version of this script left the real web process (and its
      # own real dnsdist/named children, since it's the one that drives
      # DNS Runtime Apply) running forever, one more orphaned generation
      # per "up" -- confirmed directly (nine leaked `alderpointdns-go
      # web` processes found accumulated on this host during the
      # 2026-09-04 session that added the DNSCrypt verification pass).
      # Pattern-match on this fixture's own unique -db path instead of
      # trusting a stored PID, matching the same discipline already used
      # for named/dnsdist below.
      pkill -9 -f "alderpointdns-go web -db $WORK/app.db" 2>/dev/null || true
      kill -9 "$WEB_PID" 2>/dev/null || true
      kill -9 "$HOSTAGENT_PID" 2>/dev/null || true
      pkill -9 -f "named -g -c $BIND_DIR/named.conf" 2>/dev/null || true
      pkill -9 -f "dnsdist -C $STAGING_DIR/dnsdist.conf" 2>/dev/null || true
      rm -rf "$BIND_DIR"
    fi
    rm -rf "$WORK"
    echo "fixture torn down"
    ;;

  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
