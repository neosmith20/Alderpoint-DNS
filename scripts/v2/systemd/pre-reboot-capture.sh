#!/usr/bin/env bash
# Captures the live appliance's pre-reboot baseline into
# /root/apdns-reboot-proof/pre-reboot-capture.log -- read by
# post-reboot-validate.sh afterward to compare against (e.g. "live SHA
# unchanged"), and readable by a human either way.
#
# Pure observation -- never starts, stops, or changes anything.
#
# Usage: scripts/v2/systemd/pre-reboot-capture.sh
set -uo pipefail

OUT_DIR=/root/apdns-reboot-proof
OUT_FILE="$OUT_DIR/pre-reboot-capture.log"
REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)"

mkdir -p "$OUT_DIR"

{
    echo "=== pre-reboot capture: $(date -u '+%Y-%m-%dT%H:%M:%SZ') ($(date))"
    echo

    echo "--- repo HEAD ---"
    (cd "$REPO_ROOT" && git rev-parse HEAD 2>&1)
    echo

    echo "--- live /api/health ---"
    curl -sk https://127.0.0.1:8443/api/health 2>&1
    echo
    echo "live SHA (parsed): $(curl -sk https://127.0.0.1:8443/api/health 2>/dev/null | grep -o '"version":"[a-f0-9]*"' | cut -d'"' -f4)"
    echo

    echo "--- systemd enabled status: apdns-go-live-* ---"
    systemctl is-enabled apdns-go-live-hostagent.service apdns-go-live-web.service apdns-go-live-dns-promote.service 2>&1
    systemctl is-active  apdns-go-live-hostagent.service apdns-go-live-web.service apdns-go-live-dns-promote.service 2>&1
    echo

    echo "--- dnscrypt-proxy mask status ---"
    systemctl is-enabled dnscrypt-proxy.socket dnscrypt-proxy.service 2>&1
    echo

    echo "--- process/container topology ---"
    podman ps -a 2>&1
    echo "named count: $(pgrep -c named 2>/dev/null || echo 0)"
    echo "dnsdist count: $(pgrep -c dnsdist 2>/dev/null || echo 0)"
    echo "hostagent: $(pgrep -af 'apdns-hostagent -socket' 2>/dev/null | grep -v ' -c ' || echo none)"
    echo

    echo "--- listeners ---"
    ss -tulnp 2>&1 | grep -E ':53( |$)|:8443|:10443|:18443|:853|:443'
    echo

    echo "--- UDP DNS proof ---"
    dig +short +time=3 +tries=2 @172.16.43.100 cloudflare.com 2>&1
    echo

    echo "--- TCP DNS proof ---"
    dig +tcp +short +time=3 +tries=2 @172.16.43.100 cloudflare.com 2>&1
    echo

    echo "--- local DNS proof (3d-printer.mylan.network) ---"
    dig +short +time=3 +tries=2 @172.16.43.100 3d-printer.mylan.network 2>&1
    echo

    echo "--- blocklist proof (doubleclick.net) ---"
    dig +time=3 +tries=2 @172.16.43.100 doubleclick.net 2>&1 | grep -E 'status:|ANSWER SECTION'
    echo

    echo "--- upstream proof (cloudflare.com, repeat) ---"
    dig +short +time=3 +tries=2 @172.16.43.100 cloudflare.com 2>&1
    echo

    echo "=== capture complete ==="
} > "$OUT_FILE" 2>&1

echo "wrote $OUT_FILE"
cat "$OUT_FILE"
