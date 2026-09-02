#!/usr/bin/env bash
# ExecStart for apdns-reboot-validate.service -- a ONE-TIME, Alex-enabled
# systemd unit that runs automatically after the real reboot proof and
# writes /root/apdns-reboot-proof/post-reboot-validation.log.
#
# Pure observation. This script must NEVER start, stop, restart, or
# promote anything -- only curl/dig/systemctl-status/ss/podman-ps style
# read-only checks. If something didn't come back on its own, that IS
# the result being tested; recording it clearly is this script's whole
# job. Recovery is for Alex/CC after SSH login, not this script.
#
# Self-disables at the end (success or failure) so it does not fire
# again on a later, unrelated reboot -- genuinely one-time, matching
# how it's meant to be armed (systemctl enable, right before each
# planned reboot test).
set -uo pipefail

OUT_DIR=/root/apdns-reboot-proof
OUT_FILE="$OUT_DIR/post-reboot-validation.log"
PRE_FILE="$OUT_DIR/pre-reboot-capture.log"
mkdir -p "$OUT_DIR"

RESULTS=()
record() {
    local name="$1" ok="$2" detail="$3"
    if [ "$ok" -eq 0 ]; then
        RESULTS+=("PASS: $name -- $detail")
    else
        RESULTS+=("FAIL: $name -- $detail")
    fi
}

# Bounded wait for the web API to answer at all before running the rest
# of the checks -- "briefly", not indefinitely, and never anything that
# starts/fixes it. 90s covers a normal boot-survival sequence (hostagent
# -> web -> dns-promote) with real margin; if it's not up by then, that
# IS the failure this proof is checking for.
waited=0
health_up=1
while [ "$waited" -lt 90 ]; do
    if curl -sk -o /dev/null --max-time 3 https://127.0.0.1:8443/api/health; then
        health_up=0
        break
    fi
    sleep 3
    waited=$((waited + 3))
done
record "web API reachable within 90s of this validator starting" "$health_up" "waited ${waited}s"

health_json="$(curl -sk --max-time 5 https://127.0.0.1:8443/api/health 2>/dev/null)"
health_code="$(curl -sk -o /dev/null --max-time 5 -w '%{http_code}' https://127.0.0.1:8443/api/health 2>/dev/null)"
record "/api/health returns 200" "$([ "$health_code" = "200" ] && echo 0 || echo 1)" "http_code=$health_code"

login_code="$(curl -sk -o /dev/null --max-time 5 -w '%{http_code}' https://127.0.0.1:8443/ 2>/dev/null)"
record "login page reachable on :8443" "$([ "$login_code" = "200" ] && echo 0 || echo 1)" "http_code=$login_code"

udp_out="$(dig +short +time=3 +tries=2 @172.16.43.100 cloudflare.com 2>&1)"
record "UDP :53 answer" "$([ -n "$udp_out" ] && ! echo "$udp_out" | grep -qi 'error\|timed out\|refused' && echo 0 || echo 1)" "$(echo "$udp_out" | tr '\n' ' ')"

tcp_out="$(dig +tcp +short +time=3 +tries=2 @172.16.43.100 cloudflare.com 2>&1)"
record "TCP :53 answer" "$([ -n "$tcp_out" ] && ! echo "$tcp_out" | grep -qi 'error\|timed out\|refused' && echo 0 || echo 1)" "$(echo "$tcp_out" | tr '\n' ' ')"

local_out="$(dig +short +time=3 +tries=2 @172.16.43.100 3d-printer.mylan.network 2>&1)"
record "local DNS record resolves (3d-printer.mylan.network)" "$([ "$local_out" = "192.168.32.15" ] && echo 0 || echo 1)" "got: $local_out"

block_out="$(dig +time=3 +tries=2 @172.16.43.100 doubleclick.net 2>&1)"
block_status="$(echo "$block_out" | grep -o 'status: [A-Z]*' | head -1)"
record "blocklist NXDOMAIN/REFUSED (doubleclick.net)" "$(echo "$block_status" | grep -qE 'NXDOMAIN|REFUSED' && echo 0 || echo 1)" "$block_status"

up_out="$(dig +short +time=3 +tries=2 @172.16.43.100 cloudflare.com 2>&1)"
record "upstream resolves (cloudflare.com)" "$([ -n "$up_out" ] && ! echo "$up_out" | grep -qi 'error\|timed out\|refused' && echo 0 || echo 1)" "$(echo "$up_out" | tr '\n' ' ')"

named_count="$(pgrep -c named 2>/dev/null || echo 0)"
dnsdist_count="$(pgrep -c dnsdist 2>/dev/null || echo 0)"
hostagent_count="$(pgrep -cf '^/root/apdns-go-live-hostagent/apdns-hostagent -socket' 2>/dev/null || echo 0)"
web_count="$(podman ps --filter name=apdns-go-live --filter status=running -q 2>/dev/null | wc -l)"
record "exactly one named" "$([ "$named_count" -eq 1 ] && echo 0 || echo 1)" "count=$named_count"
record "exactly one dnsdist" "$([ "$dnsdist_count" -eq 1 ] && echo 0 || echo 1)" "count=$dnsdist_count"
record "exactly one apdns-hostagent" "$([ "$hostagent_count" -eq 1 ] && echo 0 || echo 1)" "count=$hostagent_count"
record "exactly one running apdns-go-live web container" "$([ "$web_count" -eq 1 ] && echo 0 || echo 1)" "count=$web_count"

banned_ports="$(ss -tulnp 2>/dev/null | grep -E ':10443|:18443')"
record "no :10443/:18443 bound" "$([ -z "$banned_ports" ] && echo 0 || echo 1)" "${banned_ports:-none found}"

dnscrypt_status="$(systemctl is-enabled dnscrypt-proxy.socket dnscrypt-proxy.service 2>&1 | tr '\n' ' ')"
record "dnscrypt-proxy remains masked" "$(echo "$dnscrypt_status" | grep -q 'masked masked' && echo 0 || echo 1)" "$dnscrypt_status"

live_sha="$(echo "$health_json" | grep -o '"version":"[a-f0-9]*"' | cut -d'"' -f4)"
expected_sha=""
if [ -f "$PRE_FILE" ]; then
    expected_sha="$(grep -oP '^live SHA \(parsed\): \K[a-f0-9]+' "$PRE_FILE" | head -1)"
fi
if [ -z "$expected_sha" ]; then
    record "live SHA unchanged" 1 "no pre-reboot-capture.log SHA found to compare against (run pre-reboot-capture.sh first next time) -- live SHA is $live_sha"
else
    record "live SHA unchanged" "$([ "$live_sha" = "$expected_sha" ] && echo 0 || echo 1)" "pre-reboot=$expected_sha post-reboot=$live_sha"
fi

fail_count=0
for r in "${RESULTS[@]}"; do
    case "$r" in FAIL:*) fail_count=$((fail_count + 1)) ;; esac
done

{
    echo "=== post-reboot validation: $(date -u '+%Y-%m-%dT%H:%M:%SZ') ($(date))"
    echo "uptime: $(uptime -p 2>/dev/null || uptime)"
    echo
    printf '%s\n' "${RESULTS[@]}"
    echo
    if [ "$fail_count" -eq 0 ]; then
        echo "=== RESULT: ALL CHECKS PASSED -- boot survival proven, no manual steps were taken or needed ==="
    else
        echo "=== RESULT: $fail_count CHECK(S) FAILED -- this validator took NO recovery action by design. ==="
        echo "Manual recovery is for Alex/CC after login -- see the handoff memory"
        echo "(alderpointdns-go-reboot-validation-handoff.md) 'If it does NOT come back"
        echo "cleanly' section, or start with:"
        echo "  journalctl -u apdns-go-live-hostagent.service -u apdns-go-live-web.service -u apdns-go-live-dns-promote.service -n 100 --no-pager"
    fi
    echo
    echo "Raw /api/health at check time:"
    echo "$health_json"
} > "$OUT_FILE" 2>&1

# One-time by design: never re-arm automatically. Alex/CC re-enables
# this unit explicitly before each future planned reboot test.
systemctl disable apdns-reboot-validate.service >/dev/null 2>&1 || true

exit 0
