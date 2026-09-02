#!/usr/bin/env bash
# ExecStartPre for apdns-go-live-dns-promote.service -- runs immediately
# before every promote attempt (boot AND any later re-run of this unit)
# to fail loudly and clearly if something else already holds port 53,
# instead of letting dnsdist crash with the opaque "exited immediately
# after start" symptom (see the 2026-09-02 outage recovery: the real
# cause that time was a stray, unrelated dnscrypt-proxy.socket auto-
# starting after a host reboot and claiming the port first -- `ss`/
# /proc/net/udp never showed a wildcard listener even though the
# conflict was real, because Linux's UDP/TCP port allocator blocks a
# NEW wildcard 0.0.0.0:53 bind against an EXISTING specific-address
# bind on the same port number, not just an exact address match).
set -uo pipefail

conflict=$(ss -H -tulnp 2>/dev/null | awk '$5 ~ /:53$/ {print}')
if [ -n "$conflict" ]; then
    echo "FAIL: port 53 is already bound -- refusing to promote the DNS runtime (dnsdist would immediately crash with 'Address already in use')." >&2
    echo "Conflicting socket(s):" >&2
    echo "$conflict" >&2
    echo "Known past cause: dnscrypt-proxy.socket/.service (must stay masked -- check 'systemctl is-enabled dnscrypt-proxy.socket dnscrypt-proxy.service', both should read 'masked')." >&2
    echo "Check for any OTHER service/container that might have grabbed :53 before investigating further." >&2
    exit 1
fi
exit 0
