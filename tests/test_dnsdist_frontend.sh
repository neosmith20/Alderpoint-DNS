#!/bin/sh
set -eu
trap 'systemctl start named >/dev/null 2>&1 || true' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

need dig
need kdig
need curl
need jq
need openssl
need systemctl
need ss
need dnsdist

dig @127.0.0.1 -p 5353 cloudflare.com A +time=3 +tries=1 >/dev/null || fail "BIND backend UDP resolution failed"
dig @127.0.0.1 -p 53 cloudflare.com A +time=3 +tries=1 >/dev/null || fail "dnsdist UDP resolution failed"
dig @127.0.0.1 -p 53 cloudflare.com A +tcp +time=3 +tries=1 >/dev/null || fail "dnsdist TCP resolution failed"

kdig +https @127.0.0.1 -p 443 \
  +tls-ca=/etc/bindguard/certs/bindguard-lab.crt \
  +tls-hostname=bindguard.local \
  cloudflare.com A +time=3 >/dev/null || fail "DoH query failed"

kdig +tls @127.0.0.1 -p 853 \
  +tls-ca=/etc/bindguard/certs/bindguard-lab.crt \
  +tls-hostname=bindguard.local \
  cloudflare.com A +time=3 >/dev/null || fail "DoT query failed"

curl --silent --show-error --fail --max-time 5 \
  --user "$(cat /etc/bindguard/dnsdist-web.creds)" \
  -H "x-api-key: $(cat /etc/bindguard/dnsdist-api.key)" \
  http://127.0.0.1:8083/jsonstat?command=stats |
  jq -e 'has("queries") and (.queries >= 1) and has("responses")' >/dev/null || fail "dnsdist stats API failed"

ss -ltnup | grep -q '127.0.0.1:53' || fail "dnsdist is not listening on TCP/UDP 53"
ss -ltnup | grep -q '127.0.0.1:443' || fail "dnsdist is not listening on TCP 443"
ss -ltnup | grep -q '127.0.0.1:853' || fail "dnsdist is not listening on TCP 853"

systemctl restart dnsdist
dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 >/dev/null || fail "dnsdist failed after restart"

systemctl stop named
if dig @127.0.0.1 -p 53 bindguard-backend-failure-test.example A +time=2 +tries=1 >/tmp/bindguard-backend-failure.out 2>&1; then
  systemctl start named
  fail "dnsdist unexpectedly resolved while BIND backend was stopped"
fi
systemctl start named
dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 >/dev/null || fail "dnsdist did not recover after BIND backend restart"

if dnsdist --check-config -C /opt/bindguard/tests/dnsdist-doq-capability.conf >/tmp/bindguard-dnsdist-doq-check.out 2>&1; then
  kdig +quic @127.0.0.1 -p 853 cloudflare.com A +time=3 >/dev/null || fail "DoQ advertised by config but query failed"
else
  grep -qi 'DNS over QUIC support is not present' /tmp/bindguard-dnsdist-doq-check.out || fail "DoQ unavailable for an unexpected reason"
fi

if dnsdist --check-config -C /opt/bindguard/tests/dnsdist-doh3-capability.conf >/tmp/bindguard-dnsdist-doh3-check.out 2>&1; then
  echo "DoH3 config validated; runtime client test still pending because installed curl lacks HTTP/3 support detection in this script."
else
  grep -qi 'DNS over HTTP/3 support is not present' /tmp/bindguard-dnsdist-doh3-check.out || fail "DoH3 unavailable for an unexpected reason"
fi

echo "dnsdist frontend tests passed"
