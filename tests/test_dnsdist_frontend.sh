#!/bin/sh
set -eu
trap 'rndc querylog off >/dev/null 2>&1 || true; systemctl start named >/dev/null 2>&1 || true' EXIT

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
need rndc
need python3

dnsdist --version | grep -q 'dns-over-quic' || fail "official dnsdist build with dns-over-quic support is required"

python3 - <<'PY'
import sqlite3

db = sqlite3.connect("/var/lib/alderpointdns/alderpointdns.db")
try:
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS encryption_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """
    )
    for key, value in {
        "doh3_enabled": "1",
        "doq_enabled": "1",
        "doh3_port": "443",
        "doq_port": "853",
        "server_hostname": "alderpointdns.local",
        "listen_ipv4": "0.0.0.0",
        "listen_ipv6": "::",
    }.items():
        db.execute(
            "INSERT INTO encryption_settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
    db.commit()
finally:
    db.close()
PY
/opt/alderpointdns/app/alderpointdns_compiler.py encryption-deploy >/dev/null

dig @127.0.0.1 -p 5353 cloudflare.com A +time=3 +tries=1 >/dev/null || fail "BIND backend UDP resolution failed"
dig @127.0.0.1 -p 53 cloudflare.com A +time=3 +tries=1 >/dev/null || fail "dnsdist UDP resolution failed"
dig @127.0.0.1 -p 53 cloudflare.com A +tcp +time=3 +tries=1 >/dev/null || fail "dnsdist TCP resolution failed"

kdig +https @127.0.0.1 -p 443 \
  +tls-ca=/etc/alderpointdns/certs/alderpointdns-lab.crt \
  +tls-hostname=alderpointdns.local \
  cloudflare.com A +time=3 | grep -q 'status: NOERROR' || fail "DoH query failed"

kdig +tls @127.0.0.1 -p 853 \
  +tls-ca=/etc/alderpointdns/certs/alderpointdns-lab.crt \
  +tls-hostname=alderpointdns.local \
  cloudflare.com A +time=3 | grep -q 'status: NOERROR' || fail "DoT query failed"

cert_modulus="$(openssl x509 -noout -modulus -in /etc/alderpointdns/certs/alderpointdns-lab.crt | sha256sum | awk '{print $1}')"
key_modulus="$(openssl rsa -noout -modulus -in /etc/alderpointdns/certs/alderpointdns-lab.key 2>/dev/null | sha256sum | awk '{print $1}')"
[ "$cert_modulus" = "$key_modulus" ] || fail "DoH/DoT certificate and private key do not match"

curl --silent --show-error --fail --max-time 5 \
  --user "$(cat /etc/alderpointdns/dnsdist-web.creds)" \
  -H "x-api-key: $(cat /etc/alderpointdns/dnsdist-api.key)" \
  http://127.0.0.1:8083/jsonstat?command=stats |
  jq -e 'has("queries") and (.queries >= 1) and has("responses")' >/dev/null || fail "dnsdist stats API failed"

if curl --silent --show-error --fail --max-time 5 http://127.0.0.1:8083/jsonstat?command=stats >/tmp/alderpointdns-unauth-stats.out 2>&1; then
  fail "dnsdist stats API allowed unauthenticated access"
fi

ss -lunp | grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0|\*):53' || fail "dnsdist is not listening on UDP 0.0.0.0:53"
ss -lunp | grep -Eq '(^|[[:space:]])(\[::\]|\*):53' || fail "dnsdist is not listening on UDP [::]:53"
ss -ltnp | grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0|\*):53' || fail "dnsdist is not listening on TCP 0.0.0.0:53"
ss -ltnp | grep -Eq '(^|[[:space:]])(\[::\]|\*):53' || fail "dnsdist is not listening on TCP [::]:53"
ss -ltnp | grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0|\*):443' || fail "dnsdist is not listening on TCP 0.0.0.0:443"
ss -ltnp | grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0|\*):853' || fail "dnsdist is not listening on TCP 0.0.0.0:853"
ss -lunp | grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0|\*):853' || fail "dnsdist is not listening on UDP 0.0.0.0:853 for DoQ"
ss -lunp | grep -Eq '(^|[[:space:]])(\[::\]|\*):853' || fail "dnsdist is not listening on UDP [::]:853 for DoQ"
ss -ltnp | grep -q '127.0.0.1:8083' || fail "dnsdist web statistics interface is not loopback-only"
ss -ltnp | grep -q '127.0.0.1:5199' || fail "dnsdist control console is not loopback-only"

if ss -H -lntup '( sport = :8083 or sport = :5199 )' |
  awk '{ print $5 }' |
  grep -Ev '^(127[.]0[.]0[.]1:(8083|5199))$'; then
  fail "dnsdist is listening on a non-loopback management address"
fi

dnsdist --check-config -C /etc/dnsdist/dnsdist.conf >/dev/null || fail "installed dnsdist configuration does not validate"
grep -q 'ALDERPOINTDNS_DNS_ALLOW_ALL' /etc/dnsdist/dnsdist.conf || fail "dnsdist allow-all switch is missing"
grep -q '10.0.0.0/8' /etc/dnsdist/dnsdist.conf || fail "dnsdist RFC1918 10/8 ACL is missing"
grep -q '172.16.0.0/12' /etc/dnsdist/dnsdist.conf || fail "dnsdist RFC1918 172.16/12 ACL is missing"
grep -q '192.168.0.0/16' /etc/dnsdist/dnsdist.conf || fail "dnsdist RFC1918 192.168/16 ACL is missing"
grep -q 'setQueryRate(120, 10' /etc/dnsdist/dnsdist.conf || fail "dnsdist query rate limit is missing"
grep -q 'setRCodeRate(DNSRCode.NXDOMAIN, 80, 10' /etc/dnsdist/dnsdist.conf || fail "dnsdist NXDOMAIN rate limit is missing"
grep -q 'setQTypeRate(DNSQType.ANY, 10, 10' /etc/dnsdist/dnsdist.conf || fail "dnsdist ANY query rate limit is missing"

systemctl restart dnsdist
dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 >/dev/null || fail "dnsdist failed after restart"

systemctl stop named
if dig @127.0.0.1 -p 53 alderpointdns-backend-failure-test.example A +time=2 +tries=1 >/tmp/alderpointdns-backend-failure.out 2>&1; then
  systemctl start named
  fail "dnsdist unexpectedly resolved while BIND backend was stopped"
fi
systemctl start named
dig @127.0.0.1 -p 53 cloudflare.com A +time=5 +tries=1 >/dev/null || fail "dnsdist did not recover after BIND backend restart"

dnsdist --check-config -C /opt/alderpointdns/tests/dnsdist-doq-capability.conf >/dev/null || fail "DoQ capability config did not validate"
kdig +quic @127.0.0.1 -p 853 \
  +tls-ca=/etc/alderpointdns/certs/alderpointdns-lab.crt \
  +tls-hostname=alderpointdns.local \
  cloudflare.com A +time=3 | grep -q 'status: NOERROR' || fail "DoQ query failed"
if kdig +quic @127.0.0.1 -p 853 \
  +tls-ca=/etc/alderpointdns/certs/alderpointdns-lab.crt \
  +tls-hostname=wrong.local \
  cloudflare.com A +time=3 >/tmp/alderpointdns-doq-wrong-host.out 2>&1; then
  fail "DoQ accepted a certificate with the wrong hostname"
fi
dnsdist --check-config -C /opt/alderpointdns/tests/dnsdist-doh3-capability.conf >/dev/null || fail "DoH3 capability config did not validate"
grep -q 'address="127.0.0.1:5354"' /etc/dnsdist/dnsdist.conf || fail "dnsdist backend is not using the PROXYv2 BIND listener"
grep -q 'useProxyProtocol=true' /etc/dnsdist/dnsdist.conf || fail "dnsdist backend PROXYv2 forwarding is not enabled"

preserve_name="alderpointdns-preserve-$(date +%s).example"
rndc querylog on
dig -b 127.0.0.2 @127.0.0.1 -p 53 "$preserve_name" A +time=3 +tries=1 >/dev/null || true
sleep 1
rndc querylog off
tail -n 120 /var/log/alderpointdns/bind/named.log |
  grep -q "127[.]0[.]0[.]2#.*($preserve_name)" || fail "BIND did not log the original client address preserved by PROXYv2"

echo "dnsdist frontend tests passed"
