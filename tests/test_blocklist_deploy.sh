#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

PYTHONPATH=/opt/bindguard python3 /opt/bindguard/tests/test_blocklist_parser.py
/opt/bindguard/app/bindguard_compiler.py init-db
/opt/bindguard/app/bindguard_compiler.py seed-lab
/opt/bindguard/app/bindguard_compiler.py add-custom block cloudflare-dns.com --comment "deployment test"
/opt/bindguard/app/bindguard_compiler.py add-custom allow cloudflare.com --comment "ordinary allow test"
/opt/bindguard/app/bindguard_compiler.py deploy

named-checkzone bindguard.rpz /var/lib/bindguard/compiled/bind/bindguard.rpz >/dev/null || fail "deployed RPZ does not validate"
dig @127.0.0.1 -p 5353 cloudflare.com A +time=3 +tries=1 | grep -q 'status: NOERROR' || fail "ordinary resolution failed after deploy"
kdig +quic @127.0.0.1 -p 853 +tls-ca=/etc/bindguard/certs/bindguard-lab.crt +tls-hostname=bindguard.local cloudflare.com A +time=3 | grep -q 'status: NOERROR' || fail "DoQ ordinary resolution failed after deploy"
if dig @127.0.0.1 -p 5353 cloudflare-dns.com A +time=3 +tries=1 | grep -q 'status: NXDOMAIN'; then
    :
else
  fail "custom blocked domain was not blocked"
fi
kdig +quic @127.0.0.1 -p 853 +tls-ca=/etc/bindguard/certs/bindguard-lab.crt +tls-hostname=bindguard.local cloudflare-dns.com A +time=3 | grep -q 'status: NXDOMAIN' || fail "DoQ blocked-domain response was not NXDOMAIN"

echo "blocklist compiler deployment tests passed"
