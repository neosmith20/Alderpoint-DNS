#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

systemctl is-active --quiet bindguard || fail "bindguard service is not active"
systemctl is-enabled --quiet bindguard || fail "bindguard service is not enabled"
ss -ltnup | grep -Eq '(^|[[:space:]])(0[.]0[.]0[.]0|\*):3000' || fail "bindguard is not listening on 0.0.0.0:3000"
curl --silent --show-error --fail --max-time 5 http://127.0.0.1:3000/setup | grep -q 'Initial administrator setup' || fail "setup page missing"
curl --silent --show-error --include --max-time 5 http://127.0.0.1:3000/ | grep -q '303 See Other' || fail "unauthenticated dashboard did not redirect"
runuser -u bindguard -- sudo -n /opt/bindguard/app/bindguard_compiler.py update-sources | grep -q 'active_domains=' || fail "bindguard sudo helper failed"

echo "web smoke tests passed"
