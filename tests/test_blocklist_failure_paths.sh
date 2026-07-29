#!/bin/sh
set -eu

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

/opt/bindguard/app/bindguard_compiler.py add-source "AdGuard DNS filter" "https://127.0.0.1:9/unreachable"
/opt/bindguard/app/bindguard_compiler.py deploy || fail "deploy with failed source and preserved previous copy should succeed"
/opt/bindguard/app/bindguard_compiler.py status | grep -q "AdGuard DNS filter" || fail "source status missing"
/opt/bindguard/app/bindguard_compiler.py status | grep -q "Connection refused\\|urlopen error" || fail "failed source update did not record an error"

before_hash="$(sha256sum /var/lib/bindguard/compiled/bind/bindguard.rpz | awk '{print $1}')"

if BINDGUARD_TEST_INVALID_RPZ=1 /opt/bindguard/app/bindguard_compiler.py deploy --no-download; then
  fail "invalid RPZ deployment unexpectedly succeeded"
fi
after_invalid_hash="$(sha256sum /var/lib/bindguard/compiled/bind/bindguard.rpz | awk '{print $1}')"
[ "$before_hash" = "$after_invalid_hash" ] || fail "invalid RPZ changed active configuration"

if BINDGUARD_TEST_FORCE_POSTCHECK_FAIL=1 /opt/bindguard/app/bindguard_compiler.py deploy --no-download; then
  fail "forced post-check failure unexpectedly succeeded"
fi
/opt/bindguard/app/bindguard_compiler.py status | grep -q "rolled_back" || fail "forced post-check failure did not record rollback"

/opt/bindguard/app/bindguard_compiler.py add-source "AdGuard DNS filter" "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"
/opt/bindguard/app/bindguard_compiler.py deploy || fail "restoring valid source failed"

echo "blocklist failure-path tests passed"
