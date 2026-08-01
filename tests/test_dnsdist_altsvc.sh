#!/bin/sh
set -eu

# Regression test: the DoH listener advertises HTTP/3 via an Alt-Svc response
# header only while DoH3 is enabled, and the generated configuration must
# still validate with `dnsdist --check-config` in both states. Skips (does
# not fail) when no dnsdist binary is available to validate against.

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

if ! command -v dnsdist >/dev/null 2>&1; then
  echo "SKIPPED: dnsdist is not installed; cannot validate the generated configuration" >&2
  exit 0
fi

grep -q 'customResponseHeaders' "$ROOT/packaging/dnsdist.conf" ||
  fail "packaging/dnsdist.conf no longer sets customResponseHeaders for the Alt-Svc header"
grep -q 'if doh3Enabled then' "$ROOT/packaging/dnsdist.conf" ||
  fail "expected doh3Enabled guard is missing from packaging/dnsdist.conf"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

CONF="$WORKDIR/dnsdist.conf"
sed \
  -e 's/ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER/test-console-key/' \
  -e 's/ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER/test-password/' \
  -e 's/ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER/test-api-key/' \
  "$ROOT/packaging/dnsdist.conf" >"$CONF"

ALDERPOINTDNS_DNS_DOH=1 ALDERPOINTDNS_DNS_DOH3=1 dnsdist --check-config -C "$CONF" >"$WORKDIR/doh3-on.log" 2>&1 ||
  fail "config with DoH3 enabled did not validate: $(cat "$WORKDIR/doh3-on.log")"

ALDERPOINTDNS_DNS_DOH=1 dnsdist --check-config -C "$CONF" >"$WORKDIR/doh3-off.log" 2>&1 ||
  fail "config with DoH3 disabled did not validate: $(cat "$WORKDIR/doh3-off.log")"

echo "Alderpoint DNS Alt-Svc / DoH3 configuration test passed"
