#!/bin/sh
set -eu

ROOT="$(mktemp -d /tmp/bindguard-install-test.XXXXXX)"
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT/var/lib/bindguard/backups"

BINDGUARD_INSTALL_ROOT="$ROOT" /opt/bindguard/scripts/install.sh --dry-run --skip-apt --source /opt/bindguard > "$ROOT/install.out"
grep -q "BindGuard installation path prepared" "$ROOT/install.out" || {
  echo "installer dry-run did not complete" >&2
  exit 1
}
grep -q "generate session, dnsdist API, and dnsdist web credentials" "$ROOT/install.out" || {
  echo "installer dry-run did not plan secret generation" >&2
  exit 1
}

mkdir -p "$ROOT/opt/bindguard"
cp -a /opt/bindguard/. "$ROOT/opt/bindguard/"
BINDGUARD_INSTALL_ROOT="$ROOT" /opt/bindguard/scripts/upgrade.sh --dry-run --source /opt/bindguard --skip-service-restart > "$ROOT/upgrade.out"
grep -q "Current BindGuard version" "$ROOT/upgrade.out" || {
  echo "upgrade dry-run did not inspect current version" >&2
  exit 1
}
grep -q "BindGuard upgrade completed" "$ROOT/upgrade.out" || {
  echo "upgrade dry-run did not complete" >&2
  exit 1
}

/opt/bindguard/scripts/bindguard-diagnostics --self-test-redaction > "$ROOT/redaction.out"
if grep -Eq 'hunter2|abcdef|secret&client|BEGIN PRIVATE KEY|x-api-key: secret' "$ROOT/redaction.out"; then
  echo "diagnostics redaction self-test leaked secret text" >&2
  exit 1
fi

/opt/bindguard/scripts/bindguard-diagnostics --output-dir "$ROOT" --no-journal > "$ROOT/bundle-path.txt"
BUNDLE="$(cat "$ROOT/bundle-path.txt")"
test -f "$BUNDLE" || {
  echo "diagnostics bundle was not created" >&2
  exit 1
}
tar -tzf "$BUNDLE" | grep -q 'bindguard-diagnostics/summary.json' || {
  echo "diagnostics bundle missing summary" >&2
  exit 1
}
tar -tzf "$BUNDLE" | grep -q 'bindguard-diagnostics/database_schema.json' || {
  echo "diagnostics bundle missing schema summary" >&2
  exit 1
}
if tar -xOzf "$BUNDLE" | grep -Eq 'BEGIN PRIVATE KEY|BINDGUARD_SESSION_SECRET|dnsdist-api.key|Authorization: Basic [A-Za-z0-9+/=]'; then
  echo "diagnostics bundle leaked secret-like content" >&2
  exit 1
fi
if tar -xOzf "$BUNDLE" | grep -Ei 'secret "[^"]{8,}"' | grep -qv '\[REDACTED\]'; then
  echo "diagnostics bundle leaked an unredacted BIND key secret (e.g. rndc-key)" >&2
  exit 1
fi

test -f /opt/bindguard/packaging/debian/control || {
  echo "debian control file missing" >&2
  exit 1
}
/opt/bindguard/scripts/build-deb.sh --output-dir "$ROOT" > "$ROOT/deb-path.txt"
DEB="$(cat "$ROOT/deb-path.txt")"
test -f "$DEB" || {
  echo "test deb package was not created" >&2
  exit 1
}
dpkg-deb --info "$DEB" | grep -q "Package: bindguard" || {
  echo "test deb package metadata is invalid" >&2
  exit 1
}
grep -q "normal uninstall must not destroy persistent data" /opt/bindguard/docs/packaging.md || {
  echo "packaging documentation missing persistent-data statement" >&2
  exit 1
}

echo "install, upgrade, and diagnostics tests passed"
