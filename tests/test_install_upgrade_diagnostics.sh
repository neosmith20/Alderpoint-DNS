#!/bin/sh
set -eu

ROOT="$(mktemp -d /tmp/alderpointdns-install-test.XXXXXX)"
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT/var/lib/alderpointdns/backups"

ALDERPOINTDNS_INSTALL_ROOT="$ROOT" /opt/alderpointdns/scripts/install.sh --dry-run --skip-apt --source /opt/alderpointdns > "$ROOT/install.out"
grep -q "Alderpoint DNS installation path prepared" "$ROOT/install.out" || {
  echo "installer dry-run did not complete" >&2
  exit 1
}
grep -q "generate session, dnsdist API, and dnsdist web credentials" "$ROOT/install.out" || {
  echo "installer dry-run did not plan secret generation" >&2
  exit 1
}

mkdir -p "$ROOT/opt/alderpointdns"
cp -a /opt/alderpointdns/. "$ROOT/opt/alderpointdns/"
ALDERPOINTDNS_INSTALL_ROOT="$ROOT" /opt/alderpointdns/scripts/upgrade.sh --dry-run --source /opt/alderpointdns --skip-service-restart > "$ROOT/upgrade.out"
grep -q "Current Alderpoint DNS version" "$ROOT/upgrade.out" || {
  echo "upgrade dry-run did not inspect current version" >&2
  exit 1
}
grep -q "Alderpoint DNS upgrade completed" "$ROOT/upgrade.out" || {
  echo "upgrade dry-run did not complete" >&2
  exit 1
}

# Recent Logs access (System Status page) is granted through the same
# sudoers drop-in every other privileged web action uses, so both fresh
# install and upgrade must plan to (re)install it, and it must actually
# authorize the fixed, allowlisted "logs <unit>" commands the web app calls
# -- never an unrestricted journalctl/systemctl escape hatch.
grep -q "sudoers-alderpointdns" "$ROOT/install.out" || {
  echo "installer dry-run did not plan to install the sudoers drop-in" >&2
  exit 1
}
grep -q "sudoers-alderpointdns" "$ROOT/upgrade.out" || {
  echo "upgrade dry-run did not plan to reinstall the sudoers drop-in" >&2
  exit 1
}
for unit in alderpointdns alderpointdns-analytics named dnsdist; do
  grep -q "alderpointdns_compiler.py logs $unit" /opt/alderpointdns/packaging/sudoers-alderpointdns || {
    echo "sudoers drop-in is missing the log-access entry for $unit" >&2
    exit 1
  }
done
if grep -Eq 'ALL=\(root\) NOPASSWD: ALL|alderpointdns_compiler\.py logs \$|alderpointdns_compiler\.py logs \*' /opt/alderpointdns/packaging/sudoers-alderpointdns; then
  echo "sudoers drop-in grants unrestricted or wildcard log access" >&2
  exit 1
fi
visudo -cf /opt/alderpointdns/packaging/sudoers-alderpointdns >/dev/null || {
  echo "sudoers drop-in has invalid syntax" >&2
  exit 1
}

/opt/alderpointdns/scripts/alderpointdns-diagnostics --self-test-redaction > "$ROOT/redaction.out"
if grep -Eq 'hunter2|abcdef|secret&client|BEGIN PRIVATE KEY|x-api-key: secret' "$ROOT/redaction.out"; then
  echo "diagnostics redaction self-test leaked secret text" >&2
  exit 1
fi

/opt/alderpointdns/scripts/alderpointdns-diagnostics --output-dir "$ROOT" --no-journal > "$ROOT/bundle-path.txt"
BUNDLE="$(cat "$ROOT/bundle-path.txt")"
test -f "$BUNDLE" || {
  echo "diagnostics bundle was not created" >&2
  exit 1
}
tar -tzf "$BUNDLE" | grep -q 'alderpointdns-diagnostics/summary.json' || {
  echo "diagnostics bundle missing summary" >&2
  exit 1
}
tar -tzf "$BUNDLE" | grep -q 'alderpointdns-diagnostics/database_schema.json' || {
  echo "diagnostics bundle missing schema summary" >&2
  exit 1
}
if tar -xOzf "$BUNDLE" | grep -Eq 'BEGIN PRIVATE KEY|ALDERPOINTDNS_SESSION_SECRET|dnsdist-api.key|Authorization: Basic [A-Za-z0-9+/=]'; then
  echo "diagnostics bundle leaked secret-like content" >&2
  exit 1
fi
if tar -xOzf "$BUNDLE" | grep -Ei 'secret "[^"]{8,}"' | grep -qv '\[REDACTED\]'; then
  echo "diagnostics bundle leaked an unredacted BIND key secret (e.g. rndc-key)" >&2
  exit 1
fi

test -f /opt/alderpointdns/packaging/debian/control || {
  echo "debian control file missing" >&2
  exit 1
}
/opt/alderpointdns/scripts/build-deb.sh --output-dir "$ROOT" > "$ROOT/deb-path.txt"
DEB="$(cat "$ROOT/deb-path.txt")"
test -f "$DEB" || {
  echo "test deb package was not created" >&2
  exit 1
}
dpkg-deb --info "$DEB" | grep -q "Package: alderpointdns" || {
  echo "test deb package metadata is invalid" >&2
  exit 1
}
grep -q "normal uninstall must not destroy persistent data" /opt/alderpointdns/docs/packaging.md || {
  echo "packaging documentation missing persistent-data statement" >&2
  exit 1
}

echo "install, upgrade, and diagnostics tests passed"
