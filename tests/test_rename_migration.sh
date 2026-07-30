#!/bin/sh
set -eu

# Regression coverage for the BindGuard -> Alderpoint DNS rename: (1) no
# stale product-name references leaked into current source/docs, and (2)
# upgrade.sh correctly detects and migrates a legacy BindGuard installation
# layout rather than treating it as a fresh install.

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

echo "== checking for stale BindGuard-era references outside historical files =="
STALE="$(grep -rlI "bindguard\|BindGuard\|BINDGUARD" "$ROOT_DIR" \
  --exclude-dir=.git --exclude-dir=__pycache__ --exclude-dir=audit \
  --exclude=AGENT_PROGRESS.md --exclude=CHANGELOG.md --exclude=bindguard-handoff.md \
  --exclude-dir=progress.md 2>/dev/null | grep -v '/docs/progress\.md$' || true)"
# Files that intentionally still say "bindguard": the preserved Linux
# system user/group, deprecated compatibility wrappers/docs, and this
# test's own patterns.
ALLOWED='
app/bindguard_compiler.py
scripts/bindguard-diagnostics
packaging/alderpointdns.service
packaging/alderpointdns-analytics.service
packaging/sudoers-alderpointdns
packaging/debian/postinst
packaging/debian/changelog
scripts/install.sh
scripts/upgrade.sh
app/replication.py
app/backup.py
tests/test_backup.py
tests/test_web_smoke.sh
tests/test_rename_migration.sh
docs/compatibility.md
docs/migrating-from-bindguard.md
'
for f in $STALE; do
  rel="${f#"$ROOT_DIR"/}"
  case "$(printf '%s' "$ALLOWED" | tr -s ' \n' '\n')" in
    *"$rel"*) continue ;;
  esac
  echo "unexpected stale BindGuard-era reference in: $rel" >&2
  grep -n "bindguard\|BindGuard\|BINDGUARD" "$f" | head -3 >&2
  exit 1
done
echo "no unexpected stale references found"

echo "== legacy BindGuard install is migrated, not treated as a fresh install =="
TESTROOT="$(mktemp -d /tmp/alderpointdns-rename-migration-test.XXXXXX)"
trap 'rm -rf "$TESTROOT"' EXIT

mkdir -p "$TESTROOT/opt/bindguard/app" "$TESTROOT/opt/bindguard/scripts"
mkdir -p "$TESTROOT/etc/bindguard/certs" "$TESTROOT/var/lib/bindguard/compiled/bind" "$TESTROOT/var/log/bindguard"
echo "legacy webapp placeholder" > "$TESTROOT/opt/bindguard/app/webapp.py"
printf '#!/bin/sh\necho fake-legacy-backup\n' > "$TESTROOT/opt/bindguard/scripts/backup.sh"
chmod +x "$TESTROOT/opt/bindguard/scripts/backup.sh"
echo "old secret" > "$TESTROOT/etc/bindguard/secrets.env"
: > "$TESTROOT/var/lib/bindguard/bindguard.db"
echo "rpz-data" > "$TESTROOT/var/lib/bindguard/compiled/bind/bindguard.rpz"
echo "log line" > "$TESTROOT/var/log/bindguard/named.log"

ALDERPOINTDNS_INSTALL_ROOT="$TESTROOT" "$ROOT_DIR/scripts/upgrade.sh" --source "$ROOT_DIR" --skip-service-restart > "$TESTROOT/upgrade.out" 2>&1 || {
  echo "legacy migration upgrade failed:" >&2
  cat "$TESTROOT/upgrade.out" >&2
  exit 1
}

grep -q "legacy BindGuard installation detected" "$TESTROOT/upgrade.out" || {
  echo "upgrade.sh did not detect the legacy installation" >&2
  exit 1
}
grep -q "Alderpoint DNS upgrade completed" "$TESTROOT/upgrade.out" || {
  echo "upgrade.sh did not complete after legacy migration" >&2
  exit 1
}

test -f "$TESTROOT/opt/alderpointdns/app/webapp.py" || { echo "app not migrated to /opt/alderpointdns" >&2; exit 1; }
test ! -e "$TESTROOT/opt/bindguard" || { echo "old /opt/bindguard still present after migration" >&2; exit 1; }
test -f "$TESTROOT/var/lib/alderpointdns/alderpointdns.db" || { echo "database was not renamed/migrated" >&2; exit 1; }
test -f "$TESTROOT/var/lib/alderpointdns/compiled/bind/alderpointdns.rpz" || { echo "compiled RPZ zone was not renamed/migrated" >&2; exit 1; }
test -f "$TESTROOT/etc/alderpointdns/secrets.env" || { echo "/etc config was not migrated" >&2; exit 1; }
test -f "$TESTROOT/var/log/alderpointdns/named.log" || { echo "log directory was not migrated" >&2; exit 1; }
test -f "$TESTROOT/etc/systemd/system/alderpointdns.service" || { echo "new systemd unit was not installed" >&2; exit 1; }

echo "legacy install correctly migrated to Alderpoint DNS paths"
echo "rename migration tests passed"
