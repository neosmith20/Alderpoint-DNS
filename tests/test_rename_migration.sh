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
docs/testing.md
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
printf 'BINDGUARD_SESSION_SECRET=super-secret-value-must-survive\n' > "$TESTROOT/etc/bindguard/secrets.env"
: > "$TESTROOT/var/lib/bindguard/bindguard.db"
echo "rpz-data" > "$TESTROOT/var/lib/bindguard/compiled/bind/bindguard.rpz"
echo "log line" > "$TESTROOT/var/log/bindguard/named.log"
mkdir -p "$TESTROOT/var/lib/bindguard/compiled/dnsdist"
cat > "$TESTROOT/var/lib/bindguard/compiled/bind/local-zones.conf" <<'EOF'
// Managed by BindGuard Local DNS. Do not edit by hand.
zone "home.arpa" {
	file "/var/lib/bindguard/compiled/bind/local/home.arpa.zone";
	allow-query { "bindguard_clients"; localhost; };
};
EOF
cat > "$TESTROOT/var/lib/bindguard/compiled/dnsdist/upstream-forwarder.conf" <<'EOF'
-- Managed by BindGuard. Generated upstream forwarder; do not edit by hand.
bindguardUpstreamsEnabled = true
setPoolServerPolicy(firstAvailable, "bindguard_upstreams")
newServer({address="1.1.1.2:53", name="upstream-1-Imported-upstream-1", pool="bindguard_upstreams"})
EOF

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

grep -q "^ALDERPOINTDNS_SESSION_SECRET=super-secret-value-must-survive$" "$TESTROOT/etc/alderpointdns/secrets.env" || {
  echo "secrets.env env var key was not migrated (or the secret value was lost/changed)" >&2
  cat "$TESTROOT/etc/alderpointdns/secrets.env" >&2
  exit 1
}
if grep -q "bindguard" "$TESTROOT/var/lib/alderpointdns/compiled/bind/local-zones.conf" "$TESTROOT/var/lib/alderpointdns/compiled/dnsdist/upstream-forwarder.conf"; then
  echo "compiled BIND/dnsdist config still has stale bindguard tokens after migration" >&2
  cat "$TESTROOT/var/lib/alderpointdns/compiled/bind/local-zones.conf" "$TESTROOT/var/lib/alderpointdns/compiled/dnsdist/upstream-forwarder.conf" >&2
  exit 1
fi
grep -q 'pool="alderpointdns_upstreams"' "$TESTROOT/var/lib/alderpointdns/compiled/dnsdist/upstream-forwarder.conf" || {
  echo "compiled dnsdist upstream pool name was not migrated" >&2
  exit 1
}

echo "legacy install correctly migrated to Alderpoint DNS paths"

echo "== self-referential --source (new source tree == legacy install dir) survives the move =="
TESTROOT2="$(mktemp -d /tmp/alderpointdns-rename-migration-selfref-test.XXXXXX)"
mkdir -p "$TESTROOT2/opt/bindguard/app" "$TESTROOT2/opt/bindguard/scripts" "$TESTROOT2/opt/bindguard/packaging"
echo "legacy webapp placeholder" > "$TESTROOT2/opt/bindguard/app/webapp.py"
printf '#!/bin/sh\necho fake-legacy-backup\n' > "$TESTROOT2/opt/bindguard/scripts/backup.sh"
chmod +x "$TESTROOT2/opt/bindguard/scripts/backup.sh"
cp "$ROOT_DIR/packaging/alderpointdns.service" "$ROOT_DIR/packaging/alderpointdns-analytics.service" \
  "$ROOT_DIR/packaging/alderpointdns-backup.service" "$ROOT_DIR/packaging/alderpointdns-backup.timer" \
  "$ROOT_DIR/packaging/sudoers-alderpointdns" "$TESTROOT2/opt/bindguard/packaging/"

ALDERPOINTDNS_INSTALL_ROOT="$TESTROOT2" "$ROOT_DIR/scripts/upgrade.sh" \
  --source "$TESTROOT2/opt/bindguard" --skip-service-restart > "$TESTROOT2/upgrade.out" 2>&1 || {
  echo "self-referential-source legacy migration failed:" >&2
  cat "$TESTROOT2/upgrade.out" >&2
  rm -rf "$TESTROOT2"
  exit 1
}
grep -q "staged upgrade source to" "$TESTROOT2/upgrade.out" || {
  echo "upgrade.sh did not stage the source tree before moving it out from under itself" >&2
  cat "$TESTROOT2/upgrade.out" >&2
  rm -rf "$TESTROOT2"
  exit 1
}
test -f "$TESTROOT2/opt/alderpointdns/app/webapp.py" || {
  echo "self-referential-source migration lost the application source" >&2
  rm -rf "$TESTROOT2"
  exit 1
}
rm -rf "$TESTROOT2"
echo "self-referential --source case handled correctly"

echo "== replace_application() stages a self-referential source before rm -rf =="
# pre_upgrade_backup() unconditionally shells out to the real (non-sandboxed)
# scripts/backup.sh against the real filesystem, so the normal (non-legacy)
# upgrade path can't be driven end-to-end from an ALDERPOINTDNS_INSTALL_ROOT
# sandbox here. Exercise replace_application()'s staging logic directly
# instead: same realpath-based self-reference check as the legacy path
# above, applied whenever --source resolves inside the install target.
TESTROOT3="$(mktemp -d /tmp/alderpointdns-rename-migration-normal-selfref-test.XXXXXX)"
mkdir -p "$TESTROOT3/opt/alderpointdns"
tar -C "$ROOT_DIR" --exclude .git --exclude __pycache__ --exclude '*.pyc' -cf - . | tar -C "$TESTROOT3/opt/alderpointdns" -xf -
(
  SOURCE_DIR="$TESTROOT3/opt/alderpointdns"
  ROOT="$TESTROOT3"
  DRY_RUN=0
  root_path() { printf '%s%s\n' "$TESTROOT3" "$1"; }
  eval "$(sed -n '/^replace_application() {/,/^}/p' "$ROOT_DIR/scripts/upgrade.sh")"
  replace_application
)
LINES_AFTER="$(wc -l < "$TESTROOT3/opt/alderpointdns/app/webapp.py")"
if [ "${LINES_AFTER:-0}" -lt 100 ]; then
  echo "replace_application lost the application source on self-referential --source (webapp.py has $LINES_AFTER lines)" >&2
  rm -rf "$TESTROOT3"
  exit 1
fi
rm -rf "$TESTROOT3"
echo "replace_application() self-referential --source handled correctly"

echo "rename migration tests passed"
