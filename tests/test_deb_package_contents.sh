#!/bin/sh
set -eu

# Regression test for a class of defects found on the first clean Debian 13
# install: correct maintainer-script content and structural package fixes
# can all be checked statically, without root or a live system, by
# inspecting the actual built .deb -- so this runs everywhere
# test_install_upgrade_diagnostics.sh's live-system checks can't.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

ROOT="$(mktemp -d /tmp/alderpointdns-deb-contents-test.XXXXXX)"
trap 'rm -rf "$ROOT"' EXIT

DEB="$(/opt/alderpointdns/scripts/build-deb.sh --output-dir "$ROOT")"
test -f "$DEB" || fail "test deb package was not created"

dpkg-deb --info "$DEB" | grep -q "Package: alderpointdns" || fail "deb metadata is invalid"
DEPENDS_FIELD="$(dpkg-deb --field "$DEB" Depends)"
echo "$DEPENDS_FIELD" | grep -q 'dnsdist (>= 1.9.0)' || \
  fail "control Depends does not require dnsdist (>= 1.9.0), the lowest version bound Debian 13's own archive dnsdist (1.9.x) satisfies with no third-party repository -- a stock 'apt-get install -y ./alderpointdns.deb' must resolve dependencies successfully with no PowerDNS repository configured"
echo "$DEPENDS_FIELD" | grep -q 'dnsdist (>= 2\.' && \
  fail "control Depends requires dnsdist >= 2.x again, which is only available from the PowerDNS project's own repository -- this regresses the stock Debian 13 install failure ('none of the choices are installable')"

mkdir -p "$ROOT/ctl" "$ROOT/data"
dpkg-deb -e "$DEB" "$ROOT/ctl"
dpkg-deb -x "$DEB" "$ROOT/data"

POSTINST="$ROOT/ctl/postinst"
test -f "$POSTINST" || fail "postinst missing from built package"
sh -n "$POSTINST" || fail "postinst has a shell syntax error"

# --- secrets.env / dnsdist-api.key / dnsdist-web.creds ownership+mode ---
# The confirmed defect: these were left 0600 root:alderpointdns (group has
# no permission bit at all), so the alderpointdns service account -- which
# needs to read them -- got PermissionError/OperationalError at runtime.
grep -q 'chmod 0640 /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds' "$POSTINST" || \
  fail "postinst does not chmod 0640 secrets.env/dnsdist-api.key/dnsdist-web.creds (group-readable by alderpointdns)"
grep -q 'chown root:alderpointdns /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds' "$POSTINST" || \
  fail "postinst does not chown secrets.env/dnsdist-api.key/dnsdist-web.creds to root:alderpointdns"
grep -q 'dnsdist-api.key' "$POSTINST" || fail "postinst never generates /etc/alderpointdns/dnsdist-api.key"
grep -q 'dnsdist-web.creds' "$POSTINST" || fail "postinst never generates /etc/alderpointdns/dnsdist-web.creds"

# --- database ownership ---
# The confirmed defect: the database was left root:root (created by
# init-db running as root in postinst, never chowned afterward), so the
# alderpointdns-analytics service (running as alderpointdns) got
# "attempt to write a readonly database". Fixed narrowly (the database
# file itself, not a blanket recursive chown of /var/lib/alderpointdns):
# compiled/bind and compiled/dnsdist must stay root-owned -- they're
# deliberately only ever rewritten through the audited, sudo-gated deploy
# path, and a recursive chown would hand the alderpointdns account direct
# write access to live BIND/dnsdist config, bypassing that.
grep -q 'chown alderpointdns:alderpointdns "\$alderpointdns_db_file"' "$POSTINST" || \
  fail "postinst does not chown the alderpointdns.db file(s) to alderpointdns:alderpointdns after generating the database"
if grep -Eq 'chown -R alderpointdns:alderpointdns /var/lib/alderpointdns\b' "$POSTINST"; then
  fail "postinst recursively chowns all of /var/lib/alderpointdns to alderpointdns -- this also reassigns the root-owned, world-readable compiled BIND/dnsdist config that must stay root-only-writable (only the sudo-gated deploy path may regenerate it)"
fi
# The database chown must run *after* the database exists, not before --
# otherwise it has nothing to fix.
awk '/analytics\.py init-db/{initdb=NR} /chown alderpointdns:alderpointdns "\$alderpointdns_db_file"/{chown=NR} END{ if (!initdb || !chown || chown < initdb) exit 1 }' "$POSTINST" || \
  fail "postinst chowns the database before (or without) initializing it -- the chown must come after init-db"
# named's own log subdirectory (bind:bind, set at directory-creation time
# near the top of postinst) must never be swept into a later recursive
# alderpointdns chown, or named.log/named.stats written before that chown
# ran would end up owned by alderpointdns and named could no longer open
# them (a real regression reproduced once already while fixing this).
if grep -Eq 'chown -R alderpointdns:alderpointdns.*/var/log/alderpointdns\b' "$POSTINST"; then
  fail "postinst recursively chowns /var/log/alderpointdns (including named's bind:bind log subdirectory) to alderpointdns"
fi

# --- AppArmor local override ---
# The confirmed defect: packaging/apparmor-named.local was never installed
# anywhere, so named (confined by the bind9 package's own AppArmor
# profile, independent of Unix permissions) was denied read access to the
# generated BIND config under /var/lib/alderpointdns/compiled/bind/.
test -f "$ROOT/data/opt/alderpointdns/packaging/apparmor-named.local" || \
  fail "packaging/apparmor-named.local is missing from the built package's data (postinst installs it from /opt/alderpointdns/packaging at runtime)"
grep -q '/etc/apparmor.d/local/usr.sbin.named' "$POSTINST" || \
  fail "postinst does not install an AppArmor local override for named"
grep -q 'apparmor_parser -r' "$POSTINST" || \
  fail "postinst does not reload the named AppArmor profile after installing the local override"

# --- dnsdist compatibility ---
DNSDIST_CONF="$ROOT/data/opt/alderpointdns/packaging/dnsdist.conf"
test -f "$DNSDIST_CONF" || fail "packaging/dnsdist.conf missing from built package"
# The confirmed defect: newRemoteLogger was called with a 5th
# (connectionCount) positional argument dnsdist 1.9.x (Debian 13's own
# archive package, pulled in whenever the PowerDNS repository documented
# in docs/dnsdist.md isn't configured) rejects outright with a fatal Lua
# error, crash-looping dnsdist forever.
grep -q 'newRemoteLogger("127.0.0.1:5301", 1, 10000, 1)' "$DNSDIST_CONF" || \
  fail "dnsdist.conf's newRemoteLogger call still passes a 5th (connectionCount) argument incompatible with Debian 13's own archive dnsdist package"
if grep -q 'newRemoteLogger("127.0.0.1:5301", 1, 10000, 1, 1)' "$DNSDIST_CONF"; then
  fail "dnsdist.conf regressed back to the incompatible 5-argument newRemoteLogger call"
fi
# Capability-aware generation: DoH3/DoQ/DNSCrypt must degrade gracefully
# (not crash dnsdist) on a build that lacks them.
grep -q 'alderpointdnsSafeCapabilityCall' "$DNSDIST_CONF" || \
  fail "dnsdist.conf does not guard DoH3/DoQ/DNSCrypt listener setup against dnsdist builds that lack those capabilities"
for fn in addDOH3Local addDOQLocal addDNSCryptBind; do
  grep -q "alderpointdnsSafeCapabilityCall(\"[^\"]*\", $fn" "$DNSDIST_CONF" || \
    fail "dnsdist.conf does not route $fn through the capability-safe wrapper"
done
grep -q 'RemoteLogResponseAction' "$DNSDIST_CONF" || fail "dnsdist.conf no longer wires up the analytics RemoteLogResponseAction"
grep -A3 'pcall(' "$DNSDIST_CONF" | grep -q 'RemoteLogResponseAction' || \
  fail "dnsdist.conf's RemoteLogResponseAction call (also version-incompatible on Debian 13's archive dnsdist -- 'requires at most 5 parameter(s)') is not wrapped in a version-aware pcall fallback"

# The follow-up defect: DoQ/DoH3 need a dnsdist build with QUIC support,
# which Debian 13's own archive dnsdist package (the default, no
# third-party repository install path) does not have. They must ship
# disabled by default so a fresh install never attempts to start a
# listener the installed binary can't provide.
DNSDIST_ENV_OVERRIDE="$ROOT/data/opt/alderpointdns/packaging/dnsdist.service.d/alderpointdns.conf"
test -f "$DNSDIST_ENV_OVERRIDE" || fail "packaging/dnsdist.service.d/alderpointdns.conf missing from built package"
grep -q '^Environment=ALDERPOINTDNS_DNS_DOQ=0$' "$DNSDIST_ENV_OVERRIDE" || \
  fail "the dnsdist.service drop-in does not ship ALDERPOINTDNS_DNS_DOQ=0 by default -- DoQ is unsupported by Debian 13's own archive dnsdist and must not be enabled out of the box"
grep -q '^Environment=ALDERPOINTDNS_DNS_DOH3=0$' "$DNSDIST_ENV_OVERRIDE" || \
  fail "the dnsdist.service drop-in does not ship ALDERPOINTDNS_DNS_DOH3=0 by default -- DoH3 is unsupported by Debian 13's own archive dnsdist and must not be enabled out of the box"

# app/encryption.py must detect dnsdist's actual capabilities at runtime
# (dnsdist --version's feature list) and use that both to keep unsupported
# protocols out of a deployment and to show them as unsupported -- not
# enabled, broken, or silently active -- in the Encryption Settings page.
ENCRYPTION_PY="$ROOT/data/opt/alderpointdns/app/encryption.py"
test -f "$ENCRYPTION_PY" || fail "app/encryption.py missing from built package"
grep -q 'def dnsdist_capabilities' "$ENCRYPTION_PY" || \
  fail "app/encryption.py does not define dnsdist_capabilities() to detect DoH/DoT/DoQ/DoH3/DNSCrypt support from the installed dnsdist build"
grep -q 'dns-over-quic' "$ENCRYPTION_PY" || fail "app/encryption.py does not check dnsdist --version for dns-over-quic support"
grep -q 'dns-over-http3' "$ENCRYPTION_PY" || fail "app/encryption.py does not check dnsdist --version for dns-over-http3 support"
grep -q 'doh3_enabled": "0"' "$ENCRYPTION_PY" || fail "app/encryption.py's DEFAULTS enables doh3_enabled by default; must default to 0 since it's unsupported on Debian 13's own archive dnsdist"
grep -q 'doq_enabled": "0"' "$ENCRYPTION_PY" || fail "app/encryption.py's DEFAULTS enables doq_enabled by default; must default to 0 since it's unsupported on Debian 13's own archive dnsdist"
ENCRYPTION_HTML="$ROOT/data/opt/alderpointdns/web/templates/encryption.html"
test -f "$ENCRYPTION_HTML" || fail "web/templates/encryption.html missing from built package"
grep -q 'capabilities.doq' "$ENCRYPTION_HTML" || \
  fail "encryption.html does not reflect DoQ capability detection -- unsupported protocols must be shown as unsupported, not enabled or broken"
grep -q 'capabilities.doh3' "$ENCRYPTION_HTML" || \
  fail "encryption.html does not reflect DoH3 capability detection"

# The confirmed warning: dnsdist's web password/API key must not be
# embedded in dnsdist.conf as plaintext; postinst must precompute a
# dnsdist hashPassword() hash and substitute that instead, without ever
# leaving the plaintext-triggering literal placeholder unresolved.
grep -q 'hashPassword' "$POSTINST" || fail "postinst does not hash the dnsdist web password/API key with dnsdist's own hashPassword() before writing dnsdist.conf"
grep -q "ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER\|ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER\|ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER" "$DNSDIST_CONF" || \
  fail "dnsdist.conf template lost its placeholder tokens (postinst substitutes these at install time; the shipped template must still contain them)"
grep -q "ALDERPOINTDNS_.*_PLACEHOLDER" "$POSTINST" || fail "postinst does not reference the dnsdist.conf secret placeholders at all"
grep -q 'grep -q .ALDERPOINTDNS_.\*_PLACEHOLDER. /etc/dnsdist/dnsdist.conf' "$POSTINST" || \
  fail "postinst does not verify all placeholders were actually resolved before continuing (would otherwise ship a config with a literal hardcoded default credential)"

# The first-install markers for named.conf.local/dnsdist.conf must live
# under /etc/alderpointdns (removed by `apt purge`), not under /etc/bind
# or /etc/dnsdist (owned by other packages, survive purge) -- otherwise a
# purge + reinstall silently reuses a stale dnsdist.conf whose hashed
# credentials no longer match the freshly-regenerated plaintext files,
# permanently breaking the web app's ability to authenticate to dnsdist.
grep -q '/etc/alderpointdns/\.dnsdist-conf-installed' "$POSTINST" || \
  fail "dnsdist.conf's first-install marker is not scoped under /etc/alderpointdns (won't be reset by 'apt purge', so a purge+reinstall would keep stale hashed credentials)"
grep -q '/etc/alderpointdns/\.named-conf-installed' "$POSTINST" || \
  fail "named.conf's first-install marker is not scoped under /etc/alderpointdns"
if grep -q '/etc/dnsdist/dnsdist\.conf\.alderpointdns-installed\|/etc/bind/named\.conf\.options\.alderpointdns-installed' "$POSTINST"; then
  fail "postinst still uses a first-install marker outside /etc/alderpointdns that 'apt purge' won't remove"
fi

# --- restart-storm prevention ---
grep -q 'StartLimitIntervalSec' /opt/alderpointdns/packaging/alderpointdns.service || \
  fail "alderpointdns.service has no StartLimitIntervalSec/Burst -- a crash-looping unit would restart forever"
grep -q 'StartLimitBurst' /opt/alderpointdns/packaging/alderpointdns.service || fail "alderpointdns.service has no StartLimitBurst"
grep -q 'StartLimitIntervalSec' /opt/alderpointdns/packaging/alderpointdns-analytics.service || \
  fail "alderpointdns-analytics.service has no StartLimitIntervalSec/Burst"
grep -q 'StartLimitIntervalSec' /opt/alderpointdns/packaging/dnsdist.service.d/alderpointdns.conf || \
  fail "the dnsdist.service drop-in does not override the upstream unit's StartLimitInterval=0 (unlimited restarts)"

# --- fail clearly instead of reporting success with broken services ---
# The confirmed defect: every mandatory postinst step (database init,
# config deploy, service restart/enable) was suffixed with `|| true`,
# so a completely broken install still reported dpkg/apt success.
grep -q 'PYTHONPATH=/opt/alderpointdns /opt/alderpointdns/app/alderpointdns_compiler.py deploy --no-download$' "$POSTINST" || \
  fail "postinst still swallows failures from alderpointdns_compiler.py deploy with || true (or a trailing redirect) instead of failing the install"
grep -q '^    systemctl restart named dnsdist$' "$POSTINST" || \
  fail "postinst still swallows failures from 'systemctl restart named dnsdist' with || true instead of failing the install"
grep -q '^    systemctl enable --now alderpointdns alderpointdns-analytics$' "$POSTINST" || \
  fail "postinst still swallows failures from enabling the web/analytics services with || true instead of failing the install"
grep -q 'alderpointdns_wait_active' "$POSTINST" || \
  fail "postinst does not verify named/dnsdist/alderpointdns/alderpointdns-analytics actually reached the active state before reporting success"
for svc in named dnsdist alderpointdns alderpointdns-analytics; do
  grep -q "alderpointdns_wait_active \"$svc\"\|for alderpointdns_svc in named dnsdist alderpointdns alderpointdns-analytics" "$POSTINST" || \
    fail "postinst's final active-service gate does not cover $svc"
done

# --- root-only local admin recovery CLI and notification checker timer ---
# Both were added alongside the local-only test build script
# (scripts/build-deb.sh), which copies packaged files individually rather
# than reading packaging/debian/install -- so it's easy to add a new
# packaging file without ever actually wiring it into a built package.
# This is the check that would have caught that.
test -f "$ROOT/data/usr/sbin/alderpointdns" || fail "usr/sbin/alderpointdns (root-only admin recovery CLI) missing from built package"
test -x "$ROOT/data/usr/sbin/alderpointdns" || fail "usr/sbin/alderpointdns is not executable"
test -f "$ROOT/data/lib/systemd/system/alderpointdns-notify.service" || fail "alderpointdns-notify.service missing from built package"
test -f "$ROOT/data/lib/systemd/system/alderpointdns-notify.timer" || fail "alderpointdns-notify.timer missing from built package"
grep -q '^User=alderpointdns$' "$ROOT/data/lib/systemd/system/alderpointdns-notify.service" || \
  fail "alderpointdns-notify.service does not run as the unprivileged alderpointdns account"
grep -q 'systemctl enable --now alderpointdns-notify.timer' "$POSTINST" || \
  fail "postinst does not enable alderpointdns-notify.timer"

# --- logrotate config for the CLI's dedicated error-traceback log ---
# The confirmed defect: alderpointdns_compiler.py's CLI dispatch logs full
# Python tracebacks (which can embed exception arguments -- paths, domain
# names, DB rows) to /var/log/alderpointdns/compiler-errors.log, but
# nothing rotated or bounded that file's growth, and build-deb.sh copies
# packaged files individually rather than reading packaging/debian/install
# -- so it's easy to add a new packaging file without ever wiring it into
# a built package. This is the check that would have caught that.
test -f "$ROOT/data/etc/logrotate.d/alderpointdns" || fail "etc/logrotate.d/alderpointdns missing from built package"
grep -q '/var/log/alderpointdns/compiler-errors.log' "$ROOT/data/etc/logrotate.d/alderpointdns" || \
  fail "logrotate config does not cover /var/log/alderpointdns/compiler-errors.log"
grep -q 'create 0600 root root' "$ROOT/data/etc/logrotate.d/alderpointdns" || \
  fail "logrotate config does not recreate the CLI error log at a root-only 0600 -- a rotation cycle must never widen it to group/world-readable"

echo "deb package content tests passed"
