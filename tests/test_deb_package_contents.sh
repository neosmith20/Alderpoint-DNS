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
dpkg-deb --field "$DEB" Depends | grep -q 'dnsdist (>= 2.0.0)' || \
  fail "control Depends does not require a dnsdist build new enough to have the Lua API packaging/dnsdist.conf uses (see docs/dnsdist.md's PowerDNS repository requirement) -- installing against Debian's own older archive dnsdist must fail cleanly at dependency resolution, not silently succeed and crash-loop"

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

echo "deb package content tests passed"
