#!/bin/sh
set -eu

# Fresh-install regression test: builds the .deb from the current source
# tree and installs it in a genuinely clean, disposable, *stock* Debian 13
# + systemd container (via podman or docker) -- no alderpointdns
# users/groups/files/database/generated config inherited from this
# development machine, unlike running the installer or postinst directly
# against the box this test happens to run on, and critically, no
# third-party APT repository, signing key, or pin of any kind. Just
# `apt-get update` against Debian's own repositories, then
# `apt-get install -y ./alderpointdns.deb`, exactly as a beta tester on an
# untouched Debian 13 VM is expected to do.
#
# Reproduces (and guards against regressing):
#   - the original first-clean-install failure: secrets.env unreadable by
#     the alderpointdns group, the analytics database unwritable by
#     alderpointdns, named denied by AppArmor, and dnsdist's incompatible
#     Lua config on Debian 13's own archive dnsdist build;
#   - the follow-up failure where the package could not even be installed
#     from stock repositories at all, because it hard-depended on
#     dnsdist (>= 2.0.0), a version only available from the PowerDNS
#     project's own (non-default) repository.
#
# Also proves two independent installs mint different dnsdist console/
# web/API credentials, that credentials survive an upgrade, and that
# DoQ/DoH3 (unavailable in Debian 13's own dnsdist build) are correctly
# left disabled and reported as unsupported rather than silently enabled
# or broken.
#
# Requires podman (or docker) and outbound network access (to pull the
# debian:trixie base image and Debian's own package repositories -- never
# repo.powerdns.com). Not part of test_acceptance.sh, which assumes an
# already-installed, already-running appliance -- this test builds and
# tears down its own isolated one.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

CONTAINER_ENGINE=""
for candidate in podman docker; do
  if command -v "$candidate" >/dev/null 2>&1; then
    CONTAINER_ENGINE="$candidate"
    break
  fi
done
[ -n "$CONTAINER_ENGINE" ] || fail "podman or docker is required to run the clean-install container test"

NAME="alderpointdns-clean-install-test-$$"
WORK="$(mktemp -d /tmp/alderpointdns-clean-install-test.XXXXXX)"
cleanup() {
  "$CONTAINER_ENGINE" rm -f "$NAME" >/dev/null 2>&1 || true
  [ -z "${IMAGE:-}" ] || "$CONTAINER_ENGINE" rmi -f "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

run() {
  "$CONTAINER_ENGINE" exec "$NAME" sh -c "$1"
}

echo "+ building test .deb"
DEB="$(/opt/alderpointdns/scripts/build-deb.sh --output-dir "$WORK")"
test -f "$DEB" || fail "test deb package was not created"

echo "+ preparing a disposable, stock Debian 13 + systemd base image"
BOOTNAME="alderpointdns-clean-install-boot-$$"
IMAGE="localhost/alderpointdns-clean-install-base-$$:latest"
cleanup_boot() { "$CONTAINER_ENGINE" rm -f "$BOOTNAME" >/dev/null 2>&1 || true; }
trap 'cleanup_boot; cleanup' EXIT
# The stock debian:trixie image has no init system at all (just a shell),
# so systemd has to be installed before a container can run it as PID 1.
# This is the *only* package-set preparation done before the package under
# test is installed -- everything alderpointdns itself needs (bind9,
# dnsdist, curl, jq, the python3-* stack, etc.) comes from its own
# Depends: and is resolved by apt from Debian's stock repositories.
"$CONTAINER_ENGINE" pull -q docker.io/library/debian:trixie >/dev/null 2>&1 || true
"$CONTAINER_ENGINE" run -d --name "$BOOTNAME" docker.io/library/debian:trixie sleep infinity >/dev/null
"$CONTAINER_ENGINE" exec "$BOOTNAME" sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus apparmor apparmor-utils sudo procps iproute2' \
  || fail "could not install systemd into the base image"
"$CONTAINER_ENGINE" commit -q "$BOOTNAME" "$IMAGE" >/dev/null
cleanup_boot

echo "+ starting the disposable stock Debian 13 + systemd container ($NAME)"
"$CONTAINER_ENGINE" run -d --name "$NAME" --systemd=always \
  --cap-add=SYS_ADMIN --cap-add=MAC_ADMIN \
  --security-opt apparmor=unconfined \
  -v /sys/kernel/security:/sys/kernel/security:rw \
  -e container=podman \
  "$IMAGE" /sbin/init >/dev/null

# Give systemd a moment to come up as PID 1 before using it.
i=0
while [ "$i" -lt 30 ]; do
  if run "systemctl is-system-running" 2>/dev/null | grep -Eq 'running|degraded'; then
    break
  fi
  i=$((i + 1))
  sleep 1
done

echo "+ confirming no third-party APT repository is configured (stock Debian 13 only)"
if run "grep -rl 'repo.powerdns.com' /etc/apt 2>/dev/null" | grep -q .; then
  fail "a repo.powerdns.com APT source is present before the package under test was even installed -- this test must exercise the stock-repository install path"
fi

echo "+ apt-get update against Debian's own repositories only"
run "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq" || fail "apt-get update failed against stock Debian 13 repositories"

"$CONTAINER_ENGINE" cp "$DEB" "$NAME:/tmp/alderpointdns.deb"

install_and_check() {
  label="$1"
  echo "+ installing the package with apt-get (dependency resolution against stock repos only) ($label)"
  install_log="$WORK/apt-install.$label.log"
  if ! run "export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq /tmp/alderpointdns.deb" >"$install_log" 2>&1; then
    cat "$install_log" >&2
    run "journalctl -u named -u dnsdist -u alderpointdns -u alderpointdns-analytics -n 60 --no-pager" >&2 || true
    fail "$label: apt-get install -y ./alderpointdns.deb did not succeed on a clean, stock Debian 13 system -- dependency resolution must succeed with no third-party repository configured"
  fi
  if grep -qi 'unable to locate\|unmet dependencies\|Depends:.*but.*not installable\|but none of the choices are installable' "$install_log"; then
    cat "$install_log" >&2
    fail "$label: apt reported an unsatisfiable/missing dependency during install"
  fi
  run "dpkg -s alderpointdns" | grep -q '^Status: install ok installed' || fail "$label: alderpointdns is not reported as installed after apt-get install"

  echo "+ confirming the installed dnsdist actually came from Debian's own archive, not a third-party repo ($label)"
  dnsdist_policy="$(run "apt-cache policy dnsdist")"
  echo "$dnsdist_policy" | grep -qi 'repo.powerdns.com' && \
    fail "$label: dnsdist was resolved from repo.powerdns.com, not Debian's own archive -- this test must prove the stock-repository path works on its own"
  dnsdist_version="$(run "dnsdist --version")"
  echo "$dnsdist_version" > "$WORK/dnsdist-version.$label.txt"

  echo "+ verifying all four core services are active with no restarts ($label)"
  for svc in named dnsdist alderpointdns alderpointdns-analytics; do
    state="$(run "systemctl is-active $svc" || true)"
    [ "$state" = "active" ] || {
      run "journalctl -u $svc -n 60 --no-pager" >&2 || true
      fail "$label: $svc is not active after install (state: $state)"
    }
  done

  echo "+ verifying secrets.env / dnsdist-api.key / dnsdist-web.creds ownership and mode ($label)"
  for f in secrets.env dnsdist-api.key dnsdist-web.creds; do
    perms="$(run "stat -c '%U:%G %a' /etc/alderpointdns/$f")"
    case "$perms" in
      "root:alderpointdns 640") ;;
      *) fail "$label: /etc/alderpointdns/$f has unexpected ownership/mode: $perms (want root:alderpointdns 640)" ;;
    esac
  done
  run "runuser -u alderpointdns -- cat /etc/alderpointdns/secrets.env" >/dev/null || \
    fail "$label: the alderpointdns service account cannot read secrets.env"

  echo "+ verifying the unprivileged alderpointdns web process can read its own TLS certificate ($label)"
  certs_dir_perms="$(run "stat -c '%U:%G %a' /etc/alderpointdns/certs")"
  case "$certs_dir_perms" in
    "root:_dnsdist 751") ;;
    *) fail "$label: /etc/alderpointdns/certs has unexpected ownership/mode: $certs_dir_perms (want root:_dnsdist 751 -- traversable by the unprivileged alderpointdns account, not just root/_dnsdist)" ;;
  esac
  run "runuser -u alderpointdns -- test -r /etc/alderpointdns/certs/alderpointdns-lab.crt" || \
    fail "$label: the alderpointdns service account cannot stat/read its own TLS certificate at /etc/alderpointdns/certs/alderpointdns-lab.crt (the Encryption Settings page and dashboard health card both need this)"
  run "runuser -u alderpointdns -- test -r /etc/alderpointdns/certs/alderpointdns-lab.key" && \
    fail "$label: the alderpointdns service account can read the TLS private key directly -- it must only be readable by root/_dnsdist"

  echo "+ verifying the analytics database is writable by alderpointdns ($label)"
  owner="$(run "stat -c '%U:%G' /var/lib/alderpointdns/alderpointdns.db")"
  [ "$owner" = "alderpointdns:alderpointdns" ] || \
    fail "$label: /var/lib/alderpointdns/alderpointdns.db is owned $owner, not alderpointdns:alderpointdns"
  run "runuser -u alderpointdns -- python3 -c \"import sqlite3; c = sqlite3.connect('/var/lib/alderpointdns/alderpointdns.db'); c.execute('CREATE TABLE IF NOT EXISTS alderpointdns_clean_install_probe (x int)'); c.commit()\"" \
    || fail "$label: the alderpointdns service account cannot write the analytics database"

  echo "+ verifying the generated BIND/dnsdist config stays root-owned ($label)"
  rpz_owner="$(run "stat -c '%U' /var/lib/alderpointdns/compiled/bind/alderpointdns.rpz")"
  [ "$rpz_owner" = "root" ] || \
    fail "$label: /var/lib/alderpointdns/compiled/bind/alderpointdns.rpz is owned by $rpz_owner, not root -- fixing the database ownership must not hand the alderpointdns account direct write access to live BIND config outside the sudo-gated deploy path"

  echo "+ verifying named's AppArmor local override was installed and applied ($label)"
  run "grep -q 'compiled/bind' /etc/apparmor.d/local/usr.sbin.named" || \
    fail "$label: the AppArmor local override for named was not installed"
  run "cat /var/lib/alderpointdns/compiled/bind/local-zones.conf >/dev/null" || \
    fail "$label: the generated BIND config is missing"

  echo "+ verifying named actually resolves through the RPZ/BIND backend ($label)"
  run "dig @127.0.0.1 -p 5353 cloudflare.com A +time=3 +tries=1 +short | grep -q ." || \
    fail "$label: BIND backend did not resolve cloudflare.com"
  run "dig @127.0.0.1 -p 53 cloudflare.com A +time=3 +tries=1 +short | grep -q ." || \
    fail "$label: dnsdist frontend did not resolve cloudflare.com"

  echo "+ verifying dnsdist has no plaintext-credential warnings and no unresolved placeholders ($label)"
  if run "journalctl -u dnsdist --no-pager" | grep -qi 'plain-text'; then
    fail "$label: dnsdist logged a plain-text password/API key warning"
  fi
  run "grep -q PLACEHOLDER /etc/dnsdist/dnsdist.conf" && fail "$label: dnsdist.conf still has an unresolved secret placeholder"
  run "dnsdist --check-config -C /etc/dnsdist/dnsdist.conf" || fail "$label: installed dnsdist.conf fails validation"

  echo "+ verifying the web app can authenticate to dnsdist using its own credential files ($label)"
  code="$(run "curl -s -o /dev/null -w '%{http_code}' --user \"\$(cat /etc/alderpointdns/dnsdist-web.creds)\" -H \"x-api-key: \$(cat /etc/alderpointdns/dnsdist-api.key)\" http://127.0.0.1:8083/jsonstat?command=stats")"
  [ "$code" = "200" ] || fail "$label: dnsdist stats API rejected the web app's own credentials (HTTP $code)"

  echo "+ verifying the alderpointdns web setup endpoint responds ($label)"
  web_code="$(run "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/setup")"
  [ "$web_code" = "200" ] || fail "$label: /setup did not return HTTP 200 (got $web_code)"

  echo "+ verifying DoQ/DoH3 are disabled by default and reported as unsupported by this dnsdist build ($label)"
  doq_env="$(run "systemctl show dnsdist -p Environment" | tr ' ' '\n' | grep '^ALDERPOINTDNS_DNS_DOQ=' || true)"
  doh3_env="$(run "systemctl show dnsdist -p Environment" | tr ' ' '\n' | grep '^ALDERPOINTDNS_DNS_DOH3=' || true)"
  case "$doq_env" in
    *=0) ;;
    *) fail "$label: ALDERPOINTDNS_DNS_DOQ is not disabled by default on a stock Debian 13 install ($doq_env)" ;;
  esac
  case "$doh3_env" in
    *=0) ;;
    *) fail "$label: ALDERPOINTDNS_DNS_DOH3 is not disabled by default on a stock Debian 13 install ($doh3_env)" ;;
  esac
  run "ss -lnu | grep -q ':853 '" && fail "$label: something is listening on :853/udp (DoQ) despite it being unsupported/disabled on this dnsdist build" || true
  caps_json="$(run "cd /opt/alderpointdns && python3 -c \"from app import encryption; import json; print(json.dumps(encryption.dnsdist_capabilities()))\"")"
  echo "$caps_json" | grep -q '\"doq\": false' || fail "$label: dnsdist_capabilities() did not report DoQ as unsupported on stock Debian 13's dnsdist (got: $caps_json)"
  echo "$caps_json" | grep -q '\"doh3\": false' || fail "$label: dnsdist_capabilities() did not report DoH3 as unsupported on stock Debian 13's dnsdist (got: $caps_json)"
  echo "$caps_json" | grep -q '\"doh\": true' || fail "$label: dnsdist_capabilities() did not report DoH as supported on stock Debian 13's dnsdist (got: $caps_json)"
  echo "$caps_json" | grep -q '\"dot\": true' || fail "$label: dnsdist_capabilities() did not report DoT as supported on stock Debian 13's dnsdist (got: $caps_json)"

  echo "+ verifying the Encryption Settings page shows DoQ/DoH3 as unsupported, not enabled or broken ($label)"
  setup_admin_and_login "$label"
  encryption_html="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/encryption")"
  echo "$encryption_html" | grep -q 'name="doq_enabled"[^>]*disabled' || \
    fail "$label: the Encryption Settings page does not render the DoQ checkbox as disabled on stock Debian 13's dnsdist"
  echo "$encryption_html" | grep -q 'name="doh3_enabled"[^>]*disabled' || \
    fail "$label: the Encryption Settings page does not render the DoH3 checkbox as disabled on stock Debian 13's dnsdist"
  echo "$encryption_html" | grep -qi 'Unsupported by installed dnsdist' || \
    fail "$label: the Encryption Settings page does not explain that DoQ/DoH3 are unsupported by the installed dnsdist build"

  echo "+ verifying reboot-equivalent restart behavior: stopping and restarting all four core services ($label)"
  run "systemctl stop named dnsdist alderpointdns-analytics alderpointdns"
  run "systemctl reset-failed" || true
  run "systemctl start named dnsdist alderpointdns-analytics alderpointdns" || fail "$label: core services did not start cleanly after a full stop (reboot-equivalent)"
  for svc in named dnsdist alderpointdns alderpointdns-analytics; do
    j=0
    state="down"
    while [ "$j" -lt 15 ]; do
      state="$(run "systemctl is-active $svc" || true)"
      [ "$state" = "active" ] && break
      j=$((j + 1))
      sleep 1
    done
    [ "$state" = "active" ] || {
      run "journalctl -u $svc -n 60 --no-pager" >&2 || true
      fail "$label: $svc did not return to active after a reboot-equivalent restart (state: $state)"
    }
  done
  run "dig @127.0.0.1 -p 53 cloudflare.com A +time=3 +tries=1 +short | grep -q ." || \
    fail "$label: DNS resolution did not work after a reboot-equivalent restart"

  run "systemctl show named dnsdist alderpointdns alderpointdns-analytics -p NRestarts" > "$WORK/nrestarts.$label.txt"
  if grep '^NRestarts=' "$WORK/nrestarts.$label.txt" | grep -qv '^NRestarts=0$'; then
    fail "$label: at least one core service restarted unexpectedly during install (restart storm): $(tr '\n' ' ' < "$WORK/nrestarts.$label.txt")"
  fi
}

setup_admin_and_login() {
  label="$1"
  COOKIE_JAR="/tmp/alderpointdns-cookies-$label.txt"
  # Neither /setup (no session/CSRF token exists yet -- there is no admin)
  # nor /login (authenticates the session, doesn't yet have one) requires a
  # CSRF token in app/webapp.py; both are plain form posts.
  run "curl -s -c $COOKIE_JAR -o /dev/null -d 'username=admin' -d 'password=ClnInst4llTest!2026' http://127.0.0.1:3000/setup" || true
  run "curl -s -c $COOKIE_JAR -b $COOKIE_JAR -o /dev/null -d 'username=admin' -d 'password=ClnInst4llTest!2026' http://127.0.0.1:3000/login" || true
}

install_and_check "install-A"
run "md5sum /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds" > "$WORK/creds-A.txt"
run "grep -E 'password=|apiKey=|setKey\(' /etc/dnsdist/dnsdist.conf" >> "$WORK/creds-A.txt"

echo "+ purging and reinstalling to prove two independent installs mint different credentials"
run "apt-get purge -y -qq alderpointdns >/dev/null 2>&1; systemctl reset-failed >/dev/null 2>&1; true"
test -z "$(run "ls /etc/alderpointdns 2>/dev/null" || true)" || fail "purge did not remove /etc/alderpointdns"

install_and_check "install-B"
run "md5sum /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds" > "$WORK/creds-B.txt"
run "grep -E 'password=|apiKey=|setKey\(' /etc/dnsdist/dnsdist.conf" >> "$WORK/creds-B.txt"

if diff -q "$WORK/creds-A.txt" "$WORK/creds-B.txt" >/dev/null; then
  fail "two independent installs produced identical dnsdist console/web/API credentials (secrets.env, dnsdist-api.key, dnsdist-web.creds, and dnsdist.conf's setKey/password/apiKey must all differ)"
fi
# Every individual line must differ too, not just the file as a whole --
# a bug that regenerated the plaintext files but left a stale dnsdist.conf
# (or vice versa) would still show *some* difference in the diff above.
paste "$WORK/creds-A.txt" "$WORK/creds-B.txt" | while IFS="$(printf '\t')" read -r line_a line_b; do
  [ "$line_a" != "$line_b" ] || fail "a credential line was identical across two independent installs: $line_a"
done

echo "+ verifying credentials are preserved across an upgrade (no purge)"
run "md5sum /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds" > "$WORK/creds-B-before-upgrade.txt"
run "export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq --reinstall /tmp/alderpointdns.deb" || fail "reinstalling over an existing configuration (simulated upgrade) failed"
run "md5sum /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds" > "$WORK/creds-B-after-upgrade.txt"
diff -q "$WORK/creds-B-before-upgrade.txt" "$WORK/creds-B-after-upgrade.txt" >/dev/null || \
  fail "credentials changed across a reinstall/upgrade (should be preserved, not regenerated)"

echo "+ final confirmation: no repo.powerdns.com reference was ever introduced during this test"
if run "grep -rl 'repo.powerdns.com' /etc/apt 2>/dev/null" | grep -q .; then
  fail "a repo.powerdns.com APT source is present at the end of the test -- the stock-repository install path must never add one"
fi

echo "clean install container tests passed"
