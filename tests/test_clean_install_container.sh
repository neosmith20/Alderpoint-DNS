#!/bin/sh
set -eu

# Fresh-install regression test: builds the .deb from the current source
# tree and installs it in a genuinely clean, disposable Debian 13 + systemd
# container -- no alderpointdns users/groups/files/database/generated
# config inherited from this development machine, unlike running the
# installer or postinst directly against the box this test happens to run
# on. Reproduces (and guards against regressing) all four confirmed
# first-clean-install failures: secrets.env unreadable by the alderpointdns
# group, the analytics database unwritable by alderpointdns, named denied
# by AppArmor, and dnsdist's incompatible Lua config on Debian 13's own
# archive dnsdist build. Also proves two independent installs mint
# different dnsdist console/web/API credentials.
#
# Requires podman (or docker) and outbound network access (to pull the
# debian:trixie base image, install bind9/dnsdist and friends, and fetch
# the PowerDNS apt repository per docs/dnsdist.md). Not part of
# test_acceptance.sh, which assumes an already-installed, already-running
# appliance -- this test builds and tears down its own isolated one.

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

echo "+ preparing a disposable Debian 13 + systemd base image"
BOOTNAME="alderpointdns-clean-install-boot-$$"
IMAGE="localhost/alderpointdns-clean-install-base-$$:latest"
cleanup_boot() { "$CONTAINER_ENGINE" rm -f "$BOOTNAME" >/dev/null 2>&1 || true; }
trap 'cleanup_boot; cleanup' EXIT
# The stock debian:trixie image has no init system at all (just a shell),
# so systemd has to be installed before a container can run it as PID 1.
"$CONTAINER_ENGINE" pull -q docker.io/library/debian:trixie >/dev/null 2>&1 || true
"$CONTAINER_ENGINE" run -d --name "$BOOTNAME" docker.io/library/debian:trixie sleep infinity >/dev/null
"$CONTAINER_ENGINE" exec "$BOOTNAME" sh -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus apparmor apparmor-utils sudo procps' \
  || fail "could not install systemd into the base image"
"$CONTAINER_ENGINE" commit -q "$BOOTNAME" "$IMAGE" >/dev/null
cleanup_boot

echo "+ starting the disposable Debian 13 + systemd container ($NAME)"
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

echo "+ installing base dependencies and the PowerDNS dnsdist repository (docs/dnsdist.md)"
run 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq apparmor apparmor-utils curl ca-certificates gnupg' \
  || fail "base dependency install failed"
run 'install -d -m 0755 /etc/apt/keyrings && curl -fsSL https://repo.powerdns.com/FD380FBB-pub.asc -o /etc/apt/keyrings/dnsdist-21-pub.asc' \
  || fail "could not fetch the PowerDNS dnsdist apt signing key"
run 'printf "deb [signed-by=/etc/apt/keyrings/dnsdist-21-pub.asc] http://repo.powerdns.com/debian trixie-dnsdist-21 main\n" > /etc/apt/sources.list.d/pdns.list'
run 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq bind9 bind9-dnsutils curl dnsutils dnsdist jq knot-dnsutils openssl python3-aioquic python3-argon2 python3-dnspython python3-fastapi python3-httpx python3-itsdangerous python3-jinja2 python3-multipart python3-openpyxl python3-yaml sudo uvicorn' \
  || fail "dependency install failed"
run "dnsdist --version | grep -q 'dns-over-quic'" || fail "test setup did not get the PowerDNS-repo dnsdist build with DoQ support"

"$CONTAINER_ENGINE" cp "$DEB" "$NAME:/tmp/alderpointdns.deb"

install_and_check() {
  label="$1"
  echo "+ installing the package ($label)"
  if ! run "dpkg -i /tmp/alderpointdns.deb"; then
    run "journalctl -u named -u dnsdist -u alderpointdns -u alderpointdns-analytics -n 60 --no-pager" >&2 || true
    fail "$label: dpkg -i did not succeed on a clean install"
  fi

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

  run "systemctl show named dnsdist alderpointdns alderpointdns-analytics -p NRestarts" > "$WORK/nrestarts.$label.txt"
  if grep '^NRestarts=' "$WORK/nrestarts.$label.txt" | grep -qv '^NRestarts=0$'; then
    fail "$label: at least one core service restarted during install (restart storm): $(tr '\n' ' ' < "$WORK/nrestarts.$label.txt")"
  fi
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
run "dpkg -i /tmp/alderpointdns.deb" || fail "reinstalling over an existing configuration (simulated upgrade) failed"
run "md5sum /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds" > "$WORK/creds-B-after-upgrade.txt"
diff -q "$WORK/creds-B-before-upgrade.txt" "$WORK/creds-B-after-upgrade.txt" >/dev/null || \
  fail "credentials changed across a reinstall/upgrade (should be preserved, not regenerated)"

echo "clean install container tests passed"
