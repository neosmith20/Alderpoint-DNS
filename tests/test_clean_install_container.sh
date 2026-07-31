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
"$CONTAINER_ENGINE" cp /opt/alderpointdns/tests/fixtures/clean_install_adguard.yaml "$NAME:/tmp/adguard_home.yaml"
"$CONTAINER_ENGINE" cp /opt/alderpointdns/tests/fixtures/clean_install_pihole.txt "$NAME:/tmp/pihole_export.txt"

# Extracts a form's CSRF token from a rendered, authenticated HTML page --
# every mutating route in app/webapp.py checks it against the session
# cookie (see check_csrf()), so POSTs below need a real one, not a guess.
extract_csrf() {
  printf '%s' "$1" | grep -o 'name="csrf" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)".*/\1/'
}

backup_archive_count() {
  run "ls -1 /var/lib/alderpointdns/backups/alderpointdns-backup-*.tar.gz 2>/dev/null | wc -l" | tr -d '[:space:]'
}

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

  echo "+ verifying the notification checker timer and root-only admin recovery CLI installed ($label)"
  run "systemctl is-enabled alderpointdns-notify.timer" | grep -q enabled || \
    fail "$label: alderpointdns-notify.timer is not enabled after install"
  run "systemctl is-active alderpointdns-notify.timer" | grep -q active || \
    fail "$label: alderpointdns-notify.timer is not active after install"
  run "test -x /usr/sbin/alderpointdns" || fail "$label: /usr/sbin/alderpointdns (root-only admin recovery CLI) is not installed/executable"
  run "/usr/sbin/alderpointdns admin list" | grep -q admin || fail "$label: 'alderpointdns admin list' did not show the setup-created administrator"
  run "sudo -u alderpointdns /usr/sbin/alderpointdns admin list" >/dev/null 2>&1 && \
    fail "$label: alderpointdns admin list must refuse to run as the unprivileged alderpointdns account" || true

  # Regression coverage for a real clean-VM failure: AdGuard/Pi-hole import
  # apply requires a mandatory pre-import backup (app/importer.py's
  # create_pre_import_backup(), run via `sudo alderpointdns_compiler.py
  # backup-create`), and that backup's manifest calls into
  # backup.alderpointdns_app_version(). A stock Debian 13 package install
  # has no `git` binary and /opt/alderpointdns is plain files, not a git
  # checkout -- version detection shelling out to git unconditionally
  # crashed backup creation, which in turn crashed every import apply.
  echo "+ confirming git is not installed and not required on this stock Debian 13 install ($label)"
  run "command -v git" >/dev/null 2>&1 && \
    fail "$label: git is installed in this 'stock Debian 13' test container -- it must not be, since this test exists to prove alderpointdns works without it" || true
  run "dpkg -s git" >/dev/null 2>&1 && \
    fail "$label: the git package is installed -- alderpointdns's own Depends: must never pull it in" || true

  echo "+ creating a backup through the same sudo/service-account path the web UI uses ($label)"
  backup_html="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/backup")"
  backup_csrf="$(extract_csrf "$backup_html")"
  [ -n "$backup_csrf" ] || fail "$label: could not extract a CSRF token from the /backup page"
  create_code="$(run "curl -s -o /tmp/backup-create-body.$label.html -w '%{http_code}' -b $COOKIE_JAR -c $COOKIE_JAR \
    -d csrf=$backup_csrf -d app_config=on -d sqlite_data=on -d blocklist_source_definitions=on \
    -d last_downloaded_lists=on -d custom_rules=on -d local_dns_zones=on -d client_aliases=on \
    -d dnsdist_source_config=on -d bind_source_config=on -d certificates=on \
    http://127.0.0.1:3000/backup/create")"
  if [ "$create_code" != "303" ]; then
    run "cat /tmp/backup-create-body.$label.html" >&2 || true
    fail "$label: POST /backup/create (the web UI's manual-backup button) did not succeed (HTTP $create_code) -- this is the exact clean-VM pre-import-backup failure mode"
  fi

  echo "+ confirming the backup archive and manifest are valid ($label)"
  [ "$(backup_archive_count)" -ge 1 ] || fail "$label: no backup archive found in /var/lib/alderpointdns/backups after a successful /backup/create"
  latest_backup="$(run "ls -1t /var/lib/alderpointdns/backups/alderpointdns-backup-*.tar.gz | head -1")"
  run "rm -rf /tmp/backup-verify.$label && mkdir -p /tmp/backup-verify.$label && tar -xzf $latest_backup -C /tmp/backup-verify.$label" || \
    fail "$label: backup archive $latest_backup is not a valid tar.gz"
  run "test -s /tmp/backup-verify.$label/manifest.json" || fail "$label: backup archive $latest_backup has no manifest.json"
  manifest_version="$(run "jq -r .alderpointdns_app_version /tmp/backup-verify.$label/manifest.json")"
  [ -n "$manifest_version" ] && [ "$manifest_version" != "null" ] || fail "$label: manifest.json's alderpointdns_app_version is empty/null ($label)"
  case "$manifest_version" in
    *"git."*) fail "$label: manifest reports git dev metadata ($manifest_version) despite git not being installed -- a commit id must never be fabricated" ;;
  esac
  installed_version="$(run "cat /opt/alderpointdns/VERSION" | tr -d '[:space:]')"
  [ "$manifest_version" = "$installed_version" ] || \
    fail "$label: manifest alderpointdns_app_version ($manifest_version) does not match the packaged VERSION file ($installed_version)"

  echo "+ uploading, previewing, and applying a synthetic AdGuard Home migration ($label)"
  import_html="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/import")"
  import_csrf="$(extract_csrf "$import_html")"
  [ -n "$import_csrf" ] || fail "$label: could not extract a CSRF token from the /import page"
  count_before_adguard="$(backup_archive_count)"
  adguard_headers="$(run "curl -s -D - -o /tmp/adguard-upload-body.$label.html -b $COOKIE_JAR -c $COOKIE_JAR \
    -F csrf=$import_csrf -F upload=@/tmp/adguard_home.yaml \
    http://127.0.0.1:3000/import/migration/adguard/yaml")"
  adguard_job_id="$(printf '%s' "$adguard_headers" | tr -d '\r' | sed -nE 's#.*[Ll]ocation: */import/jobs/([0-9]+)/preview.*#\1#p' | head -1)"
  if [ -z "$adguard_job_id" ]; then
    run "cat /tmp/adguard-upload-body.$label.html" >&2 || true
    fail "$label: uploading the synthetic AdGuard Home migration did not reach a preview page"
  fi
  apply_code="$(run "curl -s -o /tmp/adguard-apply-body.$label.html -w '%{http_code}' -b $COOKIE_JAR -c $COOKIE_JAR \
    -d csrf=$import_csrf http://127.0.0.1:3000/import/jobs/$adguard_job_id/apply")"
  if [ "$apply_code" != "303" ]; then
    run "cat /tmp/adguard-apply-body.$label.html" >&2 || true
    fail "$label: applying the synthetic AdGuard Home migration failed (HTTP $apply_code) -- this reproduces the pre-import backup failure"
  fi
  adguard_status="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/import/jobs/$adguard_job_id/status")"
  echo "$adguard_status" | grep -q '"status":"applied"' || \
    fail "$label: AdGuard migration job $adguard_job_id did not reach status=applied (got: $adguard_status)"
  echo "+ confirming the AdGuard import's mandatory pre-import backup actually succeeded ($label)"
  [ "$(backup_archive_count)" -gt "$count_before_adguard" ] || \
    fail "$label: applying the AdGuard migration did not create a new pre-import backup archive"

  # Regression coverage for two real beta-tester failures with the same
  # root cause class: (1) the migration job reported "Applied" with the
  # correct object count, but none of the AdGuardHome.yaml's
  # filtering.rewrites DNS rewrites actually showed up anywhere in
  # Alderpoint DNS; (2) a later regression where rewrites whose domain did
  # not fall under Alderpoint DNS's configured internal domain were instead
  # classified as Custom Filtering Rules. The clean_install_adguard.yaml
  # fixture carries real rewrites (an A record, an AAAA record, a
  # CNAME-style alias, one rewrite disabled at the source, and one rewrite
  # under a domain -- otherlan.test -- that is NOT home.arpa) so neither can
  # regress silently again.
  echo "+ verifying the AdGuard import's job page reports Local DNS counts explicitly, not just a bare 'Applied' ($label)"
  adguard_job_html="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/import/jobs/$adguard_job_id")"
  echo "$adguard_job_html" | grep -q 'Local DNS: 5 created' || \
    fail "$label: the AdGuard import job page does not report 'Local DNS: 5 created' in its result breakdown (got: $(echo "$adguard_job_html" | grep -o 'Local DNS:[^<]*' | head -1))"

  echo "+ verifying the imported Local DNS records actually landed in Alderpoint DNS's database ($label)"
  local_dns_rows="$(run "runuser -u alderpointdns -- python3 -c \"import sqlite3; c = sqlite3.connect('/var/lib/alderpointdns/alderpointdns.db'); c.row_factory = sqlite3.Row; [print(dict(r)) for r in c.execute(\\\"SELECT fqdn, record_type, value, enabled FROM local_dns_records WHERE fqdn LIKE 'clean-install-%' ORDER BY fqdn\\\")]\"")"
  echo "$local_dns_rows" | grep -q "'fqdn': 'clean-install-nas.home.arpa'.*'record_type': 'A'.*'value': '192.168.50.10'.*'enabled': 1" || \
    fail "$label: the imported A record clean-install-nas.home.arpa was not found (enabled) in local_dns_records (got: $local_dns_rows)"
  echo "$local_dns_rows" | grep -q "'fqdn': 'clean-install-printer.home.arpa'.*'record_type': 'AAAA'.*'enabled': 1" || \
    fail "$label: the imported AAAA record clean-install-printer.home.arpa was not found (enabled) in local_dns_records (got: $local_dns_rows)"
  echo "$local_dns_rows" | grep -q "'fqdn': 'clean-install-alias.home.arpa'.*'record_type': 'CNAME'.*'enabled': 1" || \
    fail "$label: the imported CNAME record clean-install-alias.home.arpa was not found (enabled) in local_dns_records (got: $local_dns_rows)"
  echo "$local_dns_rows" | grep -q "'fqdn': 'clean-install-disabled.home.arpa'.*'enabled': 0" || \
    fail "$label: the source-disabled rewrite clean-install-disabled.home.arpa was not imported as a disabled (enabled=0) record (got: $local_dns_rows)"
  echo "$local_dns_rows" | grep -q "'fqdn': 'clean-install-router.otherlan.test'.*'record_type': 'A'.*'value': '192.168.50.12'.*'enabled': 1" || \
    fail "$label: the imported A record clean-install-router.otherlan.test (outside the internal domain) was not found (enabled) in local_dns_records (got: $local_dns_rows)"

  echo "+ verifying the external-domain rewrite did NOT land in Custom Filtering Rules ($label)"
  custom_rule_leak="$(run "runuser -u alderpointdns -- python3 -c \"import sqlite3; c = sqlite3.connect('/var/lib/alderpointdns/alderpointdns.db'); print(c.execute(\\\"SELECT count(*) FROM custom_filter_rules WHERE domain LIKE '%otherlan.test%' OR domain LIKE 'clean-install-router%'\\\").fetchone()[0])\"")"
  [ "$custom_rule_leak" = "0" ] || \
    fail "$label: the AdGuard rewrite clean-install-router.otherlan.test leaked into custom_filter_rules instead of staying in Local DNS only (count: $custom_rule_leak)"

  echo "+ verifying the Local DNS and Custom Filtering Rules web pages show each import in the correct place ($label)"
  local_dns_page_html="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/local-dns")"
  echo "$local_dns_page_html" | grep -q 'clean-install-router.otherlan.test' || \
    fail "$label: clean-install-router.otherlan.test does not appear on the /local-dns page"
  custom_rules_page_html="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/custom-rules")"
  echo "$custom_rules_page_html" | grep -q 'clean-install-router.otherlan.test' && \
    fail "$label: clean-install-router.otherlan.test incorrectly appears on the /custom-rules page"
  echo "$custom_rules_page_html" | grep -q 'clean-install-block.invalid' || \
    fail "$label: the genuine custom rule clean-install-block.invalid does not appear on the /custom-rules page"

  echo "+ verifying the generated BIND zone files contain the imported Local DNS records ($label)"
  run "grep -q 'clean-install-nas' /var/lib/alderpointdns/compiled/bind/local/home.arpa.zone" || \
    fail "$label: the generated home.arpa.zone does not contain clean-install-nas"
  run "grep -q 'clean-install-printer' /var/lib/alderpointdns/compiled/bind/local/home.arpa.zone" || \
    fail "$label: the generated home.arpa.zone does not contain clean-install-printer"
  run "grep -q 'clean-install-alias' /var/lib/alderpointdns/compiled/bind/local/home.arpa.zone" || \
    fail "$label: the generated home.arpa.zone does not contain clean-install-alias"
  run "grep -q 'clean-install-router' /var/lib/alderpointdns/compiled/bind/local/otherlan.test.zone" || \
    fail "$label: the auto-created otherlan.test.zone does not contain clean-install-router"

  echo "+ verifying the imported Local DNS records resolve through dnsdist ($label)"
  run "dig @127.0.0.1 -p 53 clean-install-nas.home.arpa A +time=3 +tries=2 +short | grep -qx '192.168.50.10'" || \
    fail "$label: clean-install-nas.home.arpa did not resolve to 192.168.50.10 through dnsdist"
  run "dig @127.0.0.1 -p 53 clean-install-printer.home.arpa AAAA +time=3 +tries=2 +short | grep -qi 'fd00:beef::50'" || \
    fail "$label: clean-install-printer.home.arpa did not resolve to fd00:beef::50 through dnsdist"
  run "dig @127.0.0.1 -p 53 clean-install-alias.home.arpa A +time=3 +tries=2 +short | grep -qx '192.168.50.10'" || \
    fail "$label: clean-install-alias.home.arpa (CNAME to clean-install-nas.home.arpa) did not resolve to 192.168.50.10 through dnsdist"
  run "dig @127.0.0.1 -p 53 clean-install-disabled.home.arpa A +time=3 +tries=2 +short | grep -q ." && \
    fail "$label: clean-install-disabled.home.arpa resolved despite being imported disabled (source-disabled AdGuard rewrites must not be served)"
  run "dig @127.0.0.1 -p 53 clean-install-router.otherlan.test A +time=3 +tries=2 +short | grep -qx '192.168.50.12'" || \
    fail "$label: clean-install-router.otherlan.test (outside the internal domain) did not resolve to 192.168.50.12 through dnsdist"

  echo "+ re-uploading and re-applying the same AdGuard Home migration to confirm Local DNS records are skipped as duplicates, not re-created ($label)"
  local_dns_count_before_reimport="$(run "runuser -u alderpointdns -- python3 -c \"import sqlite3; c = sqlite3.connect('/var/lib/alderpointdns/alderpointdns.db'); print(c.execute('SELECT count(*) FROM local_dns_records').fetchone()[0])\"")"
  adguard_headers2="$(run "curl -s -D - -o /tmp/adguard-upload-body2.$label.html -b $COOKIE_JAR -c $COOKIE_JAR \
    -F csrf=$import_csrf -F upload=@/tmp/adguard_home.yaml \
    http://127.0.0.1:3000/import/migration/adguard/yaml")"
  adguard_job_id2="$(printf '%s' "$adguard_headers2" | tr -d '\r' | sed -nE 's#.*[Ll]ocation: */import/jobs/([0-9]+)/preview.*#\1#p' | head -1)"
  [ -n "$adguard_job_id2" ] || fail "$label: re-uploading the AdGuard Home migration did not reach a preview page"
  apply_code2="$(run "curl -s -o /tmp/adguard-apply-body2.$label.html -w '%{http_code}' -b $COOKIE_JAR -c $COOKIE_JAR \
    -d csrf=$import_csrf http://127.0.0.1:3000/import/jobs/$adguard_job_id2/apply")"
  [ "$apply_code2" = "303" ] || fail "$label: re-applying the AdGuard Home migration failed (HTTP $apply_code2)"
  adguard_job_html2="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/import/jobs/$adguard_job_id2")"
  echo "$adguard_job_html2" | grep -q 'Local DNS: 0 created' || \
    fail "$label: re-importing the identical AdGuard Home migration did not report 'Local DNS: 0 created' (got: $(echo "$adguard_job_html2" | grep -o 'Local DNS:[^<]*' | head -1))"
  local_dns_count_after_reimport="$(run "runuser -u alderpointdns -- python3 -c \"import sqlite3; c = sqlite3.connect('/var/lib/alderpointdns/alderpointdns.db'); print(c.execute('SELECT count(*) FROM local_dns_records').fetchone()[0])\"")"
  [ "$local_dns_count_before_reimport" = "$local_dns_count_after_reimport" ] || \
    fail "$label: re-importing the identical AdGuard Home migration changed the local_dns_records row count ($local_dns_count_before_reimport -> $local_dns_count_after_reimport) -- duplicates were created"

  echo "+ uploading, previewing, and applying a synthetic Pi-hole migration ($label)"
  count_before_pihole="$(backup_archive_count)"
  pihole_headers="$(run "curl -s -D - -o /tmp/pihole-upload-body.$label.html -b $COOKIE_JAR -c $COOKIE_JAR \
    -F csrf=$import_csrf -F source_type=pihole -F default_domain=home.arpa -F upload=@/tmp/pihole_export.txt \
    http://127.0.0.1:3000/import/upload")"
  pihole_job_id="$(printf '%s' "$pihole_headers" | tr -d '\r' | sed -nE 's#.*[Ll]ocation: */import/jobs/([0-9]+)/preview.*#\1#p' | head -1)"
  if [ -z "$pihole_job_id" ]; then
    run "cat /tmp/pihole-upload-body.$label.html" >&2 || true
    fail "$label: uploading the synthetic Pi-hole migration did not reach a preview page"
  fi
  pihole_apply_code="$(run "curl -s -o /tmp/pihole-apply-body.$label.html -w '%{http_code}' -b $COOKIE_JAR -c $COOKIE_JAR \
    -d csrf=$import_csrf http://127.0.0.1:3000/import/jobs/$pihole_job_id/apply")"
  if [ "$pihole_apply_code" != "303" ]; then
    run "cat /tmp/pihole-apply-body.$label.html" >&2 || true
    fail "$label: applying the synthetic Pi-hole migration failed (HTTP $pihole_apply_code) -- this reproduces the pre-import backup failure"
  fi
  pihole_status="$(run "curl -s -b $COOKIE_JAR http://127.0.0.1:3000/import/jobs/$pihole_job_id/status")"
  echo "$pihole_status" | grep -q '"status":"applied"' || \
    fail "$label: Pi-hole migration job $pihole_job_id did not reach status=applied (got: $pihole_status)"
  echo "+ confirming the Pi-hole import's mandatory pre-import backup actually succeeded ($label)"
  [ "$(backup_archive_count)" -gt "$count_before_pihole" ] || \
    fail "$label: applying the Pi-hole migration did not create a new pre-import backup archive"

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
  # /setup requires a CSRF token, bound to the anonymous pre-login session
  # established on first visit (app/webapp.py's render()), plus a matching
  # password confirmation. /login still takes plain form posts.
  setup_page="$(run "curl -s -c $COOKIE_JAR http://127.0.0.1:3000/setup")"
  setup_csrf="$(printf '%s\n' "$setup_page" | sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' | head -1)"
  run "curl -s -c $COOKIE_JAR -b $COOKIE_JAR -o /dev/null -d 'username=admin' -d 'password=ClnInst4llTest!2026' -d 'confirm_password=ClnInst4llTest!2026' -d 'csrf=$setup_csrf' http://127.0.0.1:3000/setup" || true
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
