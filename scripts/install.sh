#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: install.sh [--dry-run] [--source DIR] [--skip-apt]

Install Alderpoint DNS on a fresh Debian-based server. The script is intended to be
downloaded and reviewed before running; do not pipe it directly from the
network into a root shell.

Environment:
  ALDERPOINTDNS_INSTALL_ROOT  Alternate root for isolated tests.
EOF
}

DRY_RUN=0
SKIP_APT=0
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ROOT="${ALDERPOINTDNS_INSTALL_ROOT:-/}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --skip-apt) SKIP_APT=1 ;;
    --source) shift; SOURCE_DIR="${1:?missing source dir}" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

root_path() {
  if [ "$ROOT" = "/" ]; then
    printf '%s\n' "$1"
  else
    printf '%s%s\n' "$ROOT" "$1"
  fi
}

run() {
  printf '+ %s\n' "$*"
  if [ "$DRY_RUN" -eq 0 ]; then
    "$@"
  fi
}

require_root() {
  if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
    echo "installer must run as root unless --dry-run is used" >&2
    exit 1
  fi
}

check_os() {
  if [ -r /etc/os-release ]; then
    . /etc/os-release
    case "${ID:-}" in
      debian|ubuntu) ;;
      *) echo "unsupported operating system: ${PRETTY_NAME:-unknown}" >&2; exit 1 ;;
    esac
    case "${VERSION_ID:-}" in
      12|13|24.04|26.04|"") ;;
      *) echo "unsupported OS version: ${VERSION_ID}; supported: Debian 12/13 or Ubuntu 24.04/26.04 LTS" >&2; exit 1 ;;
    esac
  fi
}

check_resources() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64|aarch64|arm64) ;;
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
  esac
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  if [ "${mem_kb:-0}" -lt 524288 ]; then
    echo "at least 512 MiB RAM is required" >&2
    exit 1
  fi
  free_kb="$(df -Pk "${ROOT:-/}" | awk 'NR==2 {print $4}')"
  if [ "${free_kb:-0}" -lt 1048576 ]; then
    echo "at least 1 GiB free disk space is required" >&2
    exit 1
  fi
}

install_packages() {
  if [ "$SKIP_APT" -eq 1 ]; then
    echo "skipping package installation"
    return
  fi
  packages="$(tr '\n' ' ' < "$SOURCE_DIR/requirements-debian.txt")"
  run apt-get update
  # shellcheck disable=SC2086
  run apt-get install -y $packages
}

copy_tree() {
  target="$(root_path /opt/alderpointdns)"
  if [ -e "$target/app/webapp.py" ]; then
    echo "existing Alderpoint DNS installation found at $target; use upgrade.sh for upgrades" >&2
    exit 1
  fi
  run install -d -m 0755 "$target"
  if [ "$DRY_RUN" -eq 0 ]; then
    tar -C "$SOURCE_DIR" \
      --exclude .git --exclude __pycache__ --exclude '*.pyc' \
      -cf - . | tar -C "$target" --strip-components=0 -xf -
  else
    echo "+ copy source tree $SOURCE_DIR -> $target"
  fi
}

create_layout() {
  run install -d -m 0755 "$(root_path /etc/alderpointdns)"
  run install -d -m 0750 "$(root_path /etc/alderpointdns/certs)"
  run install -d -m 0755 "$(root_path /var/lib/alderpointdns)"
  run install -d -m 0750 "$(root_path /var/lib/alderpointdns/backups)"
  # 0755, not 0750: named and dnsdist (separate system accounts, unrelated
  # to alderpointdns) must be able to traverse into this directory to
  # reach their own generated config under compiled/bind/ and
  # compiled/dnsdist/ -- those files are root-owned and world-readable
  # already (written by the root-escalated deploy path), so this
  # directory only needs to be enterable, not additionally restricted.
  run install -d -m 0755 "$(root_path /var/lib/alderpointdns/compiled)"
  run install -d -m 0750 "$(root_path /var/lib/alderpointdns/imports)"
  run install -d -m 0750 "$(root_path /var/lib/alderpointdns/staging)"
  run install -d -m 0755 "$(root_path /var/log/alderpointdns)"
}

create_users() {
  if [ "$ROOT" != "/" ]; then
    echo "test root in use; skipping system user/group creation"
    return
  fi
  if ! getent group alderpointdns >/dev/null; then
    run groupadd --system alderpointdns
  fi
  if ! id alderpointdns >/dev/null 2>&1; then
    run useradd --system --home /var/lib/alderpointdns --shell /usr/sbin/nologin --gid alderpointdns alderpointdns
  fi
}

install_config() {
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns.service" "$(root_path /etc/systemd/system/alderpointdns.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns-analytics.service" "$(root_path /etc/systemd/system/alderpointdns-analytics.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns-backup.service" "$(root_path /etc/systemd/system/alderpointdns-backup.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns-backup.timer" "$(root_path /etc/systemd/system/alderpointdns-backup.timer)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns-filter-update.service" "$(root_path /etc/systemd/system/alderpointdns-filter-update.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns-filter-update.timer" "$(root_path /etc/systemd/system/alderpointdns-filter-update.timer)"
  run install -D -m 0440 "$SOURCE_DIR/packaging/sudoers-alderpointdns" "$(root_path /etc/sudoers.d/alderpointdns)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/named.conf.options" "$(root_path /etc/bind/named.conf.options)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/named.conf.local" "$(root_path /etc/bind/named.conf.local)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/dnsdist.conf" "$(root_path /etc/dnsdist/dnsdist.conf)"
  run install -d -m 0755 "$(root_path /etc/systemd/system/dnsdist.service.d)"
  run install -m 0644 "$SOURCE_DIR/packaging/dnsdist.service.d/alderpointdns.conf" "$(root_path /etc/systemd/system/dnsdist.service.d/alderpointdns.conf)"
}

create_venv() {
  venv="$(root_path /opt/alderpointdns/venv)"
  run python3 -m venv --system-site-packages "$venv"
  if [ "$DRY_RUN" -eq 0 ] && command -v "$venv/bin/pip" >/dev/null 2>&1; then
    "$venv/bin/pip" install --no-index --find-links "$(root_path /opt/alderpointdns/vendor)" -r "$(root_path /opt/alderpointdns/requirements.txt)" || \
      echo "offline wheel install skipped; Debian Python packages remain the supported runtime"
  fi
}

generate_secrets() {
  secrets_env="$(root_path /etc/alderpointdns/secrets.env)"
  dnsdist_api="$(root_path /etc/alderpointdns/dnsdist-api.key)"
  dnsdist_web="$(root_path /etc/alderpointdns/dnsdist-web.creds)"
  if [ "$DRY_RUN" -eq 0 ]; then
    # Each block runs in a subshell: `umask` has no block scope in POSIX
    # sh (a bare `{ ...; }` group does not fork one), and initialize()
    # runs right after this function in the same shell -- its deploy step
    # creates compiled zone/config files that named/dnsdist must be able
    # to read, which must not inherit a leftover 077 meant only for these
    # three secrets.
    [ -e "$secrets_env" ] || (
      umask 077
      printf 'ALDERPOINTDNS_SESSION_SECRET=%s\n' "$(openssl rand -base64 48)" > "$secrets_env"
    )
    [ -e "$dnsdist_api" ] || (
      umask 077
      openssl rand -base64 32 > "$dnsdist_api"
    )
    [ -e "$dnsdist_web" ] || (
      umask 077
      printf 'alderpointdns:%s\n' "$(openssl rand -base64 24)" > "$dnsdist_web"
    )
  else
    echo "+ generate session, dnsdist API, and dnsdist web credentials"
  fi
}

initialize() {
  if [ "$DRY_RUN" -eq 0 ]; then
    /opt/alderpointdns/scripts/ensure_tls_cert.sh
    PYTHONPATH=/opt/alderpointdns /opt/alderpointdns/app/analytics.py init-db
    PYTHONPATH=/opt/alderpointdns /opt/alderpointdns/app/alderpointdns_compiler.py deploy --no-download
    chown -R alderpointdns:alderpointdns /var/lib/alderpointdns /var/log/alderpointdns
    # Deliberately not recursive: /etc/alderpointdns/certs is owned and
    # managed entirely by ensure_tls_cert.sh/app/encryption.py (root:_dnsdist
    # for the TLS-serving cert/key, root:root for the CA key) so that
    # dnsdist -- a separate system account with no relationship to
    # alderpointdns -- can read its own TLS material directly. Recursing
    # into it here would silently reassign that directory back to
    # alderpointdns and break dnsdist's cert access.
    chown root:alderpointdns /etc/alderpointdns
    chown root:alderpointdns /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds
    chmod 0640 /etc/alderpointdns/secrets.env /etc/alderpointdns/dnsdist-api.key /etc/alderpointdns/dnsdist-web.creds
    # named (running as its own "bind" system user, not alderpointdns) writes
    # its own log/statistics files directly into this subdirectory per
    # named.conf.options -- it must own it, so re-assert that ownership after
    # the blanket alderpointdns chown above.
    install -d -o bind -g bind -m 0750 "$(root_path /var/log/alderpointdns/bind)"
    systemctl daemon-reload
    systemctl enable --now named dnsdist alderpointdns alderpointdns-analytics
    systemctl enable alderpointdns-backup.timer
    # Writes the filter-update timer drop-in from the stored Filter Update
    # Interval (fresh installs default to 1 Day) and enables the timer.
    PYTHONPATH=/opt/alderpointdns /opt/alderpointdns/app/alderpointdns_compiler.py filter-schedule-deploy
    systemctl is-active --quiet named
    systemctl is-active --quiet dnsdist
    systemctl is-active --quiet alderpointdns
    systemctl is-active --quiet alderpointdns-analytics
  else
    echo "+ initialize database, TLS material, generated DNS config, ownership, systemd services, and health checks"
    echo "+ enable alderpointdns-filter-update.timer for the default 1 Day filter update interval"
  fi
}

main() {
  require_root
  check_os
  check_resources
  install_packages
  create_users
  create_layout
  copy_tree
  create_venv
  install_config
  generate_secrets
  initialize
  echo "Alderpoint DNS installation path prepared."
  echo "Next: open http://<server-ip>:3000/setup to create the first administrator."
}

main
