#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: install.sh [--dry-run] [--source DIR] [--skip-apt]

Install BindGuard on a fresh Debian-based server. The script is intended to be
downloaded and reviewed before running; do not pipe it directly from the
network into a root shell.

Environment:
  BINDGUARD_INSTALL_ROOT  Alternate root for isolated tests.
EOF
}

DRY_RUN=0
SKIP_APT=0
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ROOT="${BINDGUARD_INSTALL_ROOT:-/}"

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
  target="$(root_path /opt/bindguard)"
  if [ -e "$target/app/webapp.py" ]; then
    echo "existing BindGuard installation found at $target; use upgrade.sh for upgrades" >&2
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
  run install -d -m 0755 "$(root_path /etc/bindguard)"
  run install -d -m 0750 "$(root_path /etc/bindguard/certs)"
  run install -d -m 0755 "$(root_path /var/lib/bindguard)"
  run install -d -m 0750 "$(root_path /var/lib/bindguard/backups)"
  run install -d -m 0750 "$(root_path /var/lib/bindguard/compiled)"
  run install -d -m 0750 "$(root_path /var/lib/bindguard/imports)"
  run install -d -m 0750 "$(root_path /var/lib/bindguard/staging)"
  run install -d -m 0755 "$(root_path /var/log/bindguard)"
}

create_users() {
  if [ "$ROOT" != "/" ]; then
    echo "test root in use; skipping system user/group creation"
    return
  fi
  if ! getent group bindguard >/dev/null; then
    run groupadd --system bindguard
  fi
  if ! id bindguard >/dev/null 2>&1; then
    run useradd --system --home /var/lib/bindguard --shell /usr/sbin/nologin --gid bindguard bindguard
  fi
}

install_config() {
  run install -D -m 0644 "$SOURCE_DIR/packaging/bindguard.service" "$(root_path /etc/systemd/system/bindguard.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/bindguard-analytics.service" "$(root_path /etc/systemd/system/bindguard-analytics.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/bindguard-backup.service" "$(root_path /etc/systemd/system/bindguard-backup.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/bindguard-backup.timer" "$(root_path /etc/systemd/system/bindguard-backup.timer)"
  run install -D -m 0440 "$SOURCE_DIR/packaging/sudoers-bindguard" "$(root_path /etc/sudoers.d/bindguard)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/named.conf.options" "$(root_path /etc/bind/named.conf.options)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/named.conf.local" "$(root_path /etc/bind/named.conf.local)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/dnsdist.conf" "$(root_path /etc/dnsdist/dnsdist.conf)"
  run install -d -m 0755 "$(root_path /etc/systemd/system/dnsdist.service.d)"
  run install -m 0644 "$SOURCE_DIR/packaging/dnsdist.service.d/bindguard.conf" "$(root_path /etc/systemd/system/dnsdist.service.d/bindguard.conf)"
}

create_venv() {
  venv="$(root_path /opt/bindguard/venv)"
  run python3 -m venv --system-site-packages "$venv"
  if [ "$DRY_RUN" -eq 0 ] && command -v "$venv/bin/pip" >/dev/null 2>&1; then
    "$venv/bin/pip" install --no-index --find-links "$(root_path /opt/bindguard/vendor)" -r "$(root_path /opt/bindguard/requirements.txt)" || \
      echo "offline wheel install skipped; Debian Python packages remain the supported runtime"
  fi
}

generate_secrets() {
  secrets_env="$(root_path /etc/bindguard/secrets.env)"
  dnsdist_api="$(root_path /etc/bindguard/dnsdist-api.key)"
  dnsdist_web="$(root_path /etc/bindguard/dnsdist-web.creds)"
  if [ "$DRY_RUN" -eq 0 ]; then
    [ -e "$secrets_env" ] || {
      umask 077
      printf 'BINDGUARD_SESSION_SECRET=%s\n' "$(openssl rand -base64 48)" > "$secrets_env"
    }
    [ -e "$dnsdist_api" ] || {
      umask 077
      openssl rand -base64 32 > "$dnsdist_api"
    }
    [ -e "$dnsdist_web" ] || {
      umask 077
      printf 'bindguard:%s\n' "$(openssl rand -base64 24)" > "$dnsdist_web"
    }
  else
    echo "+ generate session, dnsdist API, and dnsdist web credentials"
  fi
}

initialize() {
  if [ "$DRY_RUN" -eq 0 ]; then
    /opt/bindguard/scripts/ensure_tls_cert.sh
    PYTHONPATH=/opt/bindguard /opt/bindguard/app/analytics.py init-db
    PYTHONPATH=/opt/bindguard /opt/bindguard/app/bindguard_compiler.py deploy --no-download
    chown -R bindguard:bindguard /var/lib/bindguard /var/log/bindguard
    chown -R root:bindguard /etc/bindguard
    chmod 0640 /etc/bindguard/secrets.env /etc/bindguard/dnsdist-api.key /etc/bindguard/dnsdist-web.creds
    systemctl daemon-reload
    systemctl enable --now named dnsdist bindguard bindguard-analytics
    systemctl enable bindguard-backup.timer
    systemctl is-active --quiet named
    systemctl is-active --quiet dnsdist
    systemctl is-active --quiet bindguard
    systemctl is-active --quiet bindguard-analytics
  else
    echo "+ initialize database, TLS material, generated DNS config, ownership, systemd services, and health checks"
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
  echo "BindGuard installation path prepared."
  echo "Next: open http://<server-ip>:3000/setup to create the first administrator."
}

main
