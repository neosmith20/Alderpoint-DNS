#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: upgrade.sh [--dry-run] [--source DIR] [--skip-service-restart]

Safely upgrade an existing BindGuard installation from a reviewed local source
tree. The workflow creates a pre-upgrade backup, stages a rollback snapshot,
validates configuration, runs migrations, restarts services in order, and
restores the prior application/configuration snapshot if health checks fail.

Environment:
  BINDGUARD_INSTALL_ROOT  Alternate root for isolated tests.
EOF
}

DRY_RUN=0
SKIP_RESTART=0
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
ROOT="${BINDGUARD_INSTALL_ROOT:-/}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --skip-service-restart) SKIP_RESTART=1 ;;
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
    echo "upgrade must run as root unless --dry-run is used" >&2
    exit 1
  fi
}

current_version() {
  if [ -r "$(root_path /opt/bindguard/VERSION)" ]; then
    cat "$(root_path /opt/bindguard/VERSION)"
  else
    echo "unknown"
  fi
}

target_version() {
  if [ -r "$SOURCE_DIR/VERSION" ]; then
    cat "$SOURCE_DIR/VERSION"
  else
    echo "unknown"
  fi
}

check_existing_install() {
  if [ ! -e "$(root_path /opt/bindguard/app/webapp.py)" ]; then
    echo "no existing BindGuard installation found; use install.sh first" >&2
    exit 1
  fi
  free_kb="$(df -Pk "${ROOT:-/}" | awk 'NR==2 {print $4}')"
  if [ "${free_kb:-0}" -lt 1048576 ]; then
    echo "at least 1 GiB free disk space is required for upgrade rollback snapshots" >&2
    exit 1
  fi
}

pre_upgrade_backup() {
  if [ -x "$(root_path /opt/bindguard/scripts/backup.sh)" ]; then
    run "$(root_path /opt/bindguard/scripts/backup.sh)"
  else
    echo "warning: backup script is unavailable; rollback snapshot will still be created" >&2
  fi
}

snapshot() {
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  path="$(root_path "/var/lib/bindguard/backups/pre-upgrade-app-${stamp}.tar.gz")"
  run install -d -m 0750 "$(dirname "$path")"
  if [ "$DRY_RUN" -eq 0 ]; then
    tar -czf "$path" -C "$(root_path /)" opt/bindguard etc/bindguard etc/systemd/system/bindguard.service etc/systemd/system/bindguard-analytics.service 2>/dev/null || true
  else
    echo "+ create rollback snapshot $path"
  fi
  printf '%s\n' "$path"
}

restore_snapshot() {
  path="$1"
  if [ "$DRY_RUN" -eq 0 ] && [ -r "$path" ]; then
    tar -xzf "$path" -C "$(root_path /)"
  else
    echo "+ restore rollback snapshot $path"
  fi
}

replace_application() {
  target="$(root_path /opt/bindguard)"
  if [ "$DRY_RUN" -eq 0 ]; then
    find "$target" -mindepth 1 -maxdepth 1 \
      ! -name .git ! -name venv ! -name vendor \
      -exec rm -rf {} +
    tar -C "$SOURCE_DIR" \
      --exclude .git --exclude __pycache__ --exclude '*.pyc' \
      -cf - . | tar -C "$target" --strip-components=0 -xf -
  else
    echo "+ replace application files in $target from $SOURCE_DIR"
  fi
}

install_units() {
  run install -D -m 0644 "$SOURCE_DIR/packaging/bindguard.service" "$(root_path /etc/systemd/system/bindguard.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/bindguard-analytics.service" "$(root_path /etc/systemd/system/bindguard-analytics.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/bindguard-backup.service" "$(root_path /etc/systemd/system/bindguard-backup.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/bindguard-backup.timer" "$(root_path /etc/systemd/system/bindguard-backup.timer)"
  run install -D -m 0440 "$SOURCE_DIR/packaging/sudoers-bindguard" "$(root_path /etc/sudoers.d/bindguard)"
}

validate() {
  if [ "$ROOT" != "/" ]; then
    echo "test root in use; skipping host configuration validation"
    return
  fi
  run python3 -m py_compile /opt/bindguard/app/webapp.py /opt/bindguard/app/bindguard_compiler.py
  run named-checkconf -p /etc/bind/named.conf
  run dnsdist --check-config
  run visudo -cf /etc/sudoers.d/bindguard
}

migrate() {
  if [ "$ROOT" = "/" ]; then
    run /opt/bindguard/app/analytics.py init-db
    run /opt/bindguard/app/bindguard_compiler.py deploy --no-download
  else
    echo "test root in use; skipping live database migrations and DNS deployment"
  fi
}

restart_services() {
  if [ "$SKIP_RESTART" -eq 1 ]; then
    echo "service restart skipped by operator"
    return
  fi
  if [ "$ROOT" = "/" ]; then
    run systemctl daemon-reload
    run systemctl restart named
    run systemctl restart dnsdist
    run systemctl restart bindguard-analytics
    run systemctl restart bindguard
    run systemctl is-active --quiet named
    run systemctl is-active --quiet dnsdist
    run systemctl is-active --quiet bindguard-analytics
    run systemctl is-active --quiet bindguard
  else
    echo "test root in use; skipping service restart"
  fi
}

main() {
  require_root
  check_existing_install
  echo "Current BindGuard version: $(current_version)"
  echo "Target BindGuard version: $(target_version)"
  pre_upgrade_backup
  rollback="$(snapshot)"
  if replace_application && install_units && validate && migrate && restart_services; then
    echo "BindGuard upgrade completed."
  else
    echo "upgrade failed; restoring rollback snapshot" >&2
    restore_snapshot "$rollback"
    restart_services || true
    exit 1
  fi
}

main
