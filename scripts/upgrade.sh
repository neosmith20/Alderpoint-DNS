#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: upgrade.sh [--dry-run] [--source DIR] [--skip-service-restart]

Safely upgrade an existing Alderpoint DNS installation from a reviewed local source
tree. The workflow creates a pre-upgrade backup, stages a rollback snapshot,
validates configuration, runs migrations, restarts services in order, and
restores the prior application/configuration snapshot if health checks fail.

Environment:
  ALDERPOINTDNS_INSTALL_ROOT  Alternate root for isolated tests.
EOF
}

DRY_RUN=0
SKIP_RESTART=0
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# Deprecated BindGuard-era environment variable name, recognized long enough
# to migrate operators to ALDERPOINTDNS_INSTALL_ROOT. See docs/compatibility.md
# for the planned removal version.
if [ -n "${BINDGUARD_INSTALL_ROOT:-}" ] && [ -z "${ALDERPOINTDNS_INSTALL_ROOT:-}" ]; then
  echo "warning: BINDGUARD_INSTALL_ROOT is deprecated, use ALDERPOINTDNS_INSTALL_ROOT (see docs/compatibility.md)" >&2
  ALDERPOINTDNS_INSTALL_ROOT="$BINDGUARD_INSTALL_ROOT"
fi
ROOT="${ALDERPOINTDNS_INSTALL_ROOT:-/}"

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
  if [ -r "$(root_path /opt/alderpointdns/VERSION)" ]; then
    cat "$(root_path /opt/alderpointdns/VERSION)"
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
  if [ ! -e "$(root_path /opt/alderpointdns/app/webapp.py)" ]; then
    echo "no existing Alderpoint DNS installation found; use install.sh first" >&2
    exit 1
  fi
  free_kb="$(df -Pk "${ROOT:-/}" | awk 'NR==2 {print $4}')"
  if [ "${free_kb:-0}" -lt 1048576 ]; then
    echo "at least 1 GiB free disk space is required for upgrade rollback snapshots" >&2
    exit 1
  fi
}

legacy_install_present() {
  [ ! -e "$(root_path /opt/alderpointdns/app/webapp.py)" ] && [ -e "$(root_path /opt/bindguard/app/webapp.py)" ]
}

# One-time migration of a pre-rename BindGuard installation, run before any
# other upgrade step so the rest of upgrade.sh only ever sees Alderpoint DNS
# paths. A legacy install is backed up with its own (still fully consistent,
# unmigrated) backup.sh before anything is touched, so the original state is
# always recoverable even if the migration itself fails partway through.
migrate_legacy_layout() {
  echo "legacy BindGuard installation detected at $(root_path /opt/bindguard); migrating to Alderpoint DNS paths"

  # If the new-source tree we're about to install from is inside the legacy
  # directory we're about to move out from under ourselves (e.g. an
  # in-place git checkout used as both the running legacy install and the
  # new release), SOURCE_DIR would silently stop existing the moment that
  # mv happens below, breaking replace_application/install_units later in
  # this script. Stage a plain copy outside the legacy tree first so
  # SOURCE_DIR keeps resolving no matter what gets moved.
  case "$SOURCE_DIR" in
    "$(root_path /opt/bindguard)"|"$(root_path /opt/bindguard)"/*)
      staged_source="$(mktemp -d /tmp/alderpointdns-upgrade-source.XXXXXX)"
      run cp -a "$SOURCE_DIR/." "$staged_source/"
      echo "staged upgrade source to $staged_source before moving the legacy installation directory"
      SOURCE_DIR="$staged_source"
      ;;
  esac

  if [ -x "$(root_path /opt/bindguard/scripts/backup.sh)" ] && [ "$ROOT" = "/" ]; then
    run "$(root_path /opt/bindguard/scripts/backup.sh)"
  else
    echo "warning: legacy backup script unavailable or test root in use; skipping pre-migration native backup" >&2
  fi

  if [ "$ROOT" = "/" ] && [ "$DRY_RUN" -eq 0 ]; then
    systemctl stop bindguard.service bindguard-analytics.service bindguard-backup.timer >/dev/null 2>&1 || true
    systemctl stop named dnsdist >/dev/null 2>&1 || true
  fi

  # Rewrite only the literal bindguard/BindGuard/BINDGUARD tokens in the live
  # BIND/dnsdist/apparmor config, in place -- this must never overwrite these
  # files wholesale from packaging templates, since they carry live secrets
  # (dnsdist console key, webserver credentials) and any local customization.
  for cfg in /etc/bind/named.conf.local /etc/bind/named.conf.options /etc/dnsdist/dnsdist.conf /etc/apparmor.d/local/usr.sbin.named; do
    live="$(root_path "$cfg")"
    if [ -f "$live" ]; then
      run sed -i \
        -e 's/BindGuard/Alderpoint DNS/g' \
        -e 's/BINDGUARD_/ALDERPOINTDNS_/g' \
        -e 's/BINDGUARD/ALDERPOINTDNS/g' \
        -e 's/bindguard/alderpointdns/g' \
        "$live"
    fi
  done

  run mv "$(root_path /opt/bindguard)" "$(root_path /opt/alderpointdns)"

  if [ -e "$(root_path /etc/bindguard)" ]; then
    run mv "$(root_path /etc/bindguard)" "$(root_path /etc/alderpointdns)"
  fi

  if [ -e "$(root_path /var/lib/bindguard)" ]; then
    run mv "$(root_path /var/lib/bindguard)" "$(root_path /var/lib/alderpointdns)"
    if [ -e "$(root_path /var/lib/alderpointdns/bindguard.db)" ]; then
      for suffix in "" -wal -shm; do
        old="$(root_path "/var/lib/alderpointdns/bindguard.db${suffix}")"
        new="$(root_path "/var/lib/alderpointdns/alderpointdns.db${suffix}")"
        [ -e "$old" ] && run mv "$old" "$new"
      done
    fi
    if [ -e "$(root_path /var/lib/alderpointdns/compiled/bind/bindguard.rpz)" ]; then
      run mv "$(root_path /var/lib/alderpointdns/compiled/bind/bindguard.rpz)" "$(root_path /var/lib/alderpointdns/compiled/bind/alderpointdns.rpz)"
    fi
  fi

  if [ -e "$(root_path /var/log/bindguard)" ]; then
    run mv "$(root_path /var/log/bindguard)" "$(root_path /var/log/alderpointdns)"
  fi

  if [ "$ROOT" = "/" ] && [ "$DRY_RUN" -eq 0 ]; then
    run ln -sfn /opt/alderpointdns /opt/bindguard
    run ln -sfn /etc/alderpointdns /etc/bindguard
    run ln -sfn /var/lib/alderpointdns /var/lib/bindguard
    run ln -sfn /var/log/alderpointdns /var/log/bindguard
    run rm -f /etc/sudoers.d/bindguard
    run rm -f /etc/systemd/system/bindguard.service /etc/systemd/system/bindguard-analytics.service \
      /etc/systemd/system/bindguard-backup.service /etc/systemd/system/bindguard-backup.timer
    run rm -f /etc/systemd/system/dnsdist.service.d/bindguard.conf
    run systemctl daemon-reload
    command -v apparmor_parser >/dev/null 2>&1 && run apparmor_parser -r /etc/apparmor.d/usr.sbin.named >/dev/null 2>&1 || true
    run systemctl start named
    run systemctl start dnsdist
  fi

  echo "legacy path migration complete; continuing upgrade with Alderpoint DNS paths (bindguard system user/group intentionally kept, see docs/compatibility.md)"
}

pre_upgrade_backup() {
  if [ -x "$(root_path /opt/alderpointdns/scripts/backup.sh)" ]; then
    run "$(root_path /opt/alderpointdns/scripts/backup.sh)"
  else
    echo "warning: backup script is unavailable; rollback snapshot will still be created" >&2
  fi
}

snapshot() {
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  path="$(root_path "/var/lib/alderpointdns/backups/pre-upgrade-app-${stamp}.tar.gz")"
  run install -d -m 0750 "$(dirname "$path")"
  if [ "$DRY_RUN" -eq 0 ]; then
    tar -czf "$path" -C "$(root_path /)" opt/alderpointdns etc/alderpointdns etc/systemd/system/alderpointdns.service etc/systemd/system/alderpointdns-analytics.service 2>/dev/null || true
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
  target="$(root_path /opt/alderpointdns)"
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
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns.service" "$(root_path /etc/systemd/system/alderpointdns.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns-analytics.service" "$(root_path /etc/systemd/system/alderpointdns-analytics.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns-backup.service" "$(root_path /etc/systemd/system/alderpointdns-backup.service)"
  run install -D -m 0644 "$SOURCE_DIR/packaging/alderpointdns-backup.timer" "$(root_path /etc/systemd/system/alderpointdns-backup.timer)"
  run install -D -m 0440 "$SOURCE_DIR/packaging/sudoers-alderpointdns" "$(root_path /etc/sudoers.d/alderpointdns)"
}

validate() {
  if [ "$ROOT" != "/" ]; then
    echo "test root in use; skipping host configuration validation"
    return
  fi
  run python3 -m py_compile /opt/alderpointdns/app/webapp.py /opt/alderpointdns/app/alderpointdns_compiler.py
  run named-checkconf -p /etc/bind/named.conf
  run dnsdist --check-config
  run visudo -cf /etc/sudoers.d/alderpointdns
}

migrate() {
  if [ "$ROOT" = "/" ]; then
    run /opt/alderpointdns/app/analytics.py init-db
    run /opt/alderpointdns/app/alderpointdns_compiler.py deploy --no-download
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
    run systemctl restart alderpointdns-analytics
    run systemctl restart alderpointdns
    run systemctl is-active --quiet named
    run systemctl is-active --quiet dnsdist
    run systemctl is-active --quiet alderpointdns-analytics
    run systemctl is-active --quiet alderpointdns
  else
    echo "test root in use; skipping service restart"
  fi
}

main() {
  require_root
  was_legacy=0
  if legacy_install_present; then
    was_legacy=1
    migrate_legacy_layout
  fi
  check_existing_install
  echo "Current Alderpoint DNS version: $(current_version)"
  echo "Target Alderpoint DNS version: $(target_version)"
  if [ "$was_legacy" -eq 0 ]; then
    # In the legacy case, migrate_legacy_layout() already took a native
    # backup of the fully self-consistent pre-migration install; the
    # just-moved application source still has old BindGuard-era path
    # constants baked in until replace_application below installs the
    # renamed source, so calling the (already-renamed) backup.sh again here
    # would look for files under names that no longer exist.
    pre_upgrade_backup
  fi
  rollback="$(snapshot)"
  if replace_application && install_units && validate && migrate && restart_services; then
    echo "Alderpoint DNS upgrade completed."
  else
    echo "upgrade failed; restoring rollback snapshot" >&2
    restore_snapshot "$rollback"
    restart_services || true
    exit 1
  fi
}

main
