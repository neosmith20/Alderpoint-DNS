#!/bin/sh
set -eu

ROOT="$(mktemp -d /tmp/alderpointdns-install-test.XXXXXX)"
trap 'rm -rf "$ROOT"' EXIT

mkdir -p "$ROOT/var/lib/alderpointdns/backups"

ALDERPOINTDNS_INSTALL_ROOT="$ROOT" /opt/alderpointdns/scripts/install.sh --dry-run --skip-apt --source /opt/alderpointdns > "$ROOT/install.out"
grep -q "Alderpoint DNS installation path prepared" "$ROOT/install.out" || {
  echo "installer dry-run did not complete" >&2
  exit 1
}
grep -q "generate session, dnsdist API, and dnsdist web credentials" "$ROOT/install.out" || {
  echo "installer dry-run did not plan secret generation" >&2
  exit 1
}

mkdir -p "$ROOT/opt/alderpointdns"
cp -a /opt/alderpointdns/. "$ROOT/opt/alderpointdns/"
ALDERPOINTDNS_INSTALL_ROOT="$ROOT" /opt/alderpointdns/scripts/upgrade.sh --dry-run --source /opt/alderpointdns --skip-service-restart > "$ROOT/upgrade.out"
grep -q "Current Alderpoint DNS version" "$ROOT/upgrade.out" || {
  echo "upgrade dry-run did not inspect current version" >&2
  exit 1
}
grep -q "Alderpoint DNS upgrade completed" "$ROOT/upgrade.out" || {
  echo "upgrade dry-run did not complete" >&2
  exit 1
}

# Recent Logs access (System Status page) is granted through the same
# sudoers drop-in every other privileged web action uses, so both fresh
# install and upgrade must plan to (re)install it, and it must actually
# authorize the fixed, allowlisted "logs <unit>" commands the web app calls
# -- never an unrestricted journalctl/systemctl escape hatch.
grep -q "sudoers-alderpointdns" "$ROOT/install.out" || {
  echo "installer dry-run did not plan to install the sudoers drop-in" >&2
  exit 1
}
grep -q "sudoers-alderpointdns" "$ROOT/upgrade.out" || {
  echo "upgrade dry-run did not plan to reinstall the sudoers drop-in" >&2
  exit 1
}
for unit in alderpointdns alderpointdns-analytics named dnsdist; do
  grep -q "alderpointdns_compiler.py logs $unit" /opt/alderpointdns/packaging/sudoers-alderpointdns || {
    echo "sudoers drop-in is missing the log-access entry for $unit" >&2
    exit 1
  }
done
if grep -Eq 'ALL=\(root\) NOPASSWD: ALL|alderpointdns_compiler\.py logs \$|alderpointdns_compiler\.py logs \*' /opt/alderpointdns/packaging/sudoers-alderpointdns; then
  echo "sudoers drop-in grants unrestricted or wildcard log access" >&2
  exit 1
fi
visudo -cf /opt/alderpointdns/packaging/sudoers-alderpointdns >/dev/null || {
  echo "sudoers drop-in has invalid syntax" >&2
  exit 1
}

# Automatic filter updates are timer-driven, so a fresh install and an upgrade
# must both plan to install the unit files, and the fresh install must plan to
# enable the timer for the default 1 Day interval. These are static checks on
# the dry-run plan and packaged files; nothing here touches live units.
for unit_file in alderpointdns-filter-update.service alderpointdns-filter-update.timer; do
  grep -q "$unit_file" "$ROOT/install.out" || {
    echo "installer dry-run did not plan to install $unit_file" >&2
    exit 1
  }
  grep -q "$unit_file" "$ROOT/upgrade.out" || {
    echo "upgrade dry-run did not plan to reinstall $unit_file" >&2
    exit 1
  }
done
grep -q "enable alderpointdns-filter-update.timer" "$ROOT/install.out" || {
  echo "installer dry-run did not plan to enable the filter update timer" >&2
  exit 1
}
grep -q "ExecStart=/opt/alderpointdns/app/alderpointdns_compiler.py filter-update-run" \
  /opt/alderpointdns/packaging/alderpointdns-filter-update.service || {
  echo "filter update service unit does not run the filter-update-run subcommand" >&2
  exit 1
}
for expected in "OnUnitActiveSec=24h" "Persistent=true" "WantedBy=timers.target"; do
  grep -q "$expected" /opt/alderpointdns/packaging/alderpointdns-filter-update.timer || {
    echo "filter update timer unit is missing $expected" >&2
    exit 1
  }
done
for entry in filter-schedule-deploy filter-update-run; do
  grep -q "alderpointdns_compiler.py $entry" /opt/alderpointdns/packaging/sudoers-alderpointdns || {
    echo "sudoers drop-in is missing the $entry entry" >&2
    exit 1
  }
done
if grep -Eq 'filter-(schedule-deploy|update-run) +[^,]' /opt/alderpointdns/packaging/sudoers-alderpointdns; then
  echo "sudoers drop-in grants wildcard or argument-taking filter schedule access" >&2
  exit 1
fi
grep -q "alderpointdns-filter-update.timer" /opt/alderpointdns/packaging/debian/prerm || {
  echo "debian prerm does not stop the filter update timer" >&2
  exit 1
}
grep -q "alderpointdns-filter-update.timer.d" /opt/alderpointdns/packaging/debian/postrm || {
  echo "debian purge does not clean the filter update timer drop-in directory" >&2
  exit 1
}
grep -q "Filter Update Interval" /opt/alderpointdns/docs/configuration.md || {
  echo "configuration documentation missing the Filter Update Interval section" >&2
  exit 1
}

/opt/alderpointdns/scripts/alderpointdns-diagnostics --self-test-redaction > "$ROOT/redaction.out"
if grep -Eq 'hunter2|abcdef|secret&client|BEGIN PRIVATE KEY|x-api-key: secret' "$ROOT/redaction.out"; then
  echo "diagnostics redaction self-test leaked secret text" >&2
  exit 1
fi

/opt/alderpointdns/scripts/alderpointdns-diagnostics --output-dir "$ROOT" --no-journal > "$ROOT/bundle-path.txt"
BUNDLE="$(cat "$ROOT/bundle-path.txt")"
test -f "$BUNDLE" || {
  echo "diagnostics bundle was not created" >&2
  exit 1
}
tar -tzf "$BUNDLE" | grep -q 'alderpointdns-diagnostics/summary.json' || {
  echo "diagnostics bundle missing summary" >&2
  exit 1
}
tar -tzf "$BUNDLE" | grep -q 'alderpointdns-diagnostics/database_schema.json' || {
  echo "diagnostics bundle missing schema summary" >&2
  exit 1
}
if tar -xOzf "$BUNDLE" | grep -Eq 'BEGIN PRIVATE KEY|ALDERPOINTDNS_SESSION_SECRET|dnsdist-api.key|Authorization: Basic [A-Za-z0-9+/=]'; then
  echo "diagnostics bundle leaked secret-like content" >&2
  exit 1
fi
if tar -xOzf "$BUNDLE" | grep -Ei 'secret "[^"]{8,}"' | grep -qv '\[REDACTED\]'; then
  echo "diagnostics bundle leaked an unredacted BIND key secret (e.g. rndc-key)" >&2
  exit 1
fi

# The recent-warnings journal excerpt must be scoped to the current boot
# (`journalctl -b`), not just the last N lines: an unscoped "-n 80" can
# still surface warning-level lines from before a rename/cleanup if the
# unit hasn't logged 80 fresh warnings since boot, which would leak
# pre-cleanup identifiers (old hostname, old account name) into a bundle
# generated after a clean reboot.
grep -Eq 'journalctl", "-u", unit, "-b", "-p", "warning"' /opt/alderpointdns/scripts/alderpointdns-diagnostics || {
  echo "diagnostics recent-warnings journal excerpt is not scoped to the current boot (-b)" >&2
  exit 1
}

test -f /opt/alderpointdns/packaging/debian/control || {
  echo "debian control file missing" >&2
  exit 1
}
/opt/alderpointdns/scripts/build-deb.sh --output-dir "$ROOT" > "$ROOT/deb-path.txt"
DEB="$(cat "$ROOT/deb-path.txt")"
test -f "$DEB" || {
  echo "test deb package was not created" >&2
  exit 1
}
dpkg-deb --info "$DEB" | grep -q "Package: alderpointdns" || {
  echo "test deb package metadata is invalid" >&2
  exit 1
}
grep -q "normal uninstall must not destroy persistent data" /opt/alderpointdns/docs/packaging.md || {
  echo "packaging documentation missing persistent-data statement" >&2
  exit 1
}

echo "install, upgrade, and diagnostics tests passed"
