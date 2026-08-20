#!/bin/sh
set -eu

# Builds the PRIVATE Alderpoint DNS V2 candidate .deb (Workstream 4A).
# Mirrors the proven dpkg-deb pattern already used and tested for V1
# (scripts/build-deb.sh, tests/test_clean_install_container.sh,
# tests/test_deb_package_contents.sh) but produces a completely separate
# package, "alderpointdns-v2": own namespace (/opt/alderpointdns-v2,
# /etc/alderpointdns-v2, /var/lib/alderpointdns-v2, /var/log/alderpointdns-v2,
# alderpointdns-v2 user/group, alderpointdns-v2-* systemd units), so
# building/installing it can never interact with the live V1
# "alderpointdns" package or appliance.
#
# Only app/__init__.py + app/v2/ ship, with one deliberate, documented
# exception: app/dnsdist_upgrade.py (a standalone, stdlib-only, root-only
# opt-in dnsdist-repository installer with no V1 app/web-code dependency)
# -- see docs/v2/packaging.md and docs/v2/doh3-transport-implemented.md.
# Plus the vendored analytics wheels and the new V2 ctl script/systemd
# units/provisioning script. No other V1 application code, no V1 web/
# assets, no V1 systemd units.

usage() {
  cat <<'EOF'
Usage: build-v2-deb.sh [--output-dir DIR]

Build the private Alderpoint DNS V2 candidate .deb with dpkg-deb.
EOF
}

OUTPUT_DIR="/tmp"
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
# Private candidate versioning, independent of V1's VERSION file --
# Workstream 4A explicitly permits "internal/private versioning...
# appropriate to this branch." 2.0.0~privateN-1: "~" sorts before the
# final 2.0.0-1 this candidate is a pre-release of, same convention V1's
# own build-deb.sh already uses for beta/dev/rc tags.
DEB_VERSION="2.0.0~rc44-1"
# Real defect closed (beta-rescue pass): this package was declared
# "Architecture: all" (built once, installs on any architecture) but
# vendor/v2-analytics/ ships REAL architecture-specific binary payloads
# -- pyarrow/duckdb wheels built for CPython 3.13 on x86_64
# (manylinux_2_28_x86_64) -- which is only accurate metadata for amd64.
# V1's own package (scripts/build-deb.sh) legitimately stays
# "Architecture: all": its own vendor/ directory carries only a
# py3-none-any wheel, no compiled extension. Determined from current
# project requirements: V2 is only built/tested for x86_64 as of this
# pass, so this reflects real support, not an ARM claim this project
# cannot back up (dpkg's own architecture name for that target is
# "amd64", not the Rust/LLVM-style "x86_64").
DEB_ARCH="amd64"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) shift; OUTPUT_DIR="${1:?missing output dir}" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

command -v dpkg-deb >/dev/null 2>&1 || {
  echo "dpkg-deb is required" >&2
  exit 1
}

WORK="$(mktemp -d /tmp/alderpointdns-v2-deb-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PKG="$WORK/alderpointdns-v2"
mkdir -p \
  "$PKG/DEBIAN" \
  "$PKG/opt/alderpointdns-v2/app" \
  "$PKG/opt/alderpointdns-v2/vendor" \
  "$PKG/opt/alderpointdns-v2/scripts/v2" \
  "$PKG/opt/alderpointdns-v2/packaging" \
  "$PKG/lib/systemd/system" \
  "$PKG/usr/share/doc/alderpointdns-v2"

# Real defect found live during RC24 clean-install acceptance testing:
# alderpointdns-v2-ctl install-enhanced-dnsdist (app/dnsdist_upgrade.py,
# reused verbatim from V1 -- see docs/v2/doh3-transport-implemented.md)
# calls `gpg` to verify the PowerDNS signing-key fingerprint and `dig`
# to verify functional resolution after the upgrade, but neither
# gnupg nor bind9-dnsutils (the Debian package providing `dig`, distinct
# from bind9-utils) were declared below -- confirmed live: a fresh
# clean-install container had `curl` (pulled in transitively) but not
# `gpg`, and the command failed outright with a clear, fail-closed
# error and automatic rollback (not a silent partial state), but should
# never have been reachable in the first place on a stock install. V1's
# own packaging/debian/control already carries the same two
# dependencies for the identical reason (see its own Depends line and
# packaging/debian/changelog's "gnupg dependency required by
# install-enhanced-dnsdist" entry) -- V2 simply hadn't picked it up yet.
cat > "$PKG/DEBIAN/control" <<EOF
Package: alderpointdns-v2
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Alderpoint DNS Maintainers <maintainers@example.invalid>
Depends: dnsdist (>= 1.9.0), bind9, bind9-utils, bind9-dnsutils, curl, gnupg, python3 (>= 3.11), python3-argon2, python3-cryptography, python3-yaml, python3-pip, python3-fastapi, python3-itsdangerous, python3-pydantic, python3-openpyxl, uvicorn, sqlite3
Conflicts: alderpointdns
Description: Alderpoint DNS V2 -- PRIVATE RELEASE CANDIDATE (not for production)
 Private, pre-release Workstream 4A/4B packaging of Alderpoint DNS V2.
 Ships the V2 policy/analytics/migration engine, the analytics vendor
 runtime (pyarrow/duckdb), background services (analytics ingestion, Tier B
 prewarm, schedule transitions, native HTTPS management UI/API, replication,
 discovery, an observation-only DNS packet ingress on alternate port 1053),
 a packaged V2 dnsdist runtime and a packaged, isolated V2 BIND
 recursive-cache backend reading only the promoted V2 compiled
 configuration (client -> dnsdist packet cache -> compiled policy/routing
 -> BIND RAM recursive cache -> upstream, per docs/v2/architecture-map.md's
 locked hot path), and self-signed TLS bootstrap.
 Never install alongside the V1 "alderpointdns" package on the same host
 that package is serving traffic from -- V2's own BIND instance uses
 entirely disjoint ports/paths from V1's, but the two packages Conflict
 regardless.
EOF
# Conflicts: alderpointdns is deliberate belt-and-suspenders (Workstream
# 4A safety constraint: "DO NOT INSTALL THE V2 PACKAGE ON THE HOST") --
# even though the two packages' paths/users/units never collide by
# construction, this makes it impossible for apt to ever co-install them
# on the same system by accident.

cp "$SOURCE_DIR/packaging/v2/postinst" "$PKG/DEBIAN/postinst"
cp "$SOURCE_DIR/packaging/v2/preinst" "$PKG/DEBIAN/preinst"
cp "$SOURCE_DIR/packaging/v2/prerm" "$PKG/DEBIAN/prerm"
cp "$SOURCE_DIR/packaging/v2/postrm" "$PKG/DEBIAN/postrm"
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/preinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"

cp "$SOURCE_DIR/app/__init__.py" "$PKG/opt/alderpointdns-v2/app/__init__.py"
# app/dnsdist_upgrade.py is the one deliberate exception to "only
# app/v2/ ships" (see this script's header comment): it's a standalone,
# stdlib-only, root-only opt-in dnsdist-repository installer with no V1
# app/web-code dependency (confirmed by inspection -- its own imports
# are all stdlib). V2 reuses it verbatim rather than duplicating it, for
# both `app/v2/webapp.py`'s real dnsdist-capability reporting
# (GET /api/dns-transports) and `alderpointdns-v2-ctl install-enhanced-
# dnsdist`/`dnsdist-capabilities` -- see docs/v2/doh3-transport-
# implemented.md.
cp "$SOURCE_DIR/app/dnsdist_upgrade.py" "$PKG/opt/alderpointdns-v2/app/dnsdist_upgrade.py"
# Second deliberate exception to "only app/v2/ ships" (see this
# script's header comment): app/db_retry.py is a standalone,
# stdlib-only SQLite busy/locked retry helper with no V1 app/web-code
# dependency, reused verbatim for the real defect fix in
# docs/v2/login-database-locked-under-load-fix.md (a real "database is
# locked" crash under real combined DNS+login load) rather than
# reimplementing V1's own already-proven pattern.
cp "$SOURCE_DIR/app/db_retry.py" "$PKG/opt/alderpointdns-v2/app/db_retry.py"
# Beta-rescue priority 2 (Import): app/v2/import_migration.py
# deliberately reuses V1's mature, already-tested, source-format-shaped
# parsing/rule-classification functions (parse_adguard_yaml,
# fetch_adguard_api, parse_pihole_text, parse_hosts_text, parse_zone_text,
# parse_alderpointdns_csv/native_json, parse_xlsx_bytes, custom_rules.
# parse_rule) rather than reimplementing them -- see that module's own
# docstring. Those functions live in app/importer.py + app/custom_rules.py,
# which import app/local_dns.py, app/upstream_dns.py, and app/clients.py
# at module scope. All five are shipped here as further deliberate,
# documented exceptions to "only app/v2/ ships": confirmed by AST
# inspection to have no dangerous module-level side effects (no DB
# connection opened at import time), and V2 code only ever calls their
# pure parsing functions -- never any of their DB-mutating entry points,
# never their own DB_PATH/connect() helpers. This does not reintroduce
# V1 storage/runtime architecture: V2 still only ever writes through its
# own control.db/policy_store schema (see import_migration.py's own
# apply layer).
cp "$SOURCE_DIR/app/local_dns.py" "$PKG/opt/alderpointdns-v2/app/local_dns.py"
cp "$SOURCE_DIR/app/upstream_dns.py" "$PKG/opt/alderpointdns-v2/app/upstream_dns.py"
cp "$SOURCE_DIR/app/clients.py" "$PKG/opt/alderpointdns-v2/app/clients.py"
cp "$SOURCE_DIR/app/importer.py" "$PKG/opt/alderpointdns-v2/app/importer.py"
cp "$SOURCE_DIR/app/custom_rules.py" "$PKG/opt/alderpointdns-v2/app/custom_rules.py"
# Transitive module-scope imports of the above (app/local_dns.py and
# app/upstream_dns.py both import app.service_logs; app/software_updates.py
# below imports app.backup, which itself only needs app.upstream_dns +
# app.service_logs -- no further cascade, confirmed by inspection).
cp "$SOURCE_DIR/app/service_logs.py" "$PKG/opt/alderpointdns-v2/app/service_logs.py"
cp "$SOURCE_DIR/app/backup.py" "$PKG/opt/alderpointdns-v2/app/backup.py"
# Beta-rescue priority 4 (Software Updates): app/v2/software_updates.py
# similarly reuses V1's already-tested, source-agnostic package-
# inspection primitives (inspect_deb, dpkg_compare, sha256_file,
# source_version_to_deb_form) from app/software_updates.py -- confirmed
# by AST inspection to have no dangerous module-level side effects.
# V2's own channel/job/apply logic is implemented from scratch (see that
# module's own docstring); only the low-level, tool-wrapping functions
# are reused.
cp "$SOURCE_DIR/app/software_updates.py" "$PKG/opt/alderpointdns-v2/app/software_updates.py"
tar -C "$SOURCE_DIR" --exclude __pycache__ --exclude '*.pyc' -cf - app/v2 | \
  tar -C "$PKG/opt/alderpointdns-v2" -xf -
tar -C "$SOURCE_DIR" -cf - vendor/v2-analytics | \
  tar -C "$PKG/opt/alderpointdns-v2" -xf -
cp "$SOURCE_DIR/scripts/v2/alderpointdns_v2_ctl.py" "$PKG/opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_ctl.py"
cp "$SOURCE_DIR/scripts/provision-v2-analytics-vendor-runtime.sh" "$PKG/opt/alderpointdns-v2/scripts/provision-v2-analytics-vendor-runtime.sh"
chmod 0755 "$PKG/opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_ctl.py" "$PKG/opt/alderpointdns-v2/scripts/provision-v2-analytics-vendor-runtime.sh"

cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-analytics.service" "$PKG/lib/systemd/system/alderpointdns-v2-analytics.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-tierb.service" "$PKG/lib/systemd/system/alderpointdns-v2-tierb.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-schedule.service" "$PKG/lib/systemd/system/alderpointdns-v2-schedule.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-web.service" "$PKG/lib/systemd/system/alderpointdns-v2-web.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-discovery.service" "$PKG/lib/systemd/system/alderpointdns-v2-discovery.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-analytics-protobuf-receiver.service" "$PKG/lib/systemd/system/alderpointdns-v2-analytics-protobuf-receiver.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-dns-observer.service" "$PKG/lib/systemd/system/alderpointdns-v2-dns-observer.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-replication.service" "$PKG/lib/systemd/system/alderpointdns-v2-replication.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-dnsdist.service" "$PKG/lib/systemd/system/alderpointdns-v2-dnsdist.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-dnsdist-reload.service" "$PKG/lib/systemd/system/alderpointdns-v2-dnsdist-reload.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-dnsdist-reload.path" "$PKG/lib/systemd/system/alderpointdns-v2-dnsdist-reload.path"
# Software Updates privileged apply helper (beta-rescue priority 4): the
# same watch-a-marker-file/oneshot-root-service pattern as the dnsdist
# reload above, so the unprivileged web process never gains apt/root
# access itself. See app/v2/software_updates.py + scripts/v2/
# alderpointdns_v2_update_apply.py.
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-update-apply.service" "$PKG/lib/systemd/system/alderpointdns-v2-update-apply.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-update-apply.path" "$PKG/lib/systemd/system/alderpointdns-v2-update-apply.path"
cp "$SOURCE_DIR/scripts/v2/alderpointdns_v2_update_apply.py" "$PKG/opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_update_apply.py"
chmod 0755 "$PKG/opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_update_apply.py"
# Subscribed Blocklists periodic refresh (beta-rescue priority 3B): same
# unprivileged account as the web service, no new privilege.
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-blocklist-refresh.service" "$PKG/lib/systemd/system/alderpointdns-v2-blocklist-refresh.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-blocklist-refresh.timer" "$PKG/lib/systemd/system/alderpointdns-v2-blocklist-refresh.timer"
cp "$SOURCE_DIR/scripts/v2/alderpointdns_v2_blocklist_refresh.py" "$PKG/opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_blocklist_refresh.py"
chmod 0755 "$PKG/opt/alderpointdns-v2/scripts/v2/alderpointdns_v2_blocklist_refresh.py"
# BIND architecture correction (Gate #3): the real packaged V2 BIND
# recursive-cache backend unit + its AppArmor local override (see
# packaging/v2/postinst's own apparmor block for why this must be
# appended to the shared /etc/apparmor.d/local/usr.sbin.named file, not
# a standalone V2-only profile -- apparmor's usr.sbin.named profile is
# keyed by binary path, and V1/V2 both run /usr/sbin/named).
# Multi-context BIND (Gate #3 acceptance closure): a systemd TEMPLATE
# unit, one real named process per distinct plain upstream selection --
# see app/v2/bind_gen.py's own module docstring on why this is
# port-based (one process per context) rather than one process with
# multiple views/loopback aliases (that design was tried live and found
# to need CAP_NET_ADMIN loopback-alias provisioning the live
# management-API's own unprivileged runtime user does not have).
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-bind@.service" "$PKG/lib/systemd/system/alderpointdns-v2-bind@.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-doh-egress@.service" "$PKG/lib/systemd/system/alderpointdns-v2-doh-egress@.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-bind-reload.service" "$PKG/lib/systemd/system/alderpointdns-v2-bind-reload.service"
cp "$SOURCE_DIR/packaging/v2/alderpointdns-v2-bind-reload.path" "$PKG/lib/systemd/system/alderpointdns-v2-bind-reload.path"
cp "$SOURCE_DIR/packaging/v2/apparmor-named-v2.local" "$PKG/opt/alderpointdns-v2/packaging/apparmor-named-v2.local"

cp "$SOURCE_DIR/LICENSE" "$PKG/usr/share/doc/alderpointdns-v2/LICENSE"
cp "$SOURCE_DIR/COPYRIGHT" "$PKG/usr/share/doc/alderpointdns-v2/copyright"
chmod 0644 "$PKG/usr/share/doc/alderpointdns-v2/"*

# Real build-reproducibility defect found and fixed live during Gate #3
# artifact recovery: every file above is staged via plain `cp`, which
# stamps each file's mtime with the wall-clock time the build happened
# to run at, not any value derived from the source itself. dpkg-deb
# --build preserves those mtimes into control.tar.xz/data.tar.xz, so
# two builds of the exact same source commit produced byte-identical
# *content* (confirmed: `diff -rq` between two consecutive rebuilds'
# extracted trees found zero differences) but different final .deb
# SHA-256 hashes purely from mtime drift -- meaning the single
# artifact Dex Gate #3 review depends on could never be reproduced or
# independently re-verified from source alone. Fixed the standard
# reproducible-builds way: every staged file's mtime is normalized to
# SOURCE_DATE_EPOCH (https://reproducible-builds.org/specs/source-date-epoch/),
# derived from the exact source commit being built (its own commit
# timestamp) rather than a build-time value -- so the same source SHA
# always produces the same mtimes, and (verified) the same final
# package hash, regardless of when or how many times it's built.
#
# Normalizing the staged files' own mtimes (above) was NOT sufficient
# by itself -- confirmed live: after that fix alone, two consecutive
# builds' inner control.tar.xz/data.tar.xz/debian-binary members were
# already byte-identical (verified via direct sha256sum of each
# extracted ar member), but the two final .deb files still differed.
# Root cause: dpkg-deb --build separately stamps the *outer* ar(5)
# container's own per-member timestamp with the real build wall-clock
# time, independent of the inner tar mtimes. dpkg-deb (>= 1.18.8)
# natively honors the same SOURCE_DATE_EPOCH environment variable for
# exactly this -- both "the timestamp in the deb's ar(5) container"
# and "clamp the mtime in the tar(5) file entries" per dpkg-deb(1) --
# so exporting it here is the complete, correct fix; the explicit
# find/touch above is kept anyway as an explicit, easy-to-audit
# statement of intent, not load-bearing on its own.
SOURCE_DATE_EPOCH="$(cd "$SOURCE_DIR" && git log -1 --format=%ct HEAD 2>/dev/null || echo 0)"
find "$PKG" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
export SOURCE_DATE_EPOCH

mkdir -p "$OUTPUT_DIR"
dpkg-deb --build --root-owner-group "$PKG" "$OUTPUT_DIR/alderpointdns-v2_${DEB_VERSION}_${DEB_ARCH}.deb" >/dev/null
echo "$OUTPUT_DIR/alderpointdns-v2_${DEB_VERSION}_${DEB_ARCH}.deb"
