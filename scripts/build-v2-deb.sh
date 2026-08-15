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
# Only app/__init__.py + app/v2/ ship (confirmed by inspection: no
# app/v2/*.py imports any top-level app/*.py module -- see
# docs/v2/packaging.md), plus the vendored analytics wheels and the new
# V2 ctl script/systemd units/provisioning script. No V1 application code,
# no V1 web/ assets, no V1 systemd units.

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
DEB_VERSION="2.0.0~private2-1"

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
  "$PKG/lib/systemd/system" \
  "$PKG/usr/share/doc/alderpointdns-v2"

cat > "$PKG/DEBIAN/control" <<EOF
Package: alderpointdns-v2
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: all
Maintainer: Alderpoint DNS Maintainers <maintainers@example.invalid>
Depends: dnsdist (>= 1.9.0), bind9-utils, python3 (>= 3.11), python3-argon2, python3-cryptography, python3-yaml, python3-pip, python3-fastapi, python3-itsdangerous, python3-pydantic, uvicorn, sqlite3
Conflicts: alderpointdns
Description: Alderpoint DNS V2 -- PRIVATE RELEASE CANDIDATE (not for production)
 Private, pre-release Workstream 4A/4B packaging of Alderpoint DNS V2.
 Ships the V2 policy/analytics/migration engine, the analytics vendor
 runtime (pyarrow/duckdb), four background services (analytics ingestion,
 Tier B prewarm, schedule transitions, and a real native-HTTPS management/
 API service), and self-signed TLS bootstrap. Does NOT ship or manage a
 live authoritative dnsdist/BIND listener or a UI -- V2 is not yet
 authoritative. Never install alongside the V1 "alderpointdns" package on
 the same host that package is serving traffic from.
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

cp "$SOURCE_DIR/LICENSE" "$PKG/usr/share/doc/alderpointdns-v2/LICENSE"
cp "$SOURCE_DIR/COPYRIGHT" "$PKG/usr/share/doc/alderpointdns-v2/copyright"
chmod 0644 "$PKG/usr/share/doc/alderpointdns-v2/"*

mkdir -p "$OUTPUT_DIR"
dpkg-deb --build --root-owner-group "$PKG" "$OUTPUT_DIR/alderpointdns-v2_${DEB_VERSION}_all.deb" >/dev/null
echo "$OUTPUT_DIR/alderpointdns-v2_${DEB_VERSION}_all.deb"
