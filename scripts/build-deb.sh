#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: build-deb.sh [--output-dir DIR]

Build a local test .deb with dpkg-deb. This is for isolated package-content
validation before the full debhelper/repository release pipeline is wired up.
EOF
}

OUTPUT_DIR="/tmp"
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
VERSION="$(cat "$SOURCE_DIR/VERSION")"

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

WORK="$(mktemp -d /tmp/bindguard-deb-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PKG="$WORK/bindguard"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/bindguard" "$PKG/usr/sbin" "$PKG/lib/systemd/system" "$PKG/etc/sudoers.d"

cat > "$PKG/DEBIAN/control" <<EOF
Package: bindguard
Version: ${VERSION}
Section: net
Priority: optional
Architecture: all
Maintainer: BindGuard Maintainers <maintainers@example.invalid>
Depends: bind9, bind9-dnsutils, curl, dnsdist, jq, knot-dnsutils, openssl, python3-aioquic, python3-argon2, python3-dnspython, python3-fastapi, python3-httpx, python3-itsdangerous, python3-jinja2, python3-multipart, python3-openpyxl, python3-yaml, sudo, uvicorn
Description: Private DNS filtering and administration appliance
 BindGuard combines BIND, dnsdist, local DNS records, filtering policy,
 analytics, backup/restore, replication, and encrypted DNS listener controls.
EOF

cp "$SOURCE_DIR/packaging/debian/postinst" "$PKG/DEBIAN/postinst"
cp "$SOURCE_DIR/packaging/debian/prerm" "$PKG/DEBIAN/prerm"
cp "$SOURCE_DIR/packaging/debian/postrm" "$PKG/DEBIAN/postrm"
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"

tar -C "$SOURCE_DIR" \
  --exclude .git --exclude __pycache__ --exclude '*.pyc' --exclude venv \
  -cf - app docs packaging scripts tests web VERSION requirements.txt requirements-debian.txt | \
  tar -C "$PKG/opt/bindguard" -xf -

cp "$SOURCE_DIR/scripts/bindguard-diagnostics" "$PKG/usr/sbin/bindguard-diagnostics"
chmod 0755 "$PKG/usr/sbin/bindguard-diagnostics"
cp "$SOURCE_DIR/packaging/bindguard.service" "$PKG/lib/systemd/system/bindguard.service"
cp "$SOURCE_DIR/packaging/bindguard-analytics.service" "$PKG/lib/systemd/system/bindguard-analytics.service"
cp "$SOURCE_DIR/packaging/bindguard-backup.service" "$PKG/lib/systemd/system/bindguard-backup.service"
cp "$SOURCE_DIR/packaging/bindguard-backup.timer" "$PKG/lib/systemd/system/bindguard-backup.timer"
cp "$SOURCE_DIR/packaging/sudoers-bindguard" "$PKG/etc/sudoers.d/bindguard"
chmod 0440 "$PKG/etc/sudoers.d/bindguard"

mkdir -p "$OUTPUT_DIR"
dpkg-deb --build --root-owner-group "$PKG" "$OUTPUT_DIR/bindguard_${VERSION}_all.deb" >/dev/null
echo "$OUTPUT_DIR/bindguard_${VERSION}_all.deb"
