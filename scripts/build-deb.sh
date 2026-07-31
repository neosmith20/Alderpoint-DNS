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
# The VERSION file uses semver-style pre-release tags (e.g. 0.4.0-beta.2) for
# release notes/UI display, but Debian's version syntax treats the *last*
# hyphen as the start of the debian_revision, so passing that string through
# unchanged would make dpkg parse "0.4.0-beta.2" as upstream "0.4.0-beta"
# revision "2". Derive the conventional Debian pre-release form instead
# (0.4.0~beta2-1), matching packaging/debian/changelog.
DEB_VERSION="$(printf '%s' "$VERSION" | sed -E 's/-beta\.([0-9]+)/~beta\1/')-1"

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

WORK="$(mktemp -d /tmp/alderpointdns-deb-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PKG="$WORK/alderpointdns"
mkdir -p "$PKG/DEBIAN" "$PKG/opt/alderpointdns" "$PKG/usr/sbin" "$PKG/lib/systemd/system" "$PKG/etc/sudoers.d" "$PKG/usr/share/doc/alderpointdns"

cat > "$PKG/DEBIAN/control" <<EOF
Package: alderpointdns
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: all
Maintainer: Alderpoint DNS Maintainers <maintainers@example.invalid>
Depends: bind9, bind9-dnsutils, curl, dnsdist (>= 1.9.0), jq, knot-dnsutils, openssl, python3-aioquic, python3-argon2, python3-dnspython, python3-fastapi, python3-httpx, python3-itsdangerous, python3-jinja2, python3-multipart, python3-openpyxl, python3-yaml, sudo, uvicorn
Description: Private DNS filtering and administration appliance
 Alderpoint DNS combines BIND, dnsdist, local DNS records, filtering policy,
 analytics, backup/restore, replication, and encrypted DNS listener controls.
EOF

cp "$SOURCE_DIR/packaging/debian/postinst" "$PKG/DEBIAN/postinst"
cp "$SOURCE_DIR/packaging/debian/prerm" "$PKG/DEBIAN/prerm"
cp "$SOURCE_DIR/packaging/debian/postrm" "$PKG/DEBIAN/postrm"
chmod 0755 "$PKG/DEBIAN/postinst" "$PKG/DEBIAN/prerm" "$PKG/DEBIAN/postrm"

tar -C "$SOURCE_DIR" \
  --exclude .git --exclude __pycache__ --exclude '*.pyc' --exclude venv \
  -cf - app docs packaging scripts tests web VERSION requirements.txt requirements-debian.txt | \
  tar -C "$PKG/opt/alderpointdns" -xf -

cp "$SOURCE_DIR/scripts/alderpointdns-diagnostics" "$PKG/usr/sbin/alderpointdns-diagnostics"
chmod 0755 "$PKG/usr/sbin/alderpointdns-diagnostics"
cp "$SOURCE_DIR/scripts/alderpointdns-admin" "$PKG/usr/sbin/alderpointdns"
chmod 0755 "$PKG/usr/sbin/alderpointdns"
cp "$SOURCE_DIR/packaging/alderpointdns.service" "$PKG/lib/systemd/system/alderpointdns.service"
cp "$SOURCE_DIR/packaging/alderpointdns-analytics.service" "$PKG/lib/systemd/system/alderpointdns-analytics.service"
cp "$SOURCE_DIR/packaging/alderpointdns-backup.service" "$PKG/lib/systemd/system/alderpointdns-backup.service"
cp "$SOURCE_DIR/packaging/alderpointdns-backup.timer" "$PKG/lib/systemd/system/alderpointdns-backup.timer"
cp "$SOURCE_DIR/packaging/alderpointdns-filter-update.service" "$PKG/lib/systemd/system/alderpointdns-filter-update.service"
cp "$SOURCE_DIR/packaging/alderpointdns-filter-update.timer" "$PKG/lib/systemd/system/alderpointdns-filter-update.timer"
cp "$SOURCE_DIR/packaging/alderpointdns-notify.service" "$PKG/lib/systemd/system/alderpointdns-notify.service"
cp "$SOURCE_DIR/packaging/alderpointdns-notify.timer" "$PKG/lib/systemd/system/alderpointdns-notify.timer"
cp "$SOURCE_DIR/packaging/sudoers-alderpointdns" "$PKG/etc/sudoers.d/alderpointdns"
chmod 0440 "$PKG/etc/sudoers.d/alderpointdns"

# License/copyright/legal docs, installed under the standard Debian
# documentation path. "copyright" (lowercase, no extension) is the
# conventional filename apt frontends and packaging tools look for at
# /usr/share/doc/<pkg>/copyright; the rest are shipped alongside it for
# completeness. Package metadata otherwise has no "License:" field (not
# a standard Debian control field) -- this is the actual authoritative
# location for licensing information in the built package.
cp "$SOURCE_DIR/LICENSE" "$PKG/usr/share/doc/alderpointdns/LICENSE"
cp "$SOURCE_DIR/COPYRIGHT" "$PKG/usr/share/doc/alderpointdns/copyright"
cp "$SOURCE_DIR/COMMERCIAL_LICENSING.md" "$PKG/usr/share/doc/alderpointdns/COMMERCIAL_LICENSING.md"
cp "$SOURCE_DIR/THIRD_PARTY_NOTICES.md" "$PKG/usr/share/doc/alderpointdns/THIRD_PARTY_NOTICES.md"
cp "$SOURCE_DIR/TRADEMARKS.md" "$PKG/usr/share/doc/alderpointdns/TRADEMARKS.md"
chmod 0644 "$PKG/usr/share/doc/alderpointdns/"*

mkdir -p "$OUTPUT_DIR"
dpkg-deb --build --root-owner-group "$PKG" "$OUTPUT_DIR/alderpointdns_${DEB_VERSION}_all.deb" >/dev/null
echo "$OUTPUT_DIR/alderpointdns_${DEB_VERSION}_all.deb"
