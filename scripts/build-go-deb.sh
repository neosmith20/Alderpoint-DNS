#!/bin/sh
set -eu

# Builds a candidate .deb for the Go control-plane rewrite
# (go/cmd/alderpointdns-go, go/cmd/apdns-hostagent, go/frontend), from
# whatever commit is currently checked out in the given source tree.
#
# packaging/systemd/*.service + packaging/debian/{postinst,prerm,postrm}
# (2026-08-29) provide real, fresh-install provisioning: a dedicated
# apdns-go-web system user, apdns-hostagent's -allowed-uid resolved to
# that user's real UID at install time (never hardcoded), directory
# ownership/modes, a real self-signed TLS cert generated on first
# install (never overwritten), and unit enable (started only on an
# upgrade of an already-running install, never forced on a fresh one --
# see postinst's own comment for why). What THIS script deliberately
# still does NOT do, unchanged from the prior disclosure (see
# go/PARITY_MATRIX.md's "Software Updates" row): reimplement arbitrary
# `.deb`/`dpkg` package-level self-update execution against a live
# production system -- that was refused as too destructive-capable for
# an unverifiable first cut, and this packaging work doesn't change that
# judgment. The running appliance keeps self-updating its own binary via
# apdns-hostagent's own audited update.check/stage/apply RPCs (verified
# checksum + self-reported version, automatic health-check rollback).
# This .deb is the same kind of versioned, whole-build artifact
# build-v2-deb.sh produces for the Python V2 line -- for archival, for
# diffing against a running instance's self-reported `version`, as the
# payload behind that existing update-apply path, or now, genuinely, as
# a real one-shot `dpkg -i` install path for a brand-new appliance.
#
# Usage: build-go-deb.sh [--source-dir DIR] [--output-dir DIR] [--version VERSION]

usage() {
  cat <<'EOF'
Usage: build-go-deb.sh [--source-dir DIR] [--output-dir DIR] [--version VERSION]

Build a candidate alderpointdns-go .deb with dpkg-deb from --source-dir
(default: this script's own repo root -- whatever commit is currently
checked out there). --version overrides the derived Debian Version field.
EOF
}

OUTPUT_DIR="/tmp"
SOURCE_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DEB_VERSION=""
DEB_ARCH="amd64"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-dir) shift; SOURCE_DIR="$(CDPATH= cd -- "${1:?missing source dir}" && pwd)" ;;
    --output-dir) shift; OUTPUT_DIR="${1:?missing output dir}" ;;
    --version) shift; DEB_VERSION="${1:?missing version}" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v go >/dev/null 2>&1 || { echo "go is required" >&2; exit 1; }

cd "$SOURCE_DIR"
FULL_SHA="$(git rev-parse HEAD)"
SHORT_SHA="$(git rev-parse --short=7 HEAD)"

# Debian upstream-version may not contain the raw commit-message-style
# "-" a bare short SHA is fine on its own, but keep the same "~<tag>"
# pre-release convention the other two build scripts use so this always
# sorts as older than the eventual "2.0.0-1" final release it previews.
if [ -z "$DEB_VERSION" ]; then
  DEB_VERSION="2.0.0~go${SHORT_SHA}-1"
fi

echo "+ building candidate from $SOURCE_DIR @ $FULL_SHA (short $SHORT_SHA)"
echo "+ package version: $DEB_VERSION"

WORK="$(mktemp -d /tmp/alderpointdns-go-deb-build.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PKG="$WORK/alderpointdns-go"
mkdir -p \
  "$PKG/DEBIAN" \
  "$PKG/opt/alderpointdns-go/frontend-dist" \
  "$PKG/opt/alderpointdns-go/schema/migrations" \
  "$PKG/etc/alderpointdns-go" \
  "$PKG/lib/systemd/system" \
  "$PKG/usr/share/doc/alderpointdns-go"

echo "+ installing systemd units + maintainer scripts"
cp "$SOURCE_DIR/packaging/systemd/apdns-hostagent.service" "$PKG/lib/systemd/system/"
cp "$SOURCE_DIR/packaging/systemd/alderpointdns-go.service" "$PKG/lib/systemd/system/"
cp "$SOURCE_DIR/packaging/systemd/alderpointdns-go-healthcheck.service" "$PKG/lib/systemd/system/"
cp "$SOURCE_DIR/packaging/systemd/alderpointdns-go-healthcheck.timer" "$PKG/lib/systemd/system/"
chmod 0644 "$PKG/lib/systemd/system/"*.service "$PKG/lib/systemd/system/"*.timer
for script in postinst prerm postrm; do
  cp "$SOURCE_DIR/packaging/go-deb/$script" "$PKG/DEBIAN/$script"
  chmod 0755 "$PKG/DEBIAN/$script"
  sh -n "$PKG/DEBIAN/$script"
done

echo "+ building frontend"
(cd "$SOURCE_DIR/go/frontend" && npm install >/dev/null && npm run build >/dev/null)

echo "+ building binaries (embedding self-reported version = full commit SHA,"
echo "  matching how scripts/v2/deploy-go-preview.sh versions live deploys)"
GOFLAGS=-mod=mod go build -C "$SOURCE_DIR/go" -buildvcs=false \
  -ldflags "-X main.Version=${FULL_SHA}" \
  -o "$PKG/opt/alderpointdns-go/alderpointdns-go" ./cmd/alderpointdns-go
GOFLAGS=-mod=mod go build -C "$SOURCE_DIR/go" -buildvcs=false \
  -ldflags "-X main.Version=${FULL_SHA}" \
  -o "$PKG/opt/alderpointdns-go/apdns-hostagent" ./cmd/apdns-hostagent

BUILT_VERSION="$("$PKG/opt/alderpointdns-go/alderpointdns-go" version)"
[ "$BUILT_VERSION" = "$FULL_SHA" ] || {
  echo "built binary self-reports '$BUILT_VERSION', expected '$FULL_SHA'" >&2
  exit 1
}

cp -r "$SOURCE_DIR/go/frontend/dist/." "$PKG/opt/alderpointdns-go/frontend-dist/"
cp "$SOURCE_DIR/go/schema/migrations/"*.sql "$PKG/opt/alderpointdns-go/schema/migrations/"

chmod 0755 "$PKG/opt/alderpointdns-go/alderpointdns-go" "$PKG/opt/alderpointdns-go/apdns-hostagent"

cat > "$PKG/DEBIAN/control" <<EOF
Package: alderpointdns-go
Version: ${DEB_VERSION}
Section: net
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: BindGuard Builder <bindguard@localhost>
Depends: dnsdist (>= 1.9.0), bind9, bind9-utils, openssl, adduser, curl, iproute2
Conflicts: alderpointdns, alderpointdns-v2
Description: Alderpoint DNS Go control plane -- CANDIDATE BUILD (not an official release)
 Candidate build of the Go/Svelte control-plane rewrite: alderpointdns-go
 (management API + web UI, static frontend-dist bundle, SQL migrations)
 and apdns-hostagent (privileged host-side helper for BIND/dnsdist
 runtime control and self-update). Built from commit ${FULL_SHA}.
 .
 Real systemd units + postinst provisioning (2026-08-29): installing
 this package creates a dedicated apdns-go-web system account, the
 directories both services need, a self-signed TLS cert for the
 management UI's first boot, and enables (but does not force-start on a
 fresh install) apdns-hostagent.service and alderpointdns-go.service --
 see each unit's own comments. What this package still does NOT do:
 reimplement arbitrary dpkg-level self-update of a live production
 install -- the running appliance keeps self-updating its own binary via
 apdns-hostagent's own audited update.check/stage/apply RPCs (verified
 checksum + self-reported version, automatic health-check rollback).
 This .deb doubles as a versioned whole-build artifact for archival, for
 diffing against a running instance's /api/version, or as the payload
 behind that existing update-apply path.
EOF

cat > "$PKG/DEBIAN/conffiles" <<'EOF'
/etc/alderpointdns-go/appliance.yaml
EOF

# Ship the actual default config template from the source tree so this
# stays in sync with whatever the binary itself expects, rather than a
# hand-maintained copy that can drift.
#
# A real, previously-undisclosed packaging bug fixed here: this checked
# for "appliance.default.yaml", a filename that has never existed
# anywhere in this repo's history -- the real file has always been
# go/config/appliance.yaml (confirmed via `git log --follow`). Every
# prior build of this script has silently hit the "no default config"
# fallback and shipped without /etc/alderpointdns-go/appliance.yaml (and
# without the conffiles entry marking it one) at all, never caught
# because the fallback path degrades quietly instead of failing the
# build.
if [ -f "$SOURCE_DIR/go/config/appliance.yaml" ]; then
  cp "$SOURCE_DIR/go/config/appliance.yaml" "$PKG/etc/alderpointdns-go/appliance.yaml"
else
  echo "no go/config/appliance.yaml found in source tree -- shipping no default config" >&2
  rmdir "$PKG/etc/alderpointdns-go" 2>/dev/null || true
  rm -f "$PKG/DEBIAN/conffiles"
fi

cp "$SOURCE_DIR/LICENSE" "$PKG/usr/share/doc/alderpointdns-go/copyright" 2>/dev/null || true
cat > "$PKG/usr/share/doc/alderpointdns-go/changelog" <<EOF
alderpointdns-go (${DEB_VERSION}) unstable; urgency=low

  * Candidate build from commit ${FULL_SHA}.

 -- BindGuard Builder <bindguard@localhost>
EOF
gzip -9n "$PKG/usr/share/doc/alderpointdns-go/changelog"

mkdir -p "$OUTPUT_DIR"
OUT="$OUTPUT_DIR/alderpointdns-go_${DEB_VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG" "$OUT" >/dev/null
echo "+ built: $OUT"
dpkg-deb --info "$OUT"
dpkg-deb --contents "$OUT"
