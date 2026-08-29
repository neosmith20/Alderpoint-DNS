#!/bin/sh
set -eu

# Builds a candidate .deb for the Go control-plane rewrite
# (go/cmd/alderpointdns-go, go/cmd/apdns-hostagent, go/frontend), from
# whatever commit is currently checked out in the given source tree.
#
# Scope note (see go/PARITY_MATRIX.md, "Software Updates" row): full
# production dpkg packaging (systemd units, postinst service
# provisioning, dedicated system user) for this control plane has been
# deliberately NOT built yet -- the appliance instead self-updates its
# own binary via apdns-hostagent's update.check/stage/apply RPCs. This
# script does not invent that packaging; it produces the same kind of
# harmless, content-addressable candidate artifact build-v2-deb.sh
# produces for the Python V2 line -- useful for archival, diffing
# against a running instance's self-reported `version`, or as a real
# candidate for the existing apdns-hostagent update-apply path (which
# only requires a binary + checksum, not a .deb at all, but a .deb is a
# convenient, versioned way to store/ship the whole build together).
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
  "$PKG/usr/share/doc/alderpointdns-go"

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
Maintainer: Alderpoint DNS Maintainers <maintainers@example.invalid>
Depends: dnsdist (>= 1.9.0), bind9, bind9-utils
Conflicts: alderpointdns, alderpointdns-v2
Description: Alderpoint DNS Go control plane -- CANDIDATE BUILD (not a production install)
 Candidate build of the Go/Svelte control-plane rewrite: alderpointdns-go
 (management API + web UI, static frontend-dist bundle, SQL migrations)
 and apdns-hostagent (privileged host-side helper for BIND/dnsdist
 runtime control and self-update). Built from commit ${FULL_SHA}.
 .
 This package intentionally ships NO systemd units and NO postinst
 service provisioning: production install automation for this control
 plane has not been built yet (see go/PARITY_MATRIX.md's "Software
 Updates" row) -- the running appliance instead self-updates its own
 binary via apdns-hostagent's update.check/stage/apply RPCs, which
 verify a staged binary's checksum and self-reported version before
 trusting it. This .deb exists to carry a whole matched build (web
 binary + hostagent + frontend + migrations, all from one commit) as a
 single versioned artifact -- for archival, for diffing against a
 running instance's /api/version, or as the payload behind that
 existing update-apply path. Installing it only places files under
 /opt/alderpointdns-go and /etc/alderpointdns-go; nothing is started.
EOF

cat > "$PKG/DEBIAN/conffiles" <<'EOF'
/etc/alderpointdns-go/appliance.yaml
EOF

# Ship the actual default config template from the source tree so this
# stays in sync with whatever the binary itself expects, rather than a
# hand-maintained copy that can drift.
if [ -f "$SOURCE_DIR/go/config/appliance.default.yaml" ]; then
  cp "$SOURCE_DIR/go/config/appliance.default.yaml" "$PKG/etc/alderpointdns-go/appliance.yaml"
else
  echo "no go/config/appliance.default.yaml found in source tree -- shipping no default config" >&2
  rmdir "$PKG/etc/alderpointdns-go" 2>/dev/null || true
  rm -f "$PKG/DEBIAN/conffiles"
fi

cp "$SOURCE_DIR/LICENSE" "$PKG/usr/share/doc/alderpointdns-go/copyright" 2>/dev/null || true
cat > "$PKG/usr/share/doc/alderpointdns-go/changelog" <<EOF
alderpointdns-go (${DEB_VERSION}) unstable; urgency=low

  * Candidate build from commit ${FULL_SHA}.

 -- Alderpoint DNS Maintainers <maintainers@example.invalid>
EOF
gzip -9n "$PKG/usr/share/doc/alderpointdns-go/changelog"

mkdir -p "$OUTPUT_DIR"
OUT="$OUTPUT_DIR/alderpointdns-go_${DEB_VERSION}_${DEB_ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKG" "$OUT" >/dev/null
echo "+ built: $OUT"
dpkg-deb --info "$OUT"
dpkg-deb --contents "$OUT"
