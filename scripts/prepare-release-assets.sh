#!/bin/sh
set -eu

usage() {
  cat <<'EOF'
Usage: prepare-release-assets.sh [--output-dir DIR]

Builds the versioned release candidate .deb (via build-deb.sh), then
produces the exact set of assets a GitHub Release should publish:

  alderpointdns_<version>_all.deb   the canonical, immutable versioned package
  alderpointdns_latest_all.deb      a byte-identical COPY of it -- not a
                                     redirect, not an independently rebuilt
                                     package -- so the README's permanent
                                     Quick Start URL
                                     (.../releases/latest/download/alderpointdns_latest_all.deb)
                                     always resolves to something that is
                                     provably the same bytes as that
                                     release's canonical package
  SHA256SUMS                        covers both filenames above; since the
                                     "latest" asset is a byte-identical copy,
                                     both entries carry the same digest

This script does not publish anything -- it only prepares local files for
whoever runs the actual `gh release create`/upload step.
EOF
}

OUTPUT_DIR="/tmp"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) shift; OUTPUT_DIR="${1:?missing output dir}" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p "$OUTPUT_DIR"

VERSIONED_DEB="$("$SCRIPT_DIR/build-deb.sh" --output-dir "$OUTPUT_DIR")"
VERSIONED_NAME="$(basename "$VERSIONED_DEB")"
LATEST_DEB="$OUTPUT_DIR/alderpointdns_latest_all.deb"

# A plain byte-for-byte copy, not a symlink and not a second build:
# a symlink wouldn't survive being uploaded as an independent GitHub
# release asset, and rebuilding would risk a second, non-identical
# artifact (different mtimes/ordering inside the .deb, or -- worse --
# a source-tree change between the two builds) being called "the same
# release". `cp -p` preserves permissions/mtime; the content is what
# actually matters and is verified identical below.
cp -p "$VERSIONED_DEB" "$LATEST_DEB"

if ! cmp -s "$VERSIONED_DEB" "$LATEST_DEB"; then
  echo "prepare-release-assets.sh: alderpointdns_latest_all.deb is not byte-identical to $VERSIONED_NAME" >&2
  exit 1
fi

SUMS_FILE="$OUTPUT_DIR/SHA256SUMS"
(
  cd "$OUTPUT_DIR"
  sha256sum "$VERSIONED_NAME" alderpointdns_latest_all.deb
) > "$SUMS_FILE"

echo "$VERSIONED_DEB"
echo "$LATEST_DEB"
echo "$SUMS_FILE"
