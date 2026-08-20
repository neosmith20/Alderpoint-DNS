#!/bin/sh
set -eu

# Publishes a built V2 private release-candidate .deb (plus its evidence
# manifest) into the private RC archive with private-by-default
# permissions, explicitly -- independent of whatever umask the calling
# shell/session happens to have.
#
# This script is NOT packaged: build-v2-deb.sh only ever copies an
# explicit whitelist of files into the .deb it builds, and this script
# is not on that list. It exists purely as private acceptance-workflow
# tooling and must never be referenced from packaging/v2/* or from
# build-v2-deb.sh's copy list.
#
# Root cause this exists to prevent: RC37-RC41 were published by hand
# under the caller's ambient umask (0022), so their directories and
# manifests silently became group/world-readable (755/644) instead of
# the private 700/600 every earlier RC (RC30-RC36) had under an
# explicit umask 077. This script pins the private posture at publish
# time so a future session's ambient umask can never regress it again.

usage() {
  cat <<'EOF'
Usage: publish-private-rc.sh --deb PATH --manifest PATH --rc NAME [--archive-dir DIR]

Publishes PATH's .deb and its MANIFEST.txt into ARCHIVE_DIR/RC_NAME with
mode 700 (dir) / 600 (files), regardless of the caller's umask.

  --deb PATH          built .deb to publish
  --manifest PATH     MANIFEST.txt evidence file to publish alongside it
  --rc NAME           RC directory name, e.g. rc42
  --archive-dir DIR   private archive root (default: /root/alderpointdns-private-artifacts)
EOF
}

DEB=""
MANIFEST=""
RC=""
ARCHIVE_DIR="/root/alderpointdns-private-artifacts"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --deb) shift; DEB="${1:?missing path}" ;;
    --manifest) shift; MANIFEST="${1:?missing path}" ;;
    --rc) shift; RC="${1:?missing rc name}" ;;
    --archive-dir) shift; ARCHIVE_DIR="${1:?missing dir}" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

[ -n "$DEB" ] && [ -n "$MANIFEST" ] && [ -n "$RC" ] || {
  echo "error: --deb, --manifest, and --rc are all required" >&2
  usage >&2
  exit 2
}
[ -f "$DEB" ] || { echo "error: not found: $DEB" >&2; exit 1; }
[ -f "$MANIFEST" ] || { echo "error: not found: $MANIFEST" >&2; exit 1; }

# Pin a private umask for every filesystem op below, independent of the
# caller's session umask.
umask 077

DEST="$ARCHIVE_DIR/$RC"
mkdir -p -m 700 "$ARCHIVE_DIR"
mkdir -m 700 "$DEST"

install -m 600 "$DEB" "$DEST/$(basename "$DEB")"
install -m 600 "$MANIFEST" "$DEST/MANIFEST.txt"

# Belt-and-suspenders: re-assert privacy even if install/mkdir semantics
# ever differ on some future platform.
chmod 700 "$DEST"
chmod 600 "$DEST"/*

# Verify before declaring success -- never silently publish something
# world/group-readable.
BAD="$(find "$DEST" \( -perm -044 -o -perm -022 \) -print)"
if [ -n "$BAD" ]; then
  echo "error: refusing to publish -- unexpectedly non-private permissions on:" >&2
  echo "$BAD" >&2
  exit 1
fi
DIR_MODE="$(stat -c '%a' "$DEST")"
if [ "$DIR_MODE" != "700" ]; then
  echo "error: refusing to publish -- $DEST is mode $DIR_MODE, expected 700" >&2
  exit 1
fi

echo "Published private RC to $DEST (dir 700, files 600, verified)."
