#!/bin/sh
set -eu

# Permanent release-hygiene gate, generic across renames: scans every
# git-tracked file's contents and every tracked filename (case-insensitive)
# for a caller-supplied prohibited-name pattern and fails if any hit is
# found. Intended use is a final pre-release check that no stale
# reference to a retired internal name (e.g. the former product name,
# before its public rename) has leaked into the tree.
#
# The prohibited pattern is deliberately NOT hardcoded in this file: if it
# were, this test would match its own source the moment it ran, which is
# exactly the kind of self-referential bug a release gate must avoid.
# Instead the pattern is supplied at invocation time via the
# PROHIBITED_NAME_PATTERN environment variable (an extended-regex pattern,
# case-insensitive):
#
#   PROHIBITED_NAME_PATTERN='some-retired-name' tests/test_release_hygiene.sh
#
# If PROHIBITED_NAME_PATTERN is unset, the scan is skipped with a clear
# message rather than silently checking against a baked-in default.
#
# Optional:
#
#   RELEASE_HYGIENE_ROOT=/path/to/public/export
#
# scans a prepared export tree instead of the current checkout. This keeps
# private-source-only notes out of public exports without baking private terms
# into this generic public-safe script.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

ROOT_DIR="${RELEASE_HYGIENE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
cd "$ROOT_DIR"

if [ -z "${PROHIBITED_NAME_PATTERN:-}" ]; then
  echo "PROHIBITED_NAME_PATTERN is not set; skipping release-hygiene stale-name scan"
  exit 0
fi

command -v git >/dev/null 2>&1 || fail "git is required"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  LIST_FILES="git ls-files -z -- . ':!:.git'"
else
  LIST_FILES="find . -type f -print0"
fi

echo "== scanning tracked file contents for prohibited pattern =="
CONTENT_MATCHES="$(eval "$LIST_FILES" \
  | xargs -0 grep -liI -E -e "$PROHIBITED_NAME_PATTERN" 2>/dev/null || true)"
if [ -n "$CONTENT_MATCHES" ]; then
  echo "tracked files whose content matches PROHIBITED_NAME_PATTERN:" >&2
  echo "$CONTENT_MATCHES" >&2
  fail "prohibited-name pattern found in tracked file contents"
fi
echo "no tracked file contents matched"

echo "== scanning tracked filenames for prohibited pattern =="
NAME_MATCHES="$(eval "$LIST_FILES" \
  | tr '\0' '\n' \
  | grep -i -E -e "$PROHIBITED_NAME_PATTERN" || true)"
if [ -n "$NAME_MATCHES" ]; then
  echo "tracked filenames matching PROHIBITED_NAME_PATTERN:" >&2
  echo "$NAME_MATCHES" >&2
  fail "prohibited-name pattern found in tracked filenames"
fi
echo "no tracked filenames matched"

echo "release hygiene scan passed"
