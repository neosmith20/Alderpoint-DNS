#!/bin/sh
set -eu

# Permanent licensing-hygiene gate: verifies the finalized license/legal
# documents exist and are intact, and scans tracked files for contradictory
# licensing claims about Alderpoint DNS itself (a stale "MIT licensed"
# claim, an unselected license like GPL/AGPL/Apache/BSD, "open source"
# claims, an "unfinalized" claim left over from before the license was
# picked, or an unrestricted-commercial-use claim). Legitimate mentions of
# other projects' licenses in THIRD_PARTY_NOTICES.md and dependency
# metadata, and CONTRIBUTOR_LICENSE_AGREEMENT.md's description of being
# adapted from the Apache ICLA, are allow-listed.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "== verifying LICENSE is the intact PolyForm Noncommercial License 1.0.0 =="
test -f LICENSE || fail "root LICENSE file is missing"
for marker in \
  "PolyForm Noncommercial License 1.0.0" \
  "https://polyformproject.org/licenses/noncommercial/1.0.0" \
  "## Acceptance" \
  "## Copyright License" \
  "## Distribution License" \
  "## Notices" \
  "## Changes and New Works License" \
  "## Patent License" \
  "## Noncommercial Purposes" \
  "## Personal Uses" \
  "## Noncommercial Organizations" \
  "## Fair Use" \
  "## No Other Rights" \
  "## Patent Defense" \
  "## Violations" \
  "## No Liability" \
  "## Definitions" \
  "Required Notice:" \
  ; do
  grep -qF "$marker" LICENSE || fail "LICENSE is missing expected section/marker: $marker"
done
# The 32-day cure period is a specific, easy-to-silently-alter detail that
# is worth pinning down explicitly, not just checking the section exists.
grep -q "within 32 days of receiving notice" LICENSE || \
  fail "LICENSE's Violations section text does not match the official PolyForm Noncommercial 1.0.0 text (32-day cure period marker missing)"

echo "== verifying COPYRIGHT carries the exact Required Notice =="
test -f COPYRIGHT || fail "root COPYRIGHT file is missing"
grep -qF "Required Notice: Copyright 2026 Alex (GitHub: neosmith20). Alderpoint DNS." COPYRIGHT || \
  fail "COPYRIGHT is missing the exact Required Notice line"

echo "== verifying the other legal documents exist =="
for f in COMMERCIAL_LICENSING.md CONTRIBUTOR_LICENSE_AGREEMENT.md TRADEMARKS.md THIRD_PARTY_NOTICES.md; do
  test -f "$f" || fail "$f is missing"
done

echo "== scanning tracked files for contradictory licensing claims =="
# Files where other projects' license names (or, for the CLA, the Apache
# ICLA it is structurally adapted from) are expected and legitimate.
ALLOWED_FILES="THIRD_PARTY_NOTICES.md requirements.txt requirements-debian.txt packaging/debian/control packaging/debian/copyright packaging/debian/alderpointdns.docs CONTRIBUTOR_LICENSE_AGREEMENT.md LICENSE COPYRIGHT tests/test_licensing_hygiene.sh docs/testing.md"

is_allowed() {
  target="$1"
  for allowed in $ALLOWED_FILES; do
    [ "$target" = "$allowed" ] && return 0
  done
  return 1
}

PATTERN='\bMIT license\b|\bMIT-licensed\b|licensed under (the )?MIT\b|\bGPL-[0-9]|\bAGPL\b|\bApache License\b|\bApache-2\.0\b|\bBSD license\b|\bBSD-[0-9]-Clause\b|license has not yet been finalized'

violations=0
git ls-files | while IFS= read -r tracked_file; do
  is_allowed "$tracked_file" && continue
  [ -f "$tracked_file" ] || continue
  grep -Iq . "$tracked_file" 2>/dev/null || continue
  if grep -nEi "$PATTERN" "$tracked_file" >/dev/null 2>&1; then
    echo "contradictory license-name claim in $tracked_file:" >&2
    grep -nEi "$PATTERN" "$tracked_file" >&2
    echo "1" > /tmp/alderpointdns-licensing-hygiene-violation
  fi
  # "open source"/"open-source" and unrestricted-commercial-use claims are
  # checked separately: a *negated* mention ("is not open source") is the
  # correct, intended phrasing and must not trip this gate.
  if grep -nEi '\bopen[- ]source\b' "$tracked_file" 2>/dev/null | grep -viE 'not (an? )?open[- ]source' >/tmp/alderpointdns-open-source-hits 2>/dev/null; then
    if [ -s /tmp/alderpointdns-open-source-hits ]; then
      echo "unqualified 'open source' claim in $tracked_file:" >&2
      cat /tmp/alderpointdns-open-source-hits >&2
      echo "1" > /tmp/alderpointdns-licensing-hygiene-violation
    fi
  fi
  rm -f /tmp/alderpointdns-open-source-hits
  if grep -nEi 'unrestricted commercial|free for commercial use|commercial use is (permitted|allowed|granted)\b' "$tracked_file" 2>/dev/null; then
    echo "unrestricted-commercial-use claim in $tracked_file (contradicts COMMERCIAL_LICENSING.md)" >&2
    echo "1" > /tmp/alderpointdns-licensing-hygiene-violation
  fi
done
if [ -e /tmp/alderpointdns-licensing-hygiene-violation ]; then
  rm -f /tmp/alderpointdns-licensing-hygiene-violation
  fail "one or more tracked files contain a contradictory licensing claim (see above)"
fi

echo "== verifying README/CONTRIBUTING reference the finalized license set =="
grep -q "PolyForm Noncommercial License 1.0.0" README.md || fail "README.md does not mention the PolyForm Noncommercial License 1.0.0"
grep -q "COMMERCIAL_LICENSING.md" README.md || fail "README.md does not reference COMMERCIAL_LICENSING.md"
grep -q "CONTRIBUTOR_LICENSE_AGREEMENT.md" CONTRIBUTING.md || fail "CONTRIBUTING.md does not reference the Contributor License Agreement"

echo "== verifying the built package installs license/copyright docs =="
DEB_WORK="$(mktemp -d /tmp/alderpointdns-licensing-deb-test.XXXXXX)"
trap 'rm -rf "$DEB_WORK"' EXIT
DEB="$(./scripts/build-deb.sh --output-dir "$DEB_WORK")"
DOC_FILES="$(dpkg-deb --contents "$DEB" | awk '{print $NF}')"
for expected in "./usr/share/doc/alderpointdns/LICENSE" "./usr/share/doc/alderpointdns/copyright" "./usr/share/doc/alderpointdns/COMMERCIAL_LICENSING.md" "./usr/share/doc/alderpointdns/THIRD_PARTY_NOTICES.md"; do
  echo "$DOC_FILES" | grep -qF "$expected" || fail "built package does not install $expected"
done
dpkg-deb --field "$DEB" Description | grep -qi "open.source" && \
  fail "built package Description falsely describes the project as open source"

echo "licensing hygiene tests passed"
