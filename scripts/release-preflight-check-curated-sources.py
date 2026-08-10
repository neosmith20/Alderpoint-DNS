#!/usr/bin/env python3
"""Release-time network preflight: verifies the three curated fresh-install
blocklist source URLs (app.alderpointdns_compiler.DEFAULT_FRESH_INSTALL_SOURCES)
are actually reachable and return a successful HTTP status, before a public
release ships them as what a brand-new install seeds by default.

This is deliberately NOT part of `python3 -m pytest tests/` or
tests/test_acceptance.sh -- both are expected to pass with no Internet
access (e.g. in an offline build environment), and a real upstream outage
or URL change (like the HaGeZi Multi Normal raw.githubusercontent.com
mirror going dead, discovered live during v1.0 fresh-install acceptance)
must never fail the ordinary test/build gate. Run this by hand, with real
network access, as one step of preparing a release:

    python3 scripts/release-preflight-check-curated-sources.py

Exits 0 only if every curated source responds successfully; exits 1 (with
each source's status printed) otherwise.
"""
from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.alderpointdns_compiler import DEFAULT_FRESH_INSTALL_SOURCES  # noqa: E402

TIMEOUT_SECONDS = 15
# Only enough to confirm the server actually starts sending list content,
# not a full download of what can be a multi-megabyte blocklist -- this is
# a reachability check, not a content validator.
PROBE_BYTES = 4096


def check_one(name: str, url: str) -> tuple[bool, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "Alderpoint DNS release-preflight/1"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status = getattr(response, "status", None) or response.getcode()
            chunk = response.read(PROBE_BYTES)
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return False, f"unreachable: {exc.reason}"
    except OSError as exc:
        return False, f"unreachable: {exc}"
    if status != 200:
        return False, f"HTTP {status}"
    if not chunk:
        return False, "HTTP 200 but empty response body"
    return True, f"HTTP {status}, {len(chunk)}+ bytes"


def main() -> int:
    if len(DEFAULT_FRESH_INSTALL_SOURCES) != 3:
        print(f"error: expected exactly 3 curated fresh-install sources, found {len(DEFAULT_FRESH_INSTALL_SOURCES)}", file=sys.stderr)
        return 1
    failures = 0
    for source in DEFAULT_FRESH_INSTALL_SOURCES:
        ok, detail = check_one(source.name, source.url)
        status_word = "OK" if ok else "FAIL"
        print(f"{status_word}: {source.name} <{source.url}> -- {detail}")
        if not ok:
            failures += 1
    if failures:
        print(f"\n{failures} of {len(DEFAULT_FRESH_INSTALL_SOURCES)} curated default source(s) are not reachable. "
              "Fix or replace the URL(s) above before preparing a release -- a fresh install would seed a dead source.", file=sys.stderr)
        return 1
    print(f"\nAll {len(DEFAULT_FRESH_INSTALL_SOURCES)} curated fresh-install default sources are reachable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
