#!/bin/sh
set -eu

# Encryption page layout regression test.
#
# Guards the Certificate settings panel sizing fix: the Protocols form panel
# and the Certificate panel share a `.grid` section, and CSS grid's default
# align-items:stretch used to force the Protocols panel to grow whenever a
# Certificate <details> section was expanded, leaving a block of artificial
# empty space. The section now carries the scoped `.grid.align-start`
# modifier so both panels are sized purely by their own content.
#
# This test never touches the live service. It renders the authenticated
# encryption page from the repository templates into a temporary directory,
# points the /static/ references at the repository's own CSS/JS so the page
# works over file://, and measures real layout in headless Chromium at four
# viewport widths.

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

CHROMIUM="$(command -v chromium || command -v chromium-browser || true)"
if [ -z "$CHROMIUM" ]; then
  echo "############################################################" >&2
  echo "SKIPPED: neither chromium nor chromium-browser is installed;" >&2
  echo "the encryption page layout regression test cannot measure" >&2
  echo "real layout without a browser. Install chromium to run it." >&2
  echo "############################################################" >&2
  exit 0
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT INT TERM

ALDERPOINTDNS_ROOT="$ROOT" ALDERPOINTDNS_LAYOUT_WORKDIR="$WORKDIR" python3 -B - <<'PY' || fail "could not render the encryption page for layout measurement"
import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

root = Path(os.environ["ALDERPOINTDNS_ROOT"])
workdir = Path(os.environ["ALDERPOINTDNS_LAYOUT_WORKDIR"])
sys.path.insert(0, str(root))

from fastapi.templating import Jinja2Templates  # noqa: E402

from app import webapp  # noqa: E402  (import parity with the running app)

# app.webapp pins its own TEMPLATES at the installed prefix; bind an identical
# environment to this checkout so the test measures the templates it ships with.
templates = (
    webapp.TEMPLATES
    if Path(webapp.ROOT) == root
    else Jinja2Templates(directory=str(root / "web" / "templates"))
)

long_domain = "extremely-long-subdomain-name-that-must-wrap-without-horizontal-overflow.example.invalid"

context = {
    "request": SimpleNamespace(url=SimpleNamespace(path="/encryption"), query_params={}),
    "admin": "layout",
    "setup_required": False,
    "csrf": "layout",
    "protection": {"label": "Active", "tone": "healthy"},
    "global_status": {"label": "Active", "tone": "healthy", "detail": "all core services active"},
    "error": None,
    "cfg": {
        "server_hostname": "alderpointdns.local", "bootstrap_ip": "192.168.1.101",
        "listen_ipv4": "0.0.0.0", "listen_ipv6": "::",
        "doh_enabled": "1", "doh3_enabled": "1", "dot_enabled": "1", "doq_enabled": "1", "dnscrypt_enabled": "0",
        "doh_path": "/dns-query", "doh_port": "443", "doh3_port": "443", "dot_port": "853", "doq_port": "853",
        "dnscrypt_port": "5443", "dnscrypt_provider": "2.dnscrypt-cert.alderpointdns.local",
        "cert_mode": "self_signed", "cert_path": "/etc/alderpointdns/certs/alderpointdns-lab.crt",
        "key_path": "/etc/alderpointdns/certs/alderpointdns-lab.key",
    },
    "capabilities": {"doh": True, "dot": True, "doh3": True, "doq": True, "dnscrypt": True},
    "cert": {
        "available": True, "subject": "CN=" + long_domain, "issuer": "CN=" + long_domain,
        "not_before": "Jul 29 00:00:00 2026 GMT", "not_after": "Oct 31 00:00:00 2028 GMT",
        "days_remaining": 824, "expiring_soon": False, "expired": False,
        "fingerprint_sha256": "AA:BB:CC:DD", "sans": ["DNS:" + long_domain, "IP Address:192.168.1.101"],
        "self_signed": True,
    },
    "deployment": {
        "status": "deployed", "started_at": "2026-07-29T00:00:00Z", "finished_at": "2026-07-29T00:00:00Z",
        "message": "deployed with protocols: {'plain': 'ok'}", "protocol_tests": "{'plain': 'ok'}",
    },
    "connection_info": {"DoH": "https://" + long_domain + "/dns-query", "DoT": "tls://alderpointdns.local:853"},
    "dnscrypt_fingerprint": None,
}

html = templates.get_template("encryption.html").render(**context)

for asset in ("app.css", "app.js"):
    shutil.copyfile(root / "web" / "static" / asset, workdir / asset)

# file:// friendly asset references.
html = html.replace('href="/static/', 'href="').replace('src="/static/', 'src="')
if "/static/" in html:
    raise SystemExit("unrewritten /static/ reference remains in the rendered page")

measure = """
<pre id="layout-result">pending</pre>
<script>
(function () {
  function report(payload) {
    var target = document.getElementById('layout-result');
    target.textContent = 'LAYOUTRESULTBEGIN' + JSON.stringify(payload) + 'LAYOUTRESULTEND';
  }

  function reflow() {
    return document.body.getBoundingClientRect().height + document.body.offsetHeight;
  }

  function panelOf(node) {
    return node ? node.closest('.panel') : null;
  }

  try {
    var protocolsHeading = null;
    var headings = document.querySelectorAll('.panel .panel__head h2');
    for (var i = 0; i < headings.length; i += 1) {
      if (headings[i].textContent.trim() === 'Protocols') { protocolsHeading = headings[i]; break; }
    }
    var protocols = panelOf(protocolsHeading);
    if (!protocols) { report({ error: 'Protocols panel not found' }); return; }

    var section = protocols.parentElement;
    var cert = null;
    for (var s = 0; s < section.children.length; s += 1) {
      if (section.children[s] !== protocols) { cert = section.children[s]; break; }
    }
    if (!cert) { report({ error: 'Certificate panel not found beside Protocols' }); return; }

    var sections = cert.querySelectorAll(':scope > details');
    var d;
    for (d = 0; d < sections.length; d += 1) { sections[d].open = false; }
    reflow();

    var baseProtocols = protocols.offsetHeight;
    var baseCert = cert.offsetHeight;
    var protocolsBox = protocols.getBoundingClientRect();
    var certBox = cert.getBoundingClientRect();
    var sideBySide = certBox.left >= protocolsBox.right - 1;

    var expansions = [];
    for (d = 0; d < sections.length; d += 1) {
      var summary = sections[d].querySelector('summary');
      sections[d].open = true;
      reflow();
      var openProtocols = protocols.offsetHeight;
      var openCert = cert.offsetHeight;
      sections[d].open = false;
      reflow();
      expansions.push({
        label: summary ? summary.textContent.trim() : 'details ' + d,
        protocolsHeight: openProtocols,
        certHeight: openCert,
        protocolsDelta: openProtocols - baseProtocols,
        certDelta: openCert - baseCert
      });
    }

    // Also confirm nothing overflows horizontally with every section expanded.
    for (d = 0; d < sections.length; d += 1) { sections[d].open = true; }
    reflow();
    var scrollWidth = document.documentElement.scrollWidth;
    var clientWidth = document.documentElement.clientWidth;
    var innerWidth = window.innerWidth;
    for (d = 0; d < sections.length; d += 1) { sections[d].open = false; }
    reflow();

    report({
      detailsCount: sections.length,
      baseProtocolsHeight: baseProtocols,
      baseCertHeight: baseCert,
      protocolsTop: Math.round(protocolsBox.top),
      protocolsLeft: Math.round(protocolsBox.left),
      certTop: Math.round(certBox.top),
      certLeft: Math.round(certBox.left),
      sideBySide: sideBySide,
      scrollWidth: scrollWidth,
      clientWidth: clientWidth,
      innerWidth: innerWidth,
      expansions: expansions
    });
  } catch (err) {
    report({ error: String(err) });
  }
}());
</script>
"""

if "</body>" in html:
    html = html.replace("</body>", measure + "</body>", 1)
else:
    html += measure

(workdir / "encryption.html").write_text(html)
PY

PAGE="$WORKDIR/encryption.html"
[ -f "$PAGE" ] || fail "rendered encryption page was not written"

measure_width() {
  label="$1"
  width="$2"
  height="$3"
  expected="$4"
  dump="$WORKDIR/dump-${label}.html"
  "$CHROMIUM" --headless=new --disable-gpu --no-sandbox --hide-scrollbars \
    --window-size="${width},${height}" --virtual-time-budget=3000 \
    --user-data-dir="$WORKDIR/profile-${label}" \
    --dump-dom "file://${PAGE}" >"$dump" 2>"$WORKDIR/dump-${label}.err" ||
    fail "chromium failed to render the encryption page at ${width}x${height}"
  if [ -n "${ALDERPOINTDNS_LAYOUT_SHOTS:-}" ]; then
    "$CHROMIUM" --headless=new --disable-gpu --no-sandbox --hide-scrollbars \
      --window-size="${width},${height}" --virtual-time-budget=3000 \
      --user-data-dir="$WORKDIR/shot-${label}" \
      --screenshot="${ALDERPOINTDNS_LAYOUT_SHOTS}/encryption-${label}-${width}x${height}.png" \
      "file://${PAGE}" >/dev/null 2>&1 || true
  fi
  ALDERPOINTDNS_LAYOUT_DUMP="$dump" \
  ALDERPOINTDNS_LAYOUT_LABEL="$label" \
  ALDERPOINTDNS_LAYOUT_VIEWPORT="${width}x${height}" \
  ALDERPOINTDNS_LAYOUT_EXPECTED="$expected" \
  python3 -B - <<'PY' || fail "encryption panel layout is wrong at ${width}x${height} (${label})"
import json
import os
import re
import sys
from pathlib import Path

dump = Path(os.environ["ALDERPOINTDNS_LAYOUT_DUMP"]).read_text()
label = os.environ["ALDERPOINTDNS_LAYOUT_LABEL"]
viewport = os.environ["ALDERPOINTDNS_LAYOUT_VIEWPORT"]
expected = os.environ["ALDERPOINTDNS_LAYOUT_EXPECTED"]

match = re.search(r"LAYOUTRESULTBEGIN(.*?)LAYOUTRESULTEND", dump, re.S)
if not match:
    raise SystemExit(
        f"{label} {viewport}: the layout measurement script produced no result; "
        "the page did not render or scripting failed"
    )
result = json.loads(match.group(1).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">"))
if "error" in result:
    raise SystemExit(f"{label} {viewport}: measurement error: {result['error']}")

problems = []

if result["detailsCount"] != 4:
    problems.append(
        f"expected the 4 Certificate details sections, measured {result['detailsCount']}"
    )

limit = max(result["innerWidth"], result["clientWidth"]) + 1
if result["scrollWidth"] > limit:
    problems.append(
        f"horizontal overflow: documentElement.scrollWidth {result['scrollWidth']} > viewport {limit}"
    )

if expected == "side_by_side":
    if not result["sideBySide"]:
        problems.append(
            "the Protocols and Certificate panels are not side by side at this width "
            f"(protocols left {result['protocolsLeft']}, certificate left {result['certLeft']}); "
            "the layout assertions below would be meaningless"
        )
    # A few pixels of tolerance absorbs sub-pixel rounding of the grid row.
    tolerance = 3
    for entry in result["expansions"]:
        if entry["protocolsDelta"] > tolerance:
            problems.append(
                f"expanding \"{entry['label']}\" stretched the Protocols panel by "
                f"{entry['protocolsDelta']}px ({result['baseProtocolsHeight']}px -> "
                f"{entry['protocolsHeight']}px); the Protocols panel must keep its natural "
                "height so no artificial empty space appears"
            )
        if entry["certDelta"] <= 0:
            problems.append(
                f"expanding \"{entry['label']}\" did not grow the Certificate panel "
                f"({result['baseCertHeight']}px -> {entry['certHeight']}px); the accordion "
                "content is not being revealed"
            )
elif expected == "stacked":
    if result["sideBySide"]:
        problems.append(
            "the panels are still side by side at mobile width; the grid must collapse "
            "to a single column"
        )
    if result["certTop"] <= result["protocolsTop"]:
        problems.append(
            f"stacked order is wrong: Protocols top {result['protocolsTop']} is not above "
            f"Certificate top {result['certTop']}"
        )
else:
    problems.append(f"unknown expectation {expected!r}")

if problems:
    print(f"FAIL: encryption panel layout at {viewport} ({label}):", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    raise SystemExit(1)

summary = " ".join(
    f"[{entry['label']}: protocols {entry['protocolsDelta']:+d}px, certificate {entry['certDelta']:+d}px]"
    for entry in result["expansions"]
)
print(
    f"ok {label} {viewport} ({expected}): protocols {result['baseProtocolsHeight']}px, "
    f"certificate {result['baseCertHeight']}px collapsed {summary}"
)
PY
}

measure_width wide-desktop 1680 1000 side_by_side
measure_width standard-desktop 1366 900 side_by_side
measure_width tablet 900 900 side_by_side
measure_width mobile 390 844 stacked

echo "Alderpoint DNS encryption page layout test passed"
