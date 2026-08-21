# Owner-beta closure pass: real defects found and fixed

This continues the beta-rescue/closure work in `docs/v2/rc45-test-evidence-reconciliation.md`.
RC45 is failed owner-beta history (`docs/v2/rc-ready-gate3.md` still applies: Gate #3
is not claimed). This document records the real, live-found defects fixed in this
pass, for the same reason those earlier documents exist: so the next reader does not
have to re-derive why each fix was made.

## 1. Soak harness: one transient connection failure killed the entire multi-hour run

`scripts/v2/soak_harness.py`'s `ApiClient._request` only caught `urllib.error.HTTPError`.
A real HTTP read timeout under real concurrent host load (this session ran a full
Chromium harness and a full `pytest tests/v2` run concurrently with an active soak,
which is itself a real lesson: don't do that on a resource-constrained host) raised an
uncaught `TimeoutError` straight out of the tick loop, killing the whole process and
losing every sample gathered so far -- exactly the kind of transient hiccup this
harness exists to survive and characterize, not die on.

Fixed: `_request` now returns a real `(0, {"error": "connection_failed", ...})` result
for `URLError`/`TimeoutError`/`ConnectionError`/`OSError`, recorded as tick evidence
like any other non-200 response. `run_soak`'s per-tick body was also extracted into
`_run_tick` and wrapped in a belt-and-suspenders `try/except` so no single tick's
unexpected failure can ever take the whole run down. Regression coverage:
`tests/v2/test_soak_harness.py::TestApiClientConnectionFailureResilience`.

## 2. Dashboard/Upstreams tables rendered `[object Object],[object Object]`

Found via the authenticated visual design pass (rendered-browser screenshots, dark and
light, of a real installed appliance) -- not by reading source. `app/v2/ui/app.js`'s
`pretty()` used a plain `String(value)` coercion with no special case for an array of
objects, so an upstream profile's `endpoints` field rendered as the literal, useless
`[object Object],[object Object]` on both the Dashboard's Upstreams panel and DNS
Settings/Upstreams' own table. Fixed to render each endpoint's real address (falling
back to JSON for any other object shape).

## 3. Installed V2 appliance always reported version "unknown"

`scripts/build-v2-deb.sh` never wrote `APP_ROOT/VERSION`, so `/api/system/status`
("Version" on System Status) and `software_updates.installed_source_version()`
("Installed (source)" on Software Updates) silently fell through to "unknown" on
every real installed appliance. Fixed by writing the package's own `DEB_VERSION` into
`VERSION` at build time.

## 4. Real SPA back/forward navigation did nothing

`app.js`'s `loadPage()` always called `history.replaceState`, never `pushState`, and
there was no `popstate` listener -- so the real V2 management console never
accumulated more than the one history entry the browser started on. Browser back/
forward did nothing (or, in a real browser tab, could navigate straight out of the
app). Fixed: push a new history entry only on an actual route change; same-route
re-renders (theme toggle, sidebar collapse) and popstate-driven loads still replace in
place. Found and proven live via the extended Chromium harness
(`browser-back-forward-navigation`, `rapid-route-cycling-no-stale-render`).

## 5. (SEVERE) The real Software Updates "Manual Package Upload" path could never accept any real V2 package

`app/v2/webapp.py` applies a blanket `MAX_REQUEST_BODY_BYTES = 1_000_000` (1 MB)
request-body cap to every route via middleware -- a real, narrowly-scoped fix from
earlier adversarial security testing against JSON-body reflection. That blanket cap
also covered `/api/updates/upload`, whose real job is accepting an entire V2
candidate `.deb` (~70 MB) base64-encoded into JSON (~93 MB after encoding overhead,
see `app.js`'s `fileToBase64` -> `data_base64`). Every real upload attempt failed
closed with 413 before ever reaching the endpoint's own real name/architecture/
version validation. Since V2 is private with no public release channel, manual
upload is the *only* real self-update path this build has at all -- so this feature
was completely non-functional for its one real documented purpose.

Found live: fixing the Chromium harness's own long-broken fake-upload-version
assertion (item 6 below) to actually reach a real upload of a real-sized package hit
this immediately. Fixed with a real, generous per-route ceiling
(`MAX_UPDATE_UPLOAD_BODY_BYTES = 250_000_000`) for this one large-binary-upload route;
every other route keeps the original 1 MB cap and rationale unchanged. Regression
coverage: `tests/v2/test_webapp.py::TestOversizedBodyRejection` (new
`test_update_upload_path_gets_real_headroom_over_the_generic_cap` /
`test_update_upload_path_still_has_a_real_ceiling`).

## 6. Chromium harness: the Software Updates apply test never actually exercised its own success path

`tests/v2/browser/chromium_ui_harness.js` hand-built a hollow stub `.deb`
(`2.0.0~fake-upload-1`, a bare `DEBIAN/control`, no real payload) for the Software
Updates upload/stage/apply-request test, on the documented assumption that the flow
"installs nothing" in this harness's environment. That version string was never
actually newer than any real `2.0.0~rcNN-1` candidate under real `dpkg` version
comparison (`'f' < 'r'`, and tilde-sorting makes this compare lexically) -- so the
test's "staged"/"apply-requested" assertions had silently been exercising the
rejection path (item 5's 413, before that, or a version-comparison rejection after)
this whole time, not the success path its own comments claimed.

Naively fixing just the version string then reached a REAL privileged `apt-get
install` of that hollow stub package once item 5 was fixed and the fake version
compared as genuinely newer -- which really did delete the real running appliance's
files out from under it (`scripts/v2/alderpointdns_v2_update_apply.py` really does run
`apt-get install` on whatever staged package passes `validate_candidate_package`'s
name/architecture/version checks once Apply is confirmed; there is no payload/
signature verification by design -- this is the manual-upload path for an
already-trusted local operator, the same trust level as `dpkg -i` over SSH).

Fixed properly: `buildRealBumpedDeb` builds a real, complete, harmless candidate via
this project's own `scripts/build-v2-deb.sh --version`, with the currently-installed
version bumped by one real debian-revision (`dpkg --compare-versions` confirms
`X-1.1 gt X-1`). Delivered via CDP `DOM.setFileInputFiles` (not a base64
`Runtime.evaluate` literal, which both overran this harness's own minimal
hand-rolled WebSocket client's 16-bit frame-length support for a ~93 MB payload and
would have hit item 5's defect anyway) -- Chromium reads the file directly off disk,
no payload ever crosses the CDP websocket. This gives real, safe, end-to-end proof:
real staging, a real privileged apply, a real "succeeded" result, and the appliance
genuinely still serving the real new version afterward
(`software-update-apply-succeeded`, `software-update-apply-verified-live`).

The dev/source-checkout case (`tests/v2/test_ui_browser_harness.py`, no real
dpkg-managed install to query or bump a version off of, and no privileged `.path`
watcher running to ever act on a marker) keeps a minimal harmless stub and
deliberately stops at proving the request was accepted -- real end-to-end apply
proof only makes sense, and is only safe, against a real dpkg-managed appliance.

Also added in this pass: a setup password-mismatch-then-correction proof
(`setup-password-mismatch-rejected`), and a permanent regression check that no
rendered table cell anywhere in the app ever contains the literal `[object Object]`
again (item 2's own defect class).
