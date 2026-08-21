# RC45 test-count discrepancy reconciled

Owner-beta closure item: historical reports disagreed --

- one RC45 final report said 1202/1202
- the RC45 MANIFEST itself said 1201/1202 with a Tier B timing failure
- later runs reported 1201 passed + 1 deselected Chromium
- the current tree (post owner-beta rescue passes 1-2) reports 1216
  passed + 1 Chromium deselected/run separately

## What actually happened

There is no real discrepancy in the underlying test suite -- only in
which of two different real numbers got repeated informally. RC45's own
MANIFEST.txt (`/root/alderpointdns-private-artifacts/rc45/MANIFEST.txt`,
preserved, authoritative) states explicitly:

> Full tests/v2 (1201/1202, one pre-existing Tier B prewarm timing flake
> consistent with the same environmental-resource-contention class,
> passes reliably in isolation) and full V1 tests/ (1197/1197) both
> green.

The "1202/1202" figure that appeared in some later informal report was
from a run where that same pre-existing Tier B timing flake happened not
to fire -- a real, already-disposed environmental flake (see
`docs/v2/v1-upstream-toggle-concurrency-flake-disposition.md`), not a
second, different test count. Both "1201" and "1202" describe the exact
same 1202-test tree at the exact same source SHA; the difference is
purely whether that one timing-sensitive test happened to pass or fail
under whatever concurrent load the CI/dev host had at the moment, not a
change in what was collected or run.

The subsequent "1201 passed + 1 deselected Chromium" and current "1216
passed + 1 deselected Chromium" both reflect the Chromium harness test
being intentionally excluded from the main pytest invocation and run
separately (it needs a real Chromium binary + real dnsdist + a real
uvicorn subprocess, unlike every other test in the suite) -- never a
different counting methodology. The growth from 1202 to 1217 total
collected tests between RC45 and the current tree is real and expected:
two full owner-beta rescue passes were made since RC45 (see the git log
between `e129da5` and `624cd6b`), each adding real regression coverage
for the real defects they fixed.

## Canonical reporting format going forward

Report the two suites separately, never rolled into one misleading N+1
total unless they were actually run together in the same invocation:

```
Core V2 pytest:
<N>/<N> passed

Chromium harness:
passed separately
```

## Current tree, reverified this pass

```
$ python3 -m pytest tests/v2 -q --deselect tests/v2/test_ui_browser_harness.py::test_chromium_management_ui_harness
1228 passed, 1 deselected in 428.41s
```

(1228, not 1216: this owner-beta closure pass's own item 1/2 work added
12 more tests -- `tests/v2/test_worker_heartbeat.py` and
`TestBackgroundWorkerHealth` in `tests/v2/test_webapp.py` -- on top of
the 1216 already reported. See the commit introducing those.)

Chromium harness, run separately:

```
$ python3 -m pytest tests/v2/test_ui_browser_harness.py::test_chromium_management_ui_harness -q
1 passed
```

(This required a real fix first -- two of the harness's own assertions
were stale, left over from the central-internal-ID-generation pass
before RC45; see the commit fixing
`tests/v2/browser/chromium_ui_harness.js`. Before that fix this test
was a real, reproducible failure, not flaky.)

## Tier B timing test stability

Re-run in isolation multiple times this pass as part of the broader
`tests/v2` runs above; did not reproduce the historical flake. No
methodology change was made to it this pass -- its existing disposition
(`docs/v2/v1-upstream-toggle-concurrency-flake-disposition.md`) already
correctly identifies it as environmental-resource-contention-class, not
a product defect, and it has not been observed flaking again since.
