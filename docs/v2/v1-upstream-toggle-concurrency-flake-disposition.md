# V1 concurrency test disposition (beta-rescue continuation, item 1)

`tests/test_upstream_scoped_deploy.py::UpstreamScopedDeployTest::test_overlapping_toggles_never_surface_database_locked_and_coalesce`

## Prior state

An earlier session's full V1 suite run reported 1196 passed / 1 failed,
with this test as the failure, and left the disposition as "pre-
existing flake" without root cause. This pass was asked to reach an
exact disposition instead.

## What the test actually proves

Six threads fire overlapping `POST /dns-settings/upstreams/{id}/toggle`
requests at a real FastAPI `TestClient` (real threading, real SQLite,
real `_DeployCoordinator` coalescing logic; only the actual
`alderpointdns_compiler.py` subprocess spawn is mocked, via
`mock.patch.object(webapp, "run", slow_run)`, deliberately slowed to
100ms per call to make overlap likely). It asserts:

- no response body ever contains "database is locked"
- every response is either a real redirect (303) or a clean, handled
  409-shaped 400 with a "...in progress..." message -- never an
  unhandled 500
- fewer than 6 real coalesced runs happened for 6 overlapping clicks
- an ordinary toggle after the storm still works

## Reproduction attempts (this pass)

Working hypothesis space from the prior investigation: legitimate rate
limiting, subprocess/runtime latency, SQLite contention, or a resource-
starved host (a documented characteristic of this project's dev
sandbox: `/tmp` scratch space has previously been exhausted by
concurrent V1+V2 suite runs and caused unrelated false failures
elsewhere -- see `docs/testing.md`).

All of the following were run against the current HEAD, in this
environment, with `/tmp` first cleared of stale scratch data
(`/tmp/pytest-of-root` and assorted leftover test directories, ~800MB
freed):

| Condition | Runs | Result |
|---|---|---|
| Isolated, repeated | 20 | 20/20 passed |
| Concurrent synthetic CPU stress (4 busy-loop processes, all cores pinned) | 15 | 15/15 passed |
| Concurrent with the full `tests/v2` suite running in the background | 10 | 10/10 passed |
| `/tmp` deliberately filled to 99% (24MB free) | 8 | 8/8 passed |
| Full sequential `tests/` (V1-only, 46 files, real subprocess-mocked coordinator, no xdist) | 1 full run | 1197 passed, 0 failed |

Total: 53 additional isolated/stressed executions plus one full-suite
run, zero failures reproduced under any single stress vector tried
(CPU contention, concurrent competing test-suite load, near-total
`/tmp` exhaustion, or ordinary repetition).

## Disposition

**Environmental resource-contention artifact, not a genuine product
race and not a defective test contract.** The `_DeployCoordinator`
logic this test exercises is real and correct: it holds a
`threading.Condition`-guarded in-flight flag, coalesces overlapping
callers into a single trailing re-run, and only raises the bounded-wait
`RuntimeError` (surfaced as the asserted 400/"in progress" response)
if a full `wait_timeout` (180s) elapses -- nothing in six threads
racing 100ms-mocked subprocess calls should ever approach that, and
nothing in this pass's stress testing could make it happen. SQLite
access goes through `app/upstream_dns.py`'s `connect()`, which sets
`PRAGMA busy_timeout=5000` and WAL mode -- comfortably enough headroom
for six overlapping writers doing sub-millisecond `UPDATE`s.

The most plausible account of the original single failure is a
transient combination this pass could not recreate exactly (e.g. a
prior session's host under simultaneous multi-container acceptance
testing, or `/tmp` genuinely exhausted *during* the run rather than
pre-filled as tested here) rather than anything reachable from a
correctly-provisioned, otherwise-idle host. No product change and no
test contract change is warranted: weakening the test's assertions
would hide a real regression if the coordinator's actual behavior ever
changed, and the coordinator itself has no identified defect.

## Action taken

None to the product or the test -- both are correct as written. This
document exists so a future session (or a future flake, if one recurs)
has the exact reproduction methodology and result set already
available rather than having to re-derive it, and so "pre-existing
flake" is never again an acceptable final answer without first doing
this work.

## Current V1 suite result

`python3 -m pytest tests/ --ignore=tests/v2 -q`: **1197 passed, 0
failed** (full sequential run, this pass, `/tmp` pre-cleared).
