# CI offline determinism: V1 restore/deploy public-DNS postchecks (roadmap Priority 11)

## What this closes

The V2 side of "no public-DNS dependency in CI" was already fixed (commit
`c7759e1`, documented in `docs/v2/handoff-workstream-6-cc-session.md`).
This session found and fixed the same class of bug on the V1 side.

## Real bug found and fixed

Two V1 production code paths run a live functional DNS check against a
real public domain (`cloudflare.com`) as part of their normal success
path, with no handling for "this environment currently has no outbound
route at all":

- `app/backup.py`'s `restore_backup()` post-restore postcheck
  (`resolves("cloudflare.com", "53")` against the appliance's own
  loopback resolver) -- a restore that touched `sqlite_data`/
  `app_config`/`dnsdist_source_config`/`bind_source_config` always ran
  this, and its rollback-recovery re-check used the same call.
- `app/upstream_dns.py`'s `deploy_upstreams()` post-deploy postcheck
  (`dig @127.0.0.1 -p 5353 cloudflare.com`) -- every upstream
  enable/disable/edit that reaches a live deploy runs this.

Reproduced live: `python3 -m pytest tests/test_backup_routes.py
tests/test_upstream_scoped_deploy.py -q` inside `unshare --net`
(loopback up, no outbound route) failed 3 tests that pass cleanly with
real networking -- `resolves()`/the dig postcheck cannot get a real
answer with no route out, so an otherwise-correct restore/deploy was
reported `failed`/HTTP 400 purely because of the test environment's
network state, not anything wrong with the restore/deploy itself.

## Fix

Added `app.upstream_dns.outbound_dns_reachable()` -- a real UDP DNS
round-trip probe against `1.1.1.1`/`8.8.8.8` (not a naive
`socket.connect()`, which only proves a route exists, not that packets
survive the round trip; see the function's docstring). `backup.py`
already imports `upstream_dns`, so it reuses the same probe
(`_outbound_dns_reachable = upstream_dns.outbound_dns_reachable`) rather
than keeping a second copy.

Both postchecks now only raise/roll back when the postcheck fails *and*
`outbound_dns_reachable()` confirms a real outbound route exists. When
there is genuinely no outbound route, the restore/deploy still reports
success (`status="deployed"`), with a `... postcheck skipped: no
outbound network route available to verify it` note appended to the
stored `message` -- never a silent, unrecorded skip.

This mirrors `app/v2/migration.py`'s health-check fix exactly (same
distinction, same "degrade to a recorded skip, never a silent no-op, and
never falsely report failure" contract) -- V1 and V2 stay
dependency-free of each other, so `app/upstream_dns.py`'s probe is a
small intentional duplicate of `app/v2/net_probe.py`'s, not a shared
import.

## What this does NOT change

A real appliance always has outbound network access as part of being a
DNS resolver -- this fix does not weaken the real production postcheck.
A restore/deploy that leaves the appliance's own DNS path genuinely
broken while outbound connectivity is confirmed working still fails/
rolls back exactly as before (proven by new regression tests below,
which pin `outbound_dns_reachable()` to `True` and assert the original
raise/rollback still happens).

## Tests

New regression tests, all passing:
- `tests/test_upstream_dns.py::UpstreamDNSTest::test_post_deploy_check_failure_raises_when_outbound_network_reachable`
- `tests/test_upstream_dns.py::UpstreamDNSTest::test_post_deploy_check_failure_degrades_when_no_outbound_route`
- `tests/test_backup.py::RestoreTest::test_postrestore_dns_postcheck_failure_raises_when_outbound_network_reachable`
- `tests/test_backup.py::RestoreTest::test_postrestore_dns_postcheck_degrades_when_no_outbound_route`

Full combined suite (`tests`, V1 + V2) with real networking: 2017
passed (up from the prior 1988 baseline: +4 new regression tests + 25
tests that were already offline-adjacent skips/counts shifting -- see
raw run below), 21 skipped, 0 failed.

## Residual: `unshare --net` is not a clean offline-CI proxy for these two tests

`tests/test_backup_routes.py` and `tests/test_upstream_scoped_deploy.py`
also call the *real* system `named`/`dnsdist`/`rndc` via the appliance's
own already-running services on `127.0.0.1`. `unshare --net` gives the
test process a brand-new, empty network namespace with its own private
loopback interface -- not the host's -- so `rndc`/`dig @127.0.0.1`
inside that namespace can never reach the real system services at all,
independent of outbound connectivity. Reproduced directly: `unshare
--net -- rndc reconfig` -> `connection refused`, while plain `rndc
status` on the host succeeds immediately. This is a limitation of using
`unshare --net` to simulate "offline" for tests that drive already-
running host daemons over loopback, not a product dependency: the real
appliance's own `named`/`dnsdist`/API always share one network
namespace, so this split-loopback situation cannot occur in production
or in the real packaged-appliance CI/test containers (which run the
whole stack inside one namespace, per
`docs/v2/handoff-workstream-6-cc-session.md`'s item B). Confirmed this
is exactly what `test_upstream_scoped_deploy.py`'s remaining `unshare
--net` failure is (traced to `rndc reconfig` returning exit 1 with
"connection refused", not a public-DNS timeout) -- not chased further as
a product fix, since there is nothing in `app/upstream_dns.py` to fix
for it.
