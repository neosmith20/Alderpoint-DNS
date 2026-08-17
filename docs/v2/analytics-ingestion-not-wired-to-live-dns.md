# Real gap confirmed live: analytics/query-log is not wired to the real DNS answering path (roadmap Priority 6 continuation)

## What this is

Found while attempting a combined-load hardware/performance pass on
RC5 (2 GiB constrained container): after real, sustained DNS traffic
through the real packaged `dnsdist` runtime, `/var/lib/alderpointdns-v2
/analytics/` contains only `aggregates.db` (empty) -- zero Parquet
files were ever written. `/api/analytics/top-domains` correctly returns
a well-shaped empty result, not an error, but there is genuinely no
query data behind it for real served traffic.

Root cause, confirmed by reading the real production entry point
(`scripts/v2/alderpointdns_v2_ctl.py`'s `cmd_analytics_worker`, the
actual code the `alderpointdns-v2-analytics.service` unit runs) -- its
own docstring already says this plainly:

> Drains a real inbox directory of one-JSON-line-per-event files (the
> real integration point a future DNS-side event logger writes into --
> **nothing populates it yet in this pass**, same honest gap noted for
> the management API).

This is not a hidden defect this session introduced or newly
discovered as a surprise -- it is an existing, explicitly acknowledged
gap already documented in the code itself. What this session adds is
**live confirmation of its real, current-day impact**: the real
packaged `dnsdist` runtime (`app/v2/dnsdist_gen.py`/
`dnsdist_policy_runtime.py`) emits no protobuf/remote-logging directive
at all, so nothing ever writes to the inbox the analytics worker
drains, for real production traffic. The only two things that *do*
populate real data today are the standalone `--inject-test-event` CLI
flag (a synthetic single event, used by the clean-install proof) and
the separate, deliberately-non-authoritative `dns-observer` ingress on
port 1053 (client-discovery only, a different, narrower purpose --
confirmed working correctly in `docs/v2/rc1-clean-install-acceptance.md`
and this session's own RC1 pass).

## Why this matters for RC readiness

V2's own roadmap explicitly lists "query log" and "analytics" among the
V1 capabilities that "must not regress." As currently packaged, they
have not yet been *implemented* for the real DNS path at all (not
regressed -- never wired up), which is a materially different and more
significant gap than a regression would be. The Parquet+DuckDB storage
layer, the aggregate SQLite layer, the ingestion queue/writer, the
Tier-B working-set feed, and the query API are all real, tested, and
working correctly -- the single missing piece is the producer: nothing
in the real dnsdist config generator emits query events for real
traffic.

## Why not fixed this session

Wiring real dnsdist query logging (most likely via `RemoteLogAction`/
`RemoteLogResponseAction` and a protobuf receiver, or a carefully
audited Lua hook) is real, non-trivial production feature work directly
on the DNS hot path -- the exact kind of change that needs its own
careful correctness and performance validation (per-query overhead,
back-pressure/drop behavior under load, no impact on answer latency)
rather than a rushed addition under time pressure in an already very
long session. Attempting it hastily risks the one invariant that must
never be compromised: DNS must keep answering correctly and fast
regardless of what analytics does.

## Recommendation

Treat as the top-priority remaining implementation item for the next
session, ahead of further hardware/performance re-verification --
performance numbers gathered without real production analytics traffic
flowing are measuring an easier workload than the appliance will
actually carry once this is wired up.
