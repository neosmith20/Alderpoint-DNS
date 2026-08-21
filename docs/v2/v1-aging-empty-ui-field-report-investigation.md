# V1.1.1 field report investigated: "after several days the UI looks empty; a full restart fixes it" -- real root cause found live, V2 hardened against the same class

Owner-beta closure item: investigate a real V1.1.1 field report (not a
hypothesis) -- after several days of uptime, the appliance can reach a
state where the UI behaves as though data/configuration is empty, and
only a full server restart restores it. Do not assume the cause is the
previously-fixed historical analytics FD leak.

## What was found: not speculation, reproduced in this environment's own long-running V1.1.1 instance

This host has its own real, long-running V1.1.1 test appliance
(`alderpointdns-analytics.service`, journalled under hostname
`alderpointdns-1`). Its own systemd journal already contains a real,
unprompted occurrence of exactly the reported failure class:

```
Aug 16 23:47:53 alderpointdns-1 analytics.py[484161]: Exception in thread Thread-2 (writer_loop):
Aug 16 23:47:53 alderpointdns-1 analytics.py[484161]: Traceback (most recent call last):
  ...
  File "/opt/alderpointdns/app/analytics.py", line 1112, in writer_loop
    cfg = self.current_settings()
  File "/opt/alderpointdns/app/analytics.py", line 991, in current_settings
    return settings(conn)
  File "/opt/alderpointdns/app/analytics.py", line 334, in settings
    return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM analytics_settings")}
sqlite3.OperationalError: database is locked
```

Immediately before this, the journal shows repeated, real
`SQLITE_BUSY` contention already in progress (`analytics: database
lock recovered after N retry(s) during retention cleanup`, several
times in the preceding hour) -- genuine concurrent load on
`alderpointdns.db`, not a synthetic condition.

**No restart followed.** The unit's own `Started`/`Stopping` log lines
show nothing between `Aug 14 08:43:21` (its last routine restart) and
`Aug 19 21:30:12` (~2 days 21.5 hours later, restarted for unrelated
reasons by a later session, not by any health mechanism). For that
entire window, the collector process was reported "active (running)"
by systemd the whole time, while its `writer_loop` thread -- the only
thing that ever writes a real query event, cleans up retention, or
updates its own heartbeat file (`_write_heartbeat`, read by
`analytics-writer-heartbeat.json`) -- was simply gone. This is
precisely "process alive, UI/data effectively frozen/stale-looking,
only a restart fixes it."

## Root cause: an unprotected SQLite call sits directly in two of the collector's three loop bodies

`app/analytics.py`'s `Collector.current_settings()`:

```python
def current_settings(self) -> dict[str, str]:
    with connect() as conn:
        return settings(conn)
```

is called unconditionally, on every iteration, directly inside both
`writer_loop()` and `poll_loop()` -- **outside** `_writer_cycle()`'s
own try/except (which only wraps `_write_events`/`_run_cleanup`) and
with no `db_retry.retry_on_locked()` wrapping at all, unlike literally
every other write path in this file (`_write_events`, `_run_cleanup`,
`init_analytics_db`'s own docstring explains exactly why that
retry exists). A transient `SQLITE_BUSY`/`database is locked` here --
which the surrounding log lines prove really happens under real
concurrent load -- raises straight out of the `while` loop and kills
that thread. `serve_tcp` and `poll_loop` never write a heartbeat or
report failure at all (only `_writer_cycle` does, via
`_write_heartbeat`/`_notify_writer`), so a dead `writer_loop` thread
is invisible to every health signal V1 has: the process, the systemd
unit, and (except for the *absence* of fresh writes an operator would
have to know to check for) the heartbeat file all keep reporting
normally.

This is a real, minimal, previously-unidentified gap, distinct from
the historical analytics FD leak this brief specifically warned not to
assume: it is a **missing retry**, not a resource leak, and it kills
the thread on the very first unlucky lock contention rather than after
gradual resource exhaustion.

## Other real candidates inspected, ruled less likely as *the* cause but noted as related risk

- `serve_tcp()`'s blocking `server.accept()` has no exception handling
  beyond `socket.timeout` -- an `OSError` (e.g. FD exhaustion) would
  silently kill the TCP listener thread the same way. Plausible over
  much longer uptimes than reproduced here; no live evidence of this
  one actually firing was found in this instance's journal (FD count
  live-checked on this host's own 26+-hour instance: 5 FDs, 5 threads,
  no growth observed -- but that instance is not under sustained real
  client-connection churn, so this does not rule the class out, only
  this specific instance/window).
- WAL/checkpoint behavior, retention/rotation, and the connection
  lifecycle elsewhere in `analytics.py` (`_write_events`,
  `_run_cleanup`, `init_analytics_db`) all already use short-lived
  `with connect() as conn:` blocks and the shared retry helper
  correctly -- no stale-cached-connection or lock-starvation pattern
  found there.
- `webapp.py`'s own request-scoped DB access was not implicated by this
  journal evidence (the dead thread is analytics-specific); a
  broader stale-frontend-state class was not reproduced and is not the
  documented mechanism here.

V1 is not being repaired (out of scope for this pass; the one-line fix
would be wrapping `current_settings()`'s body in
`db_retry.retry_on_locked()`, matching every sibling call in the same
file, but is left as a documented finding rather than a shipped V1
change).

## What this means for V2, and what was actually fixed there

V2's four periodic background workers (analytics-worker,
discovery-worker, tier-b-worker, schedule-worker;
`scripts/v2/alderpointdns_v2_ctl.py`'s shared `_run_loop`) are
architecturally different from V1's multi-thread-in-one-process
collector: **each worker command is its own systemd unit's entire
process**, and `_run_loop` already wrapped every `tick_fn()` call in a
blanket `except Exception` (logged, loop continues) before this pass --
so V2 was never at risk of V1's exact crash-the-thread failure mode
from an uncaught exception like the one reproduced above.

What V2 *did* lack, identically to V1's real gap, was any way to tell
"this worker's process hasn't exited" (all systemd's own view can ever
say) apart from "this worker's loop is actually still making
progress" -- e.g. a tick that hangs forever inside a lock wait, a dead
socket, or any other stall that never raises. That is now closed:

- `app/v2/worker_heartbeat.py` (new): each `_run_loop` iteration
  records a heartbeat before calling `tick_fn` (`status="running"`,
  tick start time) and after it returns or raises
  (`status="ok"`/`"tick_failed"`), with a real progress counter
  (`tick_count`) and last result. `HeartbeatState.is_stale()` is the
  health predicate: stale if the current tick has been running longer
  than `max(120s, 3x its own interval)`, or if there is no recent
  successful tick within that same window -- deliberately not stale
  just because a tick legitimately found no work (an empty inbox is a
  real, healthy outcome, not the failure this defends against).
- `scripts/v2/alderpointdns_v2_ctl.py`'s `_run_loop` now writes these
  heartbeats around all four call sites
  (`tests/v2/test_worker_heartbeat.py::TestAllFourSharedWorkersAreWired`
  statically guards that a fifth worker or a refactor of the existing
  four can't silently lose this wiring).
- `GET /api/health`'s `background_workers` component reports each
  worker's live status/staleness; a stalled worker demotes overall
  health to `"degraded"` (never silently `"ok"`), the same way BIND/
  analytics-dependency degradation already does.

See `tests/v2/test_worker_heartbeat.py` and
`tests/v2/test_webapp.py::TestBackgroundWorkerHealth` for direct
coverage, including the actual field-report shape (a tick stuck for
far longer than its own interval, with the process otherwise
untouched) reported as `stale` rather than folded into `"ok"`.
