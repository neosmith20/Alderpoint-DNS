# Real defect found and fixed: blocked queries silently logged as "allowed" in analytics

Roadmap continuation, discovered while auditing `NormalizedQueryEvent`
fields the real receiver pipeline never populates -- following the
same pattern that surfaced the `cache_profile_id` gap
(`docs/v2/cache-profile-id-not-populated-fix.md`).

## What was found

`app/v2/filtering_decision.py`'s `evaluate_filtering` -- a real,
independently tested "why was this blocked" decision engine, exactly
what the roadmap's §47 requirement calls for -- was **never called
anywhere in production code**, confirmed by a repo-wide grep: every
reference to it outside its own module was in a test file. Every real
event produced by the analytics-protobuf-receiver pipeline defaulted
to `action="allowed"`/`block_reason=""` unconditionally, meaning the
entire "blocked queries" dashboard/statistic was silently
non-functional for real traffic, even for a domain an admin had
explicitly configured to be blocked.

Traced why this was invisible until now: real blocking is enforced
entirely via terminal dnsdist actions (`SpoofAction`/`RCodeAction`,
`app/v2/dnsdist_policy_runtime.py`) -- the exact same wire shape as
local-DNS/SafeSearch answers (a query message with no matching
response, per this session's earlier findings), so a genuinely blocked
query was logged with whatever rcode the spoofed answer carried and no
signal at all distinguishing it from an ordinary allowed answer.

Also confirmed live during this investigation: `app/v2/bind_rpz_gen.py`'s
RPZ zone is **always empty** in the real running system --
`cmd_generate_runtime` unconditionally calls
`render_rpz_zone({}, [], ...)`. All real blocking, including migrated
V1 custom block/allow lists (`app/v2/migration_convert.py`'s
`migrate_filtering_to_control_db`), goes through the same
`service_definitions`/`service_domains` mechanism `evaluate_filtering`
already reads -- confirming it is the complete real decision source in
this architecture today, not a partial one.

## Fix

`_query_log_flags_for_client` (already renamed `_effective_flags_for_client`
in the previous fix) now also returns the compiled `EffectivePolicy`
object itself, not just the extracted flags. A new
`_action_for_event(conn, policy, qname)` calls `evaluate_filtering`
per event (reusing the client's already-compiled policy, no extra
policy compile) and sets `action`/`block_reason` on the record before
`NormalizedQueryEvent(**record)`. Fails safe: any error defaults to
`("allowed", "")` rather than risking a false "blocked" classification
or crashing the drain loop.

## Verification

New test:
`tests/v2/test_ctl_analytics_worker_policy_exclusion.py::test_real_blocked_query_gets_action_blocked_not_silently_allowed`
-- a real client with a real service-blocking ruleset assigned, one
matching query and one non-matching query, read back from the real
written Parquet segment: the matching query shows
`blocked=True, block_reason="blocked-app"`; the non-matching query
shows `blocked=False`.

Full suite: 2074 passed (`tests/`), 883 passed (`tests/v2/`; 1
confirmed non-regression flake, passes 1/1 on isolated retry).
