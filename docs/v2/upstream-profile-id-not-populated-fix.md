# Real defect found and fixed: `upstream_profile_id` never populated for real dnsdist-sourced analytics events

Found in the same investigation pass as `cache_profile_id`
(`docs/v2/cache-profile-id-not-populated-fix.md`) and the blocked-action
fix (`docs/v2/blocked-action-not-populated-fix.md`) -- the same root
cause pattern, discovered by continuing the audit of every
`NormalizedQueryEvent` field against what the real receiver pipeline
actually populates.

## What was found

`upstream_profile_id` -- the real `"upstream"` filterable query-log
column (`app/v2/analytics_query.py`) -- was always blank for every
real dnsdist-sourced event, for the exact same reason as the other two
fixes: the per-client `EffectivePolicy` was already being compiled at
the exact call site that needed this value, and it simply was never
read for this field either.

## Fix

One-line fix at the same call site as the `action`/`block_reason`
fix: `record.setdefault("upstream_profile_id", policy.upstream_profile_id
if policy else "")`.

## Verification

New test:
`tests/v2/test_ctl_analytics_worker_policy_exclusion.py::test_real_upstream_profile_id_is_populated_not_left_blank`
-- a client with a real `upstream_profile_id="secure-dns-profile"`
override, confirmed threaded through to the real written Parquet
segment's `upstream` column.

Full suite: 2076 passed (`tests/`), 884 passed (`tests/v2/`), no
flakes this pass.
