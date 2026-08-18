# Real defect found and fixed: `cache_profile_id` never populated for real dnsdist-sourced analytics events

Roadmap continuation, found while tracing the unused `"prewarm"`
`cache_status` enum value -- led to auditing every field
`NormalizedQueryEvent` defines against what the real analytics-
protobuf-receiver pipeline actually populates.

## What was found

`app/v2/analytics_query.py` exposes `cache_profile_id` as a real,
admin-facing filterable and sortable query-log column
(`_FILTERABLE_COLUMNS`/`_SORTABLE_COLUMNS`). `app/v2/parquet_writer.py`
has always had a dedicated column for it. But every real event
produced by `scripts/v2/alderpointdns_v2_ctl.py`'s
`analytics-protobuf-receiver`/`cmd_analytics_worker` pipeline left it
at `NormalizedQueryEvent`'s own default, `""` -- silently making this
entire feature non-functional for all real traffic, ever since the
receiver was first wired up.

The machinery to compute the real value already existed and was
already being invoked one function away: `_query_log_flags_for_client`
(the same function that resolves `query_log_enabled`/
`statistics_enabled` per client) already compiles a full
`EffectivePolicy` via `compile_effective_policy`/
`compile_effective_policy_from_store` -- `compile_cache_profile(policy)
.profile_id` was simply never called on it.

## Fix

`_query_log_flags_for_client` renamed to `_effective_flags_for_client`
and extended to also return `compile_cache_profile(policy).profile_id`,
threaded into the inbox record as `effective_cache_profile_id` before
`NormalizedQueryEvent(**record)`, exactly the same pattern already used
for the other two flags (single per-client policy compile per drain
cycle, cached for the cycle's duration).

## Verification

New test:
`tests/v2/test_ctl_analytics_worker_policy_exclusion.py::test_real_effective_cache_profile_id_is_populated_not_left_blank`
-- gives one client a real answer-affecting policy override
(`upstream_profile_id="custom-profile"`), reads the real written
Parquet segment back with `pyarrow`, and confirms the recorded
`cache_profile_id` is both non-blank and genuinely different from the
global default's own compiled profile id (not just "some string").

Full suite: 2074 passed (`tests/`), 882 passed (`tests/v2/`).
