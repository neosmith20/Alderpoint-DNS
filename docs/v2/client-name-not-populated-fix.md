# Real defect found and fixed: `client_name` never populated for real dnsdist-sourced analytics events

Found in the same investigation pass as `cache_profile_id`,
`action`/`block_reason`, and `upstream_profile_id` -- the same root
cause pattern, discovered by finishing the field-by-field audit of
`NormalizedQueryEvent` against what the real receiver pipeline
actually populates.

## What was found

`client_name` (a real projectable/sortable query-log column,
`app/v2/analytics_query.py`'s `_PROJECTABLE_COLUMNS`/`_SORTABLE_COLUMNS`)
was always blank for every real event with a registered managed
client, even though `client_id` (the exact value needed to look up the
name) was already resolved right there in `_effective_flags_for_client`
and simply never used to fetch it.

Also audited the remaining unused `NormalizedQueryEvent` fields
(`network_id`, `group_ids`, `encrypted_transport`) for the same
pattern -- confirmed these are **not** read by either downstream sink
(`app/v2/parquet_writer.py`'s `_COLUMN_NAMES`, `app/v2/aggregates_db.py`),
so populating them would have no observable effect anywhere; not
pursued further, unlike the four fields that genuinely reach a real
exposed column.

## Fix

`_effective_flags_for_client` now also does one extra `SELECT name
FROM clients WHERE id=?` (only when a client was actually matched) and
returns `client_name` as a fifth tuple element; the drain loop threads
it through via `record.setdefault("client_name", client_name)`.

## Verification

New test:
`tests/v2/test_ctl_analytics_worker_policy_exclusion.py::test_real_client_name_is_populated_not_left_blank`
-- a real registered client named "Kids Tablet", confirmed threaded
through to the real written Parquet segment's `client_name` column.

Full suite: 2077 passed (`tests/`), 885 passed (`tests/v2/`), no
flakes this pass.

## Conclusion

This closes out the "policy/client field silently left blank in real
analytics events" investigation for this continuation. Every
`NormalizedQueryEvent` field that reaches a real, exposed downstream
column has now been audited and, where genuinely populatable from
already-available data, fixed: `cache_profile_id`, `action`/
`block_reason`, `upstream_profile_id`, `client_name`. The remaining
gaps (`latency_ms`, `cache_status` beyond the earlier heuristic,
`network_id`/`group_ids`/`encrypted_transport`) are honestly
documented as not derivable from what dnsdist's protobuf stream
carries or not consumed by any real sink, not silently left as
unexamined placeholders.
