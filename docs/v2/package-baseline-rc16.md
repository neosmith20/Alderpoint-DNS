# RC16 clean-install acceptance + live verification of the cache_profile_id fix

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc16-1_all.deb`
(sha256 `05bb0f7df4eda4603aa0a067d83d0f50b249b7f5826b66a34c32f953a818ecf8`).

## What RC16 fixes over RC15

`docs/v2/cache-profile-id-not-populated-fix.md`: `cache_profile_id`
was always blank for every real dnsdist-sourced analytics event, a
real filterable/sortable query-log column. Fixed by threading the
already-compiled `EffectivePolicy` through `compile_cache_profile`.

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login, one real `example.com` query.
- Real `GET /api/analytics/query-log` row (after a graceful
  `systemctl restart alderpointdns-v2-analytics` to force the
  parquet writer's segment flush -- see below):
  `cache_profile_id = "1b09cded91904c3d66aa57ca0d576dc7"`, a real,
  non-blank compiled profile digest, confirming the fix end to end
  through the real installed package's real HTTPS API.

## Transparency note found along the way (not a regression, not fixed this pass)

`app/v2/parquet_writer.py`'s raw per-query segments buffer in memory
for up to `max_seconds_per_segment` (default **3600s = 1 hour**) or
`max_rows_per_segment` (50,000) before being written to disk --
confirmed live: a single real query did not appear in
`/api/analytics/query-log` at all until the analytics-worker service
was restarted (which forces a flush via its own graceful-shutdown
`finally: pipeline.parquet_writer.close()`, already correctly wired).
Real, deliberate tradeoff (avoids many tiny Parquet files on a
resource-constrained appliance), and the aggregate statistics path
(`time_buckets`/`dimension_counts`, used by the dashboard's live
numbers) is NOT affected -- that already updates within seconds, as
confirmed in every prior RC's live checks in this session. The
consequence is specifically that the **raw per-query drill-down log**
can lag up to an hour behind real traffic on a quiet appliance unless
a service restart happens to flush it sooner. Not fixed this pass
(a real architecture tradeoff, not a defect, and changing the default
segment window deserves explicit product input rather than a
unilateral change this late in RC hardening) -- documented here for
transparency and left as a genuine, known, open design consideration.

## Conclusion

The `cache_profile_id` fix is confirmed live and correct against the
real installed package's real HTTPS API. Container torn down after
verification.
