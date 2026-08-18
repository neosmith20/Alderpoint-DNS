# RC18 clean-install acceptance + live verification of the upstream_profile_id fix

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc18-1_all.deb`
(sha256 `8f02a7d27d14e3d7fab3aa4395acbf6947a0d6cfdb24465484fdaf784ef1f91d`).

## What RC18 fixes over RC17

`docs/v2/upstream-profile-id-not-populated-fix.md`: `upstream_profile_id`
(the real `"upstream"` filterable query-log column) was always blank
for every real dnsdist-sourced analytics event.

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login, `PUT /api/policy/global` sets
  `upstream_profile_id="rc18-secure-profile"` (real recompile+promote).
- Real `example.com` query still resolves correctly (`upstream_profile_id`
  is a policy label, not a hard requirement that a matching upstream
  server config exist under that exact name -- confirmed non-breaking).
- Real `GET /api/analytics/query-log` after a graceful analytics-worker
  restart: `upstream = "rc18-secure-profile"` -- real, non-blank,
  confirmed end to end through the real installed package's real
  HTTPS API.

## Conclusion

This closes out the current pass of "policy field silently left blank
in real analytics events" defects found this continuation
(`cache_profile_id`, `action`/`block_reason`, `upstream_profile_id`),
all sharing the same root cause (the per-client `EffectivePolicy` was
already compiled at the exact point needed, just not fully read) and
all now live-verified against real installed packages. Container torn
down after verification.
