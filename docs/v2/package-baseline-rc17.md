# RC17 clean-install acceptance + live verification of the blocked-action fix

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc17-1_all.deb`
(sha256 `3b3d2c60b71632969fba0cfa0668a638c777b78ce391d348d74696a7a6ca7bc3`).

## What RC17 fixes over RC16

`docs/v2/blocked-action-not-populated-fix.md`: `evaluate_filtering`
(the real "why was this blocked" decision engine) was never actually
invoked anywhere in production -- every real blocked query was
silently logged as `action="allowed"`.

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap + login, real admin flow:
  `POST /api/services` (a real service definition for
  `rc17-blocked.test`), `POST /api/service-rulesets` (a real ruleset),
  `PUT /api/policy/global` (assigns the ruleset globally, real
  recompile+promote, `"promoted":true`).
- Real `dig` confirms the block is actually enforced at the DNS level:
  `rc17-blocked.test` -> `NXDOMAIN`; `example.com` -> `NOERROR`
  (unaffected).
- Real `GET /api/analytics/query-log` after a graceful
  analytics-worker restart (forces the parquet flush, per RC16's
  documented buffering behavior):
  - `rc17-blocked.test.`: `blocked=true, block_reason="rc17-blocked-svc"`
    -- the real fix, confirmed end to end through the real installed
    package's real HTTPS API.
  - `example.com.` and `not-blocked-rc17.test.`: `blocked=false` --
    unaffected traffic correctly not misclassified.

## Conclusion

The blocked-action fix is confirmed live and correct against the real
installed package's real HTTPS API. Container torn down after
verification.
