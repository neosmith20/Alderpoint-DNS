# RC27 clean-install acceptance + real packaged Tier B worker verification

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc27-1_all.deb`
(sha256 `446f4c7416e0951d323733bb98a65fe20903e431f4b15a500bb3431ecee48791`).

## What RC27 adds over RC26

`docs/v2/tier-b-cache-key-defect-fix.md`: fixes a real defect where
Tier B prewarm's own query shape never matched real clients' dnsdist
cache key, silently defeating prewarm's entire purpose. The core fix
and its proof were already established with rigorous, real,
dnsdist-cache-hits-counter-based verification on the dev host (see
that doc); this RC verifies the fix runs correctly through the actual
packaged worker entry point against a real installed appliance.

## Real, live verification

Fresh RC27 target:

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real working-set index seeded directly (simulating a real persisted
  Tier B snapshot from before a restart).
- Real `python3 scripts/v2/alderpointdns_v2_ctl.py tier-b-worker --once
  --dns-address 127.0.0.1 --dns-port 53` (the exact packaged/systemd
  entry point, `app/v2/tier_b_worker.py`'s fixed `_build_query()` under
  the hood) -> `tier-b-worker: attempted 1 prewarm resolutions`,
  real success against the real live appliance dnsdist.
- Real HTTPS bootstrap + login.
- Real `dig` queries continued answering correctly throughout,
  `NRestarts=0`, `active` the whole time.

## Note on this RC's verification scope

The core fix was proven with the strongest available signal (dnsdist's
own real `cache-hits` counter via its console) on the dev host, where a
console is available by design for ad-hoc dnsdist instances -- V2's
real production compiled runtime deliberately has no console at all
(a documented, deliberate architecture choice, see
`docs/v2/dnscrypt-transport-implemented.md`'s "why a disposable scratch
instance" section for the same rationale applied elsewhere this
session), so an equivalent live cache-hits-counter check against the
packaged appliance's actual production dnsdist isn't available by the
same means. The real analytics query-log API was checked as an
alternative real-product-native verification path but the raw
per-query log buffers up to 1 hour before flushing to disk by design
(the same RC16-documented behavior), too slow for this RC's
verification window. This RC therefore confirms the fixed code path
runs correctly, without error, against a real installed appliance and
does not destabilize it -- the cache-hit-reuse proof itself remains
the dev-host, dnsdist-console-based verification recorded in
`docs/v2/tier-b-cache-key-defect-fix.md`.

## Conclusion

Clean install, real packaged worker execution succeeds against a real
live appliance, zero restarts, DNS unaffected throughout. Container
torn down after verification.
