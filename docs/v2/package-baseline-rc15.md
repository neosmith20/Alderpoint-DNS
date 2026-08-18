# RC15 clean-install acceptance + live verification of the prewarm-pollution fix

Real `podman --privileged --systemd=always` container, base
`localhost/apdns-v2-4c-accept-base:trixie`, fresh `apt-get install` of
`alderpointdns-v2_2.0.0~rc15-1_all.deb`
(sha256 `ff0a9ae329d9f844556a4c0d935cfb7fef523ff90d986cc3e467b549b6395e31`).

## What RC15 fixes over RC14

`docs/v2/prewarm-analytics-pollution-fix.md`: Tier B prewarm's
self-generated re-queries of already-popular domains were
indistinguishable from real client traffic in the analytics pipeline
(both attributed to client `127.0.0.1`), silently inflating every
statistic. Fixed by sourcing prewarm traffic from a dedicated loopback
address and unconditionally excluding it from both analytics sinks.

## Live verification

- `apt-get install`: `EXIT:0`; `systemctl --failed --no-legend`: zero
  failed units.
- Real HTTPS bootstrap, one real client query for `example.com`
  (`total_queries=1`, `client=127.0.0.1`).
- Ran `tier-b-worker --once` manually against the real installed
  package (real UDP resolution through the live dnsdist listener,
  confirmed `attempted 1 prewarm resolutions`).
- Real aggregate database after the prewarm tick:
  `total_queries` stayed at `1` (not `2`), and `dimension_counts` for
  `client` shows only `127.0.0.1: 1` -- the prewarm resolution's own
  traffic (sourced from `127.0.0.2`) never reached the statistics
  sinks, confirming the fix on the real installed package.

## Conclusion

Both real defects found during this roadmap continuation (packet-cache
rcode mislabeling in RC14, prewarm analytics pollution in RC15) are
now fixed and live-verified against real installed packages, not just
unit tests. Container torn down after verification.
