# V2 private11 — package baseline after Tier B resolve_fn fix

Rebuilt because `scripts/v2/alderpointdns_v2_ctl.py`'s `cmd_tier_b_worker`
changed (real defect fix: the fake inline `resolve_fn` that never
actually queried DNS was replaced with the real, already-tested
`app/v2/tier_b_worker.py::make_udp_resolve_fn`). See
`docs/v2/tier-b-and-failure-domains.md` for the full writeup.

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~private11-1`
- Filename: `alderpointdns-v2_2.0.0~private11-1_all.deb`
- SHA-256: `cedc7aea615d19def4037016a23b77a0b4ee8d06e2df0d9050a68c0ae54666cc`

## Acceptance

All Tier B and failure-domain results in
`docs/v2/tier-b-and-failure-domains.md` were measured against this exact
artifact: real cold-vs-prewarm latency comparison (31.57ms -> 17.24ms),
corruption/kill/removal degrade-to-cold-not-outage checks, and a full
failure-domain pass (7 components individually + combined, plus
control.db/secrets removed entirely after runtime compiled) confirming
DNS answering independence.

No postinst/provisioning changes since `private10`; base clean-install
acceptance not independently re-run beyond what this session's testing
itself exercised (real install, real service start, real sustained DNS
serving throughout).
