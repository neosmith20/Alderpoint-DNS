# V2 private10 — package baseline after reload/dnsdist StartLimit fix

Rebuilt twice in sequence during hardware/performance testing:

- **private9**: fixed `alderpointdns-v2-dnsdist-reload.service`/`.path`'s
  systemd default start-rate limit (see
  `docs/v2/hardware-performance-1g-2g.md` for the full defect writeup).
  This alone was insufficient -- retesting the same burst surfaced the
  identical failure one layer deeper, in `alderpointdns-v2-dnsdist.service`
  itself.
- **private10**: also fixed `alderpointdns-v2-dnsdist.service`'s own
  start-rate limit. This is the artifact all hardware/performance results
  in `docs/v2/hardware-performance-1g-2g.md` were measured against.

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~private10-1`
- Filename: `alderpointdns-v2_2.0.0~private10-1_all.deb`
- SHA-256: `3bfda1f668c1a9f5d7f6efdc8b44656bc9bd75b69fe90e979a91bee426b5f552`

## Acceptance

Re-ran the exact 50-local-DNS-record burst that originally exposed the
defect, in fresh containers, at both 1 GiB and 2 GiB memory constraints:
all three affected units (`alderpointdns-v2-dnsdist`,
`alderpointdns-v2-dnsdist-reload.service`,
`alderpointdns-v2-dnsdist-reload.path`) stayed `active` throughout, and
all 50 records resolved correctly afterward (`ok: 50 fail: 0`). Full
hardware/performance results (sustained throughput, latency percentiles,
memory/CPU/OOM) in `docs/v2/hardware-performance-1g-2g.md`.

Base clean-install acceptance not independently re-run for this artifact
beyond what the hardware/performance test itself exercised (bootstrap,
login, real API mutations, sustained real DNS traffic) -- no
postinst/provisioning changes since `private8`.
