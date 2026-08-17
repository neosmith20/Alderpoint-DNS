# V2 private RC3 — package baseline + real migration re-verification (roadmap Priority 12)

## Source

- Source SHA: `f37ebab...` (commit "Fix real live migration defect
  found during RC2 acceptance: custom filter rules never migrated")
- Build environment: this session's real KVM host,
  `scripts/build-v2-deb.sh --output-dir /tmp/alderpointdns-v2-rc3`

## Artifact

- Package/version: `alderpointdns-v2` `2.0.0~rc3-1`
- Filename: `alderpointdns-v2_2.0.0~rc3-1_all.deb`
- Architecture: `all`
- Size (see build output; not independently re-measured beyond the
  build's own SHA-256 below)
- SHA-256: `d033753550c9f296786cc1cc3cad7699edcd7c908f9fc6b4e7b34af430f49e9f`

## Real V1 -> RC3 migration: bug found, fixed, and re-verified live

Fresh Debian 13 container. Real `apt-get install` of a freshly rebuilt
`alderpointdns_1.1.1-1_all.deb` (source SHA matching this session's V1
changes too). Real V1 admin bootstrap through the actual `/setup` HTTP
route. Representative data seeded through the **real V1 application
functions** (`clients.create_client`, `local_dns.add_record`,
`custom_rules.add_rule` x20, `notifications.add_provider`,
`upstream_dns.add_resolver`, `encryption.update_settings`) rather than
raw SQL against assumed table shapes -- this is what actually exposed
the bug: raw-SQL-seeded fixtures (including this project's own shared
test fixture) had been unknowingly matching the same wrong table the
migration code read from.

**First run** (pre-fix, RC2-era code): `alderpointdns-v2-ctl migrate`
reported `filtering_blocked: 0` for a V1 install with 20 real, enabled
filter rules. Root-caused, fixed, and regression-tested (commit
`f37ebab`, full detail there): `migrate_filtering()`/`build_preview()`
read the bare `custom_rules` table, which is dead V1 schema no current
V1 code path ever writes to -- every real V1 admin's real filter rules
live in `custom_filter_rules`. This bug has silently affected every
V1->V2 migration this project has ever run.

**Re-run against RC3** (post-fix), fresh containers both sides:
`migrate --promote` reported `filtering_blocked: 10` (matches the 10
real block rules seeded), `local_dns_records_migrated: 10`. Live
verification after restarting the affected services:

- `rule3.example.test` (migrated blocked domain): real UDP query ->
  instant local `NXDOMAIN` (0ms query time, no upstream round trip) --
  the real RPZ block, not a passthrough negative answer
- `host1.lan` (migrated local DNS record): real UDP query -> `NOERROR`,
  `10.20.1.1`
- `example.com` (real upstream): real UDP query -> `NOERROR`, real
  answer
- Expected warnings correctly surfaced, not silent: the 10 migrated
  V1 allow-list domains (no V2 migration target, by design -- they
  exist to override a V1-only default blocklist), and the one DoT
  upstream resolver (skipped -- mixed-transport upstream profiles
  aren't supported, V1's 4 plain resolvers migrated instead)

## Residual, unresolved: one observed dnsdist restart anomaly (not reproduced)

During this same session, immediately after promoting the migration
and manually running `systemctl daemon-reload` followed by a batch
`systemctl restart` of all 8 V2 services (including
`alderpointdns-v2-dnsdist`), the dnsdist unit entered a crash loop:
`Fatal error: binding socket to 0.0.0.0:53: Address already in use`,
repeating every ~3s. `ss -ulnp` showed the *previous* dnsdist process
(from the promotion's own automatic `alderpointdns-v2-dnsdist-reload
.path`-triggered restart, which had logged a clean success ~43 seconds
earlier) still alive and holding port 53, orphaned from systemd's
tracking of the unit's current main PID. Manually killing that orphaned
PID and restarting once more fully recovered DNS immediately, and the
migrated local-DNS/filtering behavior above was verified working
correctly after that recovery.

Attempted deliberate reproduction afterward, all unsuccessful:
3 consecutive plain restarts of just the dnsdist unit (clean each
time); `daemon-reload` immediately followed by a restart (clean);
5 explicit races of a config-file touch (simulating the promotion's
`.path` trigger) against a concurrent manual restart of the same unit,
0.05s apart (clean every time -- systemd correctly serializes concurrent
restart requests for the same unit, as expected); a full batch restart
of all 8 services together (clean, no failed units).

Not confirmed as a reproducible product defect and not chased further
this session given repeated failed reproduction attempts -- recorded
honestly as an unresolved, low-confidence, single-occurrence anomaly
for a future session to investigate with tighter instrumentation
(e.g. capturing `ss`/`journalctl` timestamps at sub-second resolution
around a real promotion event), not claimed as fixed or dismissed as
definitely environmental.

## Tests

`tests/v2`: 831 passed (includes the 2 new migration regression tests
for this fix). Full detail in commit `f37ebab`.
