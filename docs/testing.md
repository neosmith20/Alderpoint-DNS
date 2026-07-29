# Testing

Run individual suites:

```sh
/opt/bindguard/tests/test_bind_backend.sh
/opt/bindguard/tests/test_dnsdist_frontend.sh
/opt/bindguard/tests/test_blocklist_deploy.sh
/opt/bindguard/tests/test_blocklist_failure_paths.sh
/opt/bindguard/tests/test_analytics.py
/opt/bindguard/tests/test_local_dns.py
/opt/bindguard/tests/test_dns_cache.py
/opt/bindguard/tests/test_dns_cache_benchmark.sh
/opt/bindguard/tests/test_encryption.py
/opt/bindguard/tests/test_importer.py
/opt/bindguard/tests/test_backup.py
/opt/bindguard/tests/test_web_smoke.sh
/opt/bindguard/tests/test_backup_restore.sh
```

`tests/test_backup_restore.sh` (script-based, exercises `scripts/backup.sh`/
`scripts/restore.sh`) and `tests/test_backup.py` (native `app/backup.py`)
both remain in the suite; the scripts still work as a minimal, dependency-free
fallback path, while the native page is the primary, versioned, richer
workflow described below.

The web smoke test also renders DNS Settings with long path/version-like
content and asserts the responsive card/table wrapping rules that prevent
horizontal overflow. It also renders the analytics dashboard and query log with
long domain and IPv6-like values.

The Local DNS suite covers A and AAAA record creation, automatic PTR records,
forward and reverse zone rendering, editing, deletion, disabled records,
duplicate hostname/PTR warnings, invalid host/IP rejection, CNAME conflicts,
multiple reverse zones, advanced FQDN records outside the default internal
domain, serial increments, generated-zone rollback, dnsdist packet-cache
invalidation for managed local zones, BIND restart readiness, analytics client
aliases, PTR fallback display, CSV import/export, and hosts-file preview. The
web smoke test renders the Local DNS page with long domains, IPv6 clients, and
upstream-like strings to guard against horizontal overflow, routine Local DNS
confirmations, async form hooks, and toast feedback.

The analytics unit suite covers aggregate collection, counter resets, bucketing,
blocked-query detection, ordinary NXDOMAIN handling, protocol classification,
retention cleanup, database-size protection, malformed protobuf input, queue
overflow, privacy modes, query-log filtering, and microsecond-to-millisecond
conversion of dnsdist's polled `latency-avg100` stat.

The latency-accuracy audit (see `docs/progress.md`) added regression tests
proving: a one-second response displays as 1000ms; no microsecond/millisecond
multiplication error against the 4058.9us regression case; negative latency
from clock skew clamps to zero; an implausible (corrupted-timestamp) latency
is discarded rather than recorded; a delayed/backlogged analytics queue does
not inflate reported DNS latency, since latency is computed only from
timestamps dnsdist embeds in the protobuf payload; a poll where dnsdist has
not yet published `latency-avg100` does not crash or fabricate a sample; and
protocol classification is correct across UDP, TCP, DoH, DoH3, DoT, and DoQ.

The web smoke test also checks that Query Log auto-refresh has a partial
`/query-log/partial` endpoint, updates only the result container, and persists
the auto-refresh state in browser session storage.

The BIND cache management suite (`tests/test_dns_cache.py`) covers default
cache-size sizing from VM memory, validation bounds (including rejecting a
cache size above 75% of total RAM and inverted min/max TTL pairs), generated
BIND syntax for both prefetch/serve-stale on and off, the idempotent
named.conf.options include migration, a successful staged deploy, rollback
to the previous file on a failed post-deploy health check, invalid settings
never touching the live file, all three flush scopes (all/name/subtree),
newest-request-wins flush processing, flush-failure recording, and cache
hit-percent computation from BIND's statistics-channels JSON API.
`tests/test_dns_cache_benchmark.sh` proves cache effectiveness on live BIND
using its own `CacheHits`/`CacheMisses` counters across a cold query followed
by a repeated (cached) query, rather than asserting on noisy wall-clock
timing. The web smoke test also renders the Cache page with a long flush
target to guard against horizontal overflow.

The Upstream Resolvers suite (`tests/test_upstream_dns.py`) covers importing
existing BIND forwarders, changing a standard DNS upstream, DoH URL/bootstrap
validation (including rejecting query parameters), generated dnsdist DoH/DoT
backend syntax, multiple enabled resolvers, rollback after a failed functional
resolution check, and SQLite persistence across a new connection. The web
smoke test checks the DNS Settings upstream UI, async form hooks, protected
routes, and the grouped navigation/global status shell. Live deployment on
this VM migrated the existing four BIND forwarders into managed plain-DNS
upstream rows, generated the dnsdist loopback upstream listener, and verified
resolution through both BIND (`127.0.0.1:5353`) and client-facing dnsdist
(`127.0.0.1:53`).

Run the combined suite:

```sh
/opt/bindguard/tests/test_acceptance.sh
```

The Encryption Settings suite (`tests/test_encryption.py`) covers settings
validation, real self-signed and local-CA certificate generation with
cert/key match checking, mismatched-pair rejection, upload staging and
consumption, the one-time `dnsdist.conf` parameterization migration
(including preserving the existing console/webserver secrets and being
idempotent), env-override rendering, full deploy success/rollback/
unchanged/forced-redeploy-on-cert-regen paths, DNSCrypt failing gracefully
without blocking other protocols, client connection info, and Apple
`.mobileconfig` content for DoH and DoT. Live verification on this VM ran
real per-protocol queries (`dig` for plain, `dnspython`'s
`dns.query.https`/`dns.query.quic` for DoH/DoH3/DoQ, `kdig +tls` for DoT)
through the actual deploy path, not just mocked unit tests.

The Import and Migration suite (`tests/test_importer.py`) covers CSV/hosts/
zone/BindGuard-CSV parsing, column-mapping auto-detection, preview
classification (valid/invalid/duplicate/conflict) against a real Local DNS
database, all three conflict policies (skip/merge/replace, each verified to
do exactly what it claims and never silently overwrite an existing record),
apply-then-rollback round-tripping, and AdGuard Home YAML translation
(blocklist sources, custom allow/block rules, rewrites, client aliases, and
the untranslatable/unsupported lists). Live verification imported real
records through the actual privileged deploy path and confirmed they
resolved from both BIND and dnsdist before rolling back.

The Backup and Restore suite (`tests/test_backup.py`) covers the real SQLite
online-backup mechanism (including under concurrent writes and correct
stripping of analytics/auth rows when those components are disabled),
manifest/checksum generation, dry-run restore preview never touching live
state, all restore code paths (component-scoped, full-database merge,
rollback-on-forced-failure, rollback-on-failed-health-check), retention
pruning, and the unprivileged-request/privileged-apply handoff pattern
including one-time password-file consumption. Live end-to-end verification
on this VM (create a real backup, mutate a real custom rule, restore,
confirm reversion, confirm file ownership, confirm DNS resolved throughout)
caught and fixed two real bugs in file-ownership handling during restore —
see `docs/progress.md`'s Backup and Restore milestone for detail.

The Replication suite (`tests/test_replication.py`) covers payload allowlist
exclusion, replica rollback when deploy fails, successful replacement of
replicated settings while preserving node-local identity keys, enrollment
staging, and revoked-client-certificate rejection. Live verification in
`/tmp/replica-test` enrolled a real temp replica against the local primary,
applied generation 1, confirmed drift detection before/after a manual edit,
confirmed failed-sync rollback left the temp replica state restored, and
confirmed a temporarily revoked peer was denied by the primary listener.

Manual protocol tests:

```sh
dig @127.0.0.1 -p 53 cloudflare.com A
dig @127.0.0.1 -p 53 cloudflare.com A +tcp
kdig +https @127.0.0.1 -p 443 +tls-ca=/etc/bindguard/certs/bindguard-lab.crt +tls-hostname=bindguard.local cloudflare.com A
kdig +tls @127.0.0.1 -p 853 +tls-ca=/etc/bindguard/certs/bindguard-lab.crt +tls-hostname=bindguard.local cloudflare.com A
kdig +quic @127.0.0.1 -p 853 cloudflare.com A
```
