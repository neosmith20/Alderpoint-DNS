# Testing

Run individual suites:

```sh
/opt/alderpointdns/tests/test_bind_backend.sh
/opt/alderpointdns/tests/test_dnsdist_frontend.sh
/opt/alderpointdns/tests/test_blocklist_deploy.sh
/opt/alderpointdns/tests/test_blocklist_failure_paths.sh
/opt/alderpointdns/tests/test_analytics.py
/opt/alderpointdns/tests/test_local_dns.py
/opt/alderpointdns/tests/test_dns_cache.py
/opt/alderpointdns/tests/test_dns_cache_benchmark.sh
/opt/alderpointdns/tests/test_encryption.py
/opt/alderpointdns/tests/test_custom_rules.py
/opt/alderpointdns/tests/test_importer.py
/opt/alderpointdns/tests/test_backup.py
/opt/alderpointdns/tests/test_admin_setup.py
/opt/alderpointdns/tests/test_administration.py
/opt/alderpointdns/tests/test_admin_cli.sh
/opt/alderpointdns/tests/test_notifications.py
/opt/alderpointdns/tests/test_web_smoke.sh
/opt/alderpointdns/tests/test_encryption_layout.sh
/opt/alderpointdns/tests/test_backup_restore.sh
/opt/alderpointdns/tests/test_deb_package_contents.sh
/opt/alderpointdns/tests/test_licensing_hygiene.sh
/opt/alderpointdns/tests/test_release_hygiene.sh
```

`tests/test_licensing_hygiene.sh` verifies the finalized license set is
intact and internally consistent: `LICENSE` contains the complete,
unmodified PolyForm Noncommercial License 1.0.0 text; `COPYRIGHT` carries
the exact Required Notice; `COMMERCIAL_LICENSING.md`,
`CONTRIBUTOR_LICENSE_AGREEMENT.md`, `TRADEMARKS.md`, and
`THIRD_PARTY_NOTICES.md` all exist; no tracked file (outside
`THIRD_PARTY_NOTICES.md`, dependency metadata, and
`CONTRIBUTOR_LICENSE_AGREEMENT.md`'s description of being adapted from the
Apache ICLA) claims Alderpoint DNS is MIT/GPL/AGPL/Apache/BSD-licensed,
"open source," unlicensed, or freely usable commercially; `README.md` and
`CONTRIBUTING.md` reference the finalized documents; and the built `.deb`
actually installs `LICENSE`/`copyright`/`COMMERCIAL_LICENSING.md`/
`THIRD_PARTY_NOTICES.md` under `/usr/share/doc/alderpointdns/`.

The first-run setup suite (`tests/test_admin_setup.py`) covers matching and
mismatched password confirmation, empty confirmation, username preservation
across a failed submission, forged/CSRF-mismatched direct POSTs (with and
without a prior page visit), and that neither password value ever appears in
response HTML on failure.

The Administration suite (`tests/test_administration.py`) covers password
change success (verifying the new hash, and that exactly the other sessions
-- never the acting one -- are revoked), wrong-current-password and
mismatched-new-password rejection (password left unchanged), the standalone
revoke-other-sessions action, successful and failed actions landing in the
audit log without credential content, and that the session list never
renders a raw session token.

The root-only recovery CLI suite (`tests/test_admin_cli.sh`) covers rejection
when run by a non-root account (via `runuser -u nobody`, regardless of the
test runner's own privilege level), `admin list`, `admin reset-password` via
both piped stdin and its own hashing round-tripping through `app.auth`
(the same implementation `app/webapp.py` uses), session revocation on reset,
the standalone `admin revoke-sessions` action, the ambiguous-multiple-admins
`--username`-required error, and that the plaintext password never appears
in CLI output or the audit log.

The Notifications suite (`tests/test_notifications.py`) covers provider
validation, secret masking (never rendered back), test-notification delivery
against mocked SMTP/HTTP, cooldown suppression, duplicate-fingerprint
suppression, recovery notices, delivery history accuracy, and each wired
event-category checker firing against fixture database state without real
systemd or network access.

Two more suites require tooling most CI environments won't have by default,
so they aren't run implicitly by the above and are called out separately:

```sh
/opt/alderpointdns/tests/test_clean_install_container.sh
```

`tests/test_deb_package_contents.sh` builds the `.deb` and statically
inspects its actual contents (control metadata, maintainer scripts,
`packaging/dnsdist.conf`, service units) for the fixes from the first clean
Debian 13 install failure: `secrets.env`/`dnsdist-api.key`/`dnsdist-web.creds`
chowned `root:alderpointdns` and chmod `0640`; the database and
`/var/log/alderpointdns` ownership recursively fixed after generation
(including reasserting `bind:bind` on the BIND log subdirectory, not just
recreating the directory); the AppArmor local override for named installed
and reloaded; `dnsdist (>= 1.9.0)` required in `Depends` -- the lowest bound
Debian 13's own archive `dnsdist` (1.9.x) satisfies with no third-party
repository, so a stock `apt-get install -y ./alderpointdns_*.deb` resolves
cleanly, while genuinely too-old builds still fail cleanly at dependency
resolution instead of silently pulling an incompatible one; the
`newRemoteLogger`/`RemoteLogResponseAction` calls fixed/made version-aware
for that build; DoH3/DoQ listener setup routed through a capability-safe
Lua wrapper *and* kept off by default / reported as unsupported in
Encryption Settings via `encryption.dnsdist_capabilities()`, since Debian's
own archive `dnsdist` lacks QUIC support (see `docs/dnsdist.md`); the web
password/API key hashed with dnsdist's own
`hashPassword()` before being written into `dnsdist.conf` (never the
plaintext); the `.dnsdist-conf-installed`/`.named-conf-installed`
first-install markers scoped under `/etc/alderpointdns` so `apt purge` +
reinstall doesn't reuse stale hashed credentials; `StartLimitIntervalSec`/
`StartLimitBurst` on the alderpointdns/analytics units and a dnsdist
drop-in override (the upstream unit ships `StartLimitInterval=0`, i.e. no
cap at all); and postinst no longer swallowing failures from database init,
config deploy, or service restart/enable with `|| true`, ending with an
explicit active-service gate for all four core services. It requires no
root access and no live system, only `dpkg-deb`.

`tests/test_clean_install_container.sh` builds the `.deb` and installs it in
a disposable, genuinely clean, **stock** Debian 13 + systemd container (via
`podman` or `docker`) that inherits no alderpointdns users, groups, files,
database, or generated configuration from the development machine it runs
on -- unlike running the installer or postinst directly against that
machine, which already has all of those from prior installs. It adds no
third-party APT repository, signing key, or pin of any kind: only
`apt-get update` against Debian's own repositories, then
`apt-get install -y ./alderpointdns.deb`, exactly like a beta tester on an
untouched Debian 13 VM, and it fails if `repo.powerdns.com` shows up
anywhere under `/etc/apt` at any point in the run. It then verifies:
`apt-get install` succeeds (dependency resolution against stock repos
alone, no "unmet dependencies"/"not installable" errors) and the installed
`dnsdist` came from Debian's own archive, not a third-party repository; all
four core services (`named`, `dnsdist`, `alderpointdns`,
`alderpointdns-analytics`) reach the active state with zero restarts;
`secrets.env`/`dnsdist-api.key`/`dnsdist-web.creds` are `root:alderpointdns
640` and readable by the `alderpointdns` account; the database is
`alderpointdns:alderpointdns` and actually writable by that account;
named's AppArmor local override is installed and named actually resolves
through both the BIND backend and the dnsdist frontend; dnsdist logs no
plain-text credential warnings and `dnsdist.conf` has no unresolved
placeholder; the web app's own credential files authenticate successfully
against dnsdist's stats API; `/setup` responds; DoQ/DoH3 are disabled by
default (`ALDERPOINTDNS_DNS_DOQ`/`ALDERPOINTDNS_DNS_DOH3=0` in the dnsdist
systemd override), nothing listens on UDP/853, `encryption.
dnsdist_capabilities()` reports `doq`/`doh3` as unsupported and `doh`/`dot`
as supported for this build, and the authenticated Encryption Settings page
renders the DoQ/DoH3 checkboxes disabled with an "unsupported" explanation
rather than silently enabled or broken; and stopping and restarting all
four core services (a reboot-equivalent check) brings every service back
active with working DNS resolution. It then purges and reinstalls to prove
two independent installations mint different console/web/API credentials
(every credential line differs, not just the file as a whole), and
reinstalls once more without purging to prove credentials are preserved
across an upgrade. Requires outbound network access (to pull the base image
and Debian's own package repositories) and takes a few minutes.

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
conversion of dnsdist's polled `latency-avg100` stat. It also covers
per-upstream resolver analytics: first-poll counter seeding without fabricated
deltas, subsequent dnsdist backend-counter deltas, latency storage, success and
failure timestamps, and dashboard history after a resolver row is deleted.

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
cache size above 75% of total RAM, inverted min/max TTL pairs, and invalid
recursive-client limits), generated BIND syntax for recursive clients and
both prefetch/serve-stale on and off, the idempotent
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
/opt/alderpointdns/tests/test_acceptance.sh
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

The Custom Filtering Rules suite (`tests/test_custom_rules.py`) is fully
sandboxed (temp database and directories, stubbed subprocess calls on the
deploy paths) and covers the rule parser (every supported form, AdGuard vs
Pi-hole plain-domain conformance, modifier and POSIX-regex rejection with
reasons), the legacy `custom_rules` migration, duplicate detection, the
evaluation API, RPZ rendering exactness and precedence conflicts, dnsdist
data-file/static-Lua rendering, the dnsdist.conf include migration, the
change-detecting dnsdist-layer deploy/rollback, and the `/custom-rules`
web routes.

The Import and Migration suite (`tests/test_importer.py`) covers CSV/hosts/
zone/Alderpoint DNS-CSV parsing, Pi-hole text/list parsing, Alderpoint DNS-native JSON
export/import round-tripping, upload filename sanitization and size limits,
column-mapping auto-detection, preview classification
(valid/invalid/duplicate/conflict) against a real Local DNS database, all
three conflict policies (skip/merge/replace, each verified to do exactly what
it claims and never silently overwrite an existing record), apply-then-
rollback round-tripping, AdGuard Home YAML translation (blocklist sources,
custom allow/block rules, rewrites, client aliases, upstream resolvers, and
the untranslatable/unsupported lists), and structured migration summaries for
adds, updates, conflicts, skipped entries, and unsupported source features.
Live verification imported real records through the actual privileged deploy
path and confirmed they resolved from both BIND and dnsdist before rolling
back.

The Backup and Restore suite (`tests/test_backup.py`) covers the real SQLite
online-backup mechanism (including under concurrent writes and correct
stripping of analytics/auth rows when those components are disabled),
manifest/checksum generation, dry-run restore preview never touching live
state, all restore code paths (component-scoped, full-database merge,
rollback-on-forced-failure, rollback-on-failed-health-check), retention
pruning, and the unprivileged-request/privileged-apply handoff pattern
including one-time password-file consumption. End-to-end verification
(create a real backup, mutate a real custom rule, restore, confirm
reversion, confirm file ownership, confirm DNS resolved throughout) caught
and fixed two real bugs in file-ownership handling during restore — see
`docs/progress.md`'s "Backup and restore" section for detail.

The installation, upgrade, diagnostics, and packaging suite
(`tests/test_install_upgrade_diagnostics.sh`) runs the installer in dry-run
mode against an isolated `ALDERPOINTDNS_INSTALL_ROOT`, runs the upgrader in dry-run
mode against a staged fake installation, verifies diagnostics redaction with a
self-test sample, creates a sanitized diagnostics tarball without journal
excerpts, checks that the bundle contains schema/summary metadata without
secret-like content, and builds/inspects a local test `.deb` with
`scripts/build-deb.sh`.

The release hygiene suite (`tests/test_release_hygiene.sh`) is a permanent
gate run as part of release verification. It scans tracked files and
filenames for stale references matching a prohibited-name pattern, supplied
via the `PROHIBITED_NAME_PATTERN` environment variable, and fails if any
tracked file's contents or filename matches. This guards against
accidentally reintroducing deprecated naming, internal identifiers, or other
prohibited strings into a release.

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
kdig +https @127.0.0.1 -p 443 +tls-ca=/etc/alderpointdns/certs/alderpointdns-lab.crt +tls-hostname=alderpointdns.local cloudflare.com A
kdig +tls @127.0.0.1 -p 853 +tls-ca=/etc/alderpointdns/certs/alderpointdns-lab.crt +tls-hostname=alderpointdns.local cloudflare.com A
kdig +quic @127.0.0.1 -p 853 cloudflare.com A
```
