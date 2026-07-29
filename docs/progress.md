# Progress

- [x] Baseline inspection captured
- [x] Required project/state/log directory skeleton created
- [x] Local Git repository initialized on `main`
- [x] Baseline and architecture commit (`aaefc75`)
- [x] BIND backend installed, validated, and tested on `127.0.0.1:5353`
- [x] dnsdist plain DNS
- [x] Encrypted DNS with official PowerDNS dnsdist package
- [x] Blocklist compiler
- [x] Safe RPZ deployment and rollback
- [x] Web interface
- [x] Authentication
- [x] Aggregate query statistics
- [x] Native analytics dashboard and query log
- [x] Backup and restore
- [x] Full reboot acceptance
- [x] Per-network policy preparation
- [x] v1 acceptance suite

## Verified BIND milestone

- BIND 9.20.26 installed from Debian security packages.
- UDP and TCP recursion pass on `127.0.0.1:5353`.
- Listener audit confirms BIND has no non-loopback socket and does not occupy 53.
- DNSSEC-valid response has the AD flag.
- DNSSEC-invalid test returns `SERVFAIL`.
- Empty RPZ validates with `named-checkzone`.
- Configuration validates with `named-checkconf`.
- RNDC is restricted to loopback and returns healthy status.
- JSON statistics channel responds only on `127.0.0.1:8053`.
- AppArmor remains enabled with narrow BindGuard path rules.
- Service is enabled and survives a stop/start cycle.
- With BIND stopped, host resolution and an HTTPS download succeeded via
  `/etc/resolv.conf`; BIND was restarted and the complete suite passed again.

## Verified dnsdist milestone

- dnsdist is installed from the official PowerDNS repository and enabled.
- Client-facing listeners bind to the VM interfaces:
  - UDP/TCP DNS on `0.0.0.0:53` and `[::]:53`
  - DoH/DoH3 on `0.0.0.0:443` and `[::]:443` path `/dns-query`
  - DoT/DoQ on `0.0.0.0:853` and `[::]:853`
- dnsdist forwards to BIND on `127.0.0.1:5354` with PROXYv2 client address
  preservation; `127.0.0.1:5353` remains available for direct loopback health
  and recovery checks.
- Access ACL defaults to RFC1918 private networks, loopback, and `fc00::/7`,
  with `BINDGUARD_DNS_ALLOW_ALL=1` available for pfSense-enforced allow-all
  deployments.
- Private-resolver dynamic rate limits are configured.
- Packet cache and local dnsdist stats API are configured.
- Temporary self-signed lab certificate validates against its private key.
- DoH and DoT pass with the lab CA explicitly trusted by the test client.
- DoQ and DoH3 listener configs validate with the official PowerDNS build; DoQ
  is exercised by the acceptance suite.
- Backend outage behavior is tested: stopping BIND prevents frontend
  resolution, restarting BIND restores dnsdist service.
- dnsdist restart test passes.
- Integrated BIND and dnsdist automated tests pass.

## Verified filtering milestone

- SQLite state database is initialized at `/var/lib/bindguard/bindguard.db`.
- Seeded public AdGuard DNS filter downloads through the host resolver.
- A 19-source public catalog can be loaded with `seed-public`; sources include
  category assignments and both `adguardteam.github.io` and GitHub raw URLs.
- Download and parse test currently accepts about 160k active domains from one
  realistic public source.
- Plain domains, hosts rules, basic Adblock rules, exceptions, duplicates, IDN
  normalization, invalid rules, and unsupported rules are covered by unit tests.
- Unit tests verify the public catalog size, enabled state, categories, and URL
  host coverage without requiring every large public list to download on every
  routine test run.
- Custom block and custom allow rules deploy successfully.
- Custom allow rules take precedence over downloaded and custom block rules.
- RPZ output validates with `named-checkzone`.
- Complete BIND configuration validates with `named-checkconf`.
- Deployment uses a lock, staging, backup, atomic replacement, `rndc reload`,
  post-deploy ordinary/blocked/allowed DNS tests, and rollback on runtime
  failure.
- Failed source update preserves the previous successful downloaded copy.
- Blocklist management now supports source add, edit, enable/disable, delete,
  update-all, and single-source update.
- Invalid generated RPZ is rejected before active configuration replacement.
- Forced post-deployment failure rolls back and records `rolled_back`.
- With both BIND and dnsdist stopped, `update-sources` and direct HTTPS download
  still work through the host maintenance resolver; services restart afterward.

## Verified web/auth milestone

- FastAPI/Jinja application runs as dedicated non-root `bindguard` user.
- Administration listener binds to `0.0.0.0:3000` and requires authentication.
- Initial setup page is reachable and no default administrator exists.
- Passwords are hashed with Argon2.
- Sessions are signed, `HttpOnly`, and `SameSite=Strict`.
- CSRF tokens protect mutating UI actions.
- Login failures are rate-limited by source IP.
- Web pages implemented: dashboard, blocklists, custom rules, DNS settings, and
  system.
- Privileged operations from the web service are limited to exact sudoers
  commands for source update and compiler deployment; no unrestricted shell is
  granted.
- `bindguard.service` is enabled and active.
- Web smoke test passes.

## Verified analytics milestone

- `bindguard-analytics.service` runs as the restricted `bindguard` account and
  listens only on `127.0.0.1:5301`.
- dnsdist 2.1 protobuf response logging is enabled with delayed delivery,
  bounded dnsdist-side queuing, and no SQLite writes in the DNS path.
- The collector polls the loopback-only dnsdist stats API for aggregate
  counters, latency, cache, drop, and health data. Polled `latency-avg100` is
  reported by dnsdist in microseconds and is converted to milliseconds before
  it is blended with per-query protobuf latency in aggregate buckets; this
  fixed a bug where dashboard/query-log average response time displayed
  roughly 1000x too high (observed ~4197 ms instead of the true ~4-9 ms on
  this VM's loopback backend).
- SQLite stores one-minute aggregate buckets plus recent detailed query events
  when detailed logging is enabled.
- Privacy modes support full, anonymized-client, and aggregate-only collection.
- Retention cleanup and database-size pruning are implemented.
- Blocked status is correlated with the active BindGuard RPZ policy set;
  ordinary NXDOMAIN responses are not counted as blocked.
- Controlled DNS traffic verified the dashboard/query log path: one allowed
  query, one RPZ-blocked query, and one ordinary NXDOMAIN produced 3 total,
  2 allowed, and 1 blocked stored events.
- Dashboard now includes range selection, metric cards, a local canvas
  time-series chart, top lists, protocol/rcode tables, and recent activity.
- Dashboard Top Upstream Resolvers now uses dnsdist's managed-upstream server
  counters. Resolver identities are stable because generated dnsdist backend
  names include the `upstream_resolvers.id` value. BindGuard stores resolver
  aggregate buckets with name/protocol/endpoint snapshots so deleting a
  resolver does not corrupt historical reporting. Per-client query rows are
  not labeled with an upstream resolver because this dnsdist+BIND architecture
  does not expose that relationship in the response protobuf stream.
- Query Log supports search, filters, pagination, auto-refresh, and creating
  custom allow/block rules from rows.
- Statistics Settings supports analytics toggles, privacy mode, retention,
  database limit, collection interval, clear, and export.

## Verified Local DNS milestone

- Local DNS uses `home.arpa` by default and rejects `.local`.
- SQLite stores A, AAAA, PTR, CNAME, TTL, comments, enabled state, automatic PTR
  links, client aliases, and Local DNS deployment results.
- Generated authoritative forward and reverse BIND zones are separate from RPZ
  filtering policy and are included through
  `/var/lib/bindguard/compiled/bind/local-zones.conf`. Advanced FQDN records
  outside the default internal domain create managed split-horizon forward
  zones, so records such as `adguard.mylan.network` are emitted and served
  locally instead of being forwarded upstream.
- Add/edit/toggle/delete operations deploy through the normal staged,
  validated, atomic no-download deployment path.
- Local DNS deployment clears dnsdist packet-cache entries for each managed
  local zone after BIND activation, preventing stale frontend NODATA responses
  after a local record is added.
- The web UI includes a dedicated Local DNS page with simple host entry,
  advanced records, alias management, CSV import/export, hosts preview,
  validation warnings, and deployment status.
- Routine Local DNS add/edit/toggle forms submit with targeted page-section
  updates and toast feedback; destructive record deletion still requires
  confirmation.
- Analytics dashboard and Query Log display configured client aliases, or local
  PTR fallback names with the raw IP when no alias exists.
- Unit and smoke tests cover record workflows, out-of-domain forward zones,
  duplicate/conflict warnings, serial increments, rollback, dnsdist cache
  invalidation, alias display, import/export, async Local DNS form behavior,
  and responsive layout rendering.

## Verified policy-preparation milestone

- SQLite schema includes policy categories for malware, ads and trackers, adult
  content, IoT telemetry, SafeSearch, and custom categories.
- Built-in policy profiles exist for trusted, standard, IoT, and restricted
  networks.
- `profile_categories` stores profile-to-category mappings, with restricted
  enabling all built-in filtering categories.
- `network_policies` can bind CIDRs to policy profiles once real client
  networks are supplied.
- Compiler status output includes policy profiles and network policy rows.
- Unit tests verify the seeded categories, profiles, restricted mapping, and a
  sample CIDR-to-profile binding.

## Verified backup/restore milestone

- Local backup script creates archives under `/var/lib/bindguard/backups`.
- Backup includes `/etc` BindGuard/BIND/dnsdist service configuration, SQLite
  state, downloads, compiled RPZ, and local source tree.
- Restore validates BIND, RPZ, dnsdist, and sudoers before extracting.
- Restore restarts named, dnsdist, and bindguard.
- Backup/restore acceptance test passes and confirms DNS and web services work
  afterward.

## Verified pre-reboot acceptance milestone

- `/opt/bindguard/tests/test_acceptance.sh` runs the BIND backend, dnsdist
  frontend, blocklist deployment, failure-path rollback, web smoke, and
  backup/restore tests.
- The pre-reboot acceptance suite passed on this VM.
- Negative-path stack traces during the suite are expected for invalid RPZ and
  forced rollback tests; both paths were verified as rejected/rolled back.

## Verified post-reboot recovery acceptance milestone

- After the VM reboot, the repository was recovered on `main` at commit
  `3c80bc8`; `git status` was clean and `git diff` was empty.
- Live services were verified active and enabled after boot:
  - `bindguard.service` on `0.0.0.0:3000`
  - `dnsdist.service` on wildcard DNS, encrypted DNS, loopback stats, and
    loopback control sockets
  - `named.service` on loopback backend recursion and RNDC
- Listener audit confirms only internal backend and management sockets remain
  loopback-only:
  - BIND on `127.0.0.1:5353`, `127.0.0.1:5354` PROXYv2, and `::1:5353`
  - dnsdist UDP/TCP DNS on `0.0.0.0:53` and `[::]:53`
  - dnsdist DoH/DoH3 on `0.0.0.0:443` and `[::]:443`
  - dnsdist DoT/DoQ on `0.0.0.0:853` and `[::]:853`
  - dnsdist web stats on `127.0.0.1:8083`
  - dnsdist control console on `127.0.0.1:5199`
  - BindGuard web on `0.0.0.0:3000`
- BIND `rndc status` confirmed the server is up and query logging remains off.
- Installed official PowerDNS dnsdist reports `dns-over-quic`.
- `/opt/bindguard/tests/test_dnsdist_frontend.sh` now asserts successful DoH and
  DoT DNS responses, certificate/key match, authenticated-only stats access,
  wildcard dnsdist DNS listeners, loopback-only management listeners, dnsdist
  config validation, DoQ capability, and configured private-resolver rate
  limits.
- `/opt/bindguard/tests/test_acceptance.sh` passed after the reboot with the
  strengthened dnsdist checks. The expected invalid-RPZ and forced-rollback
  stack traces still occurred only inside the negative-path tests, and the suite
  completed successfully.

## Verified latency accuracy audit

A prior session fixed the primary bug (`latency-avg100` is reported by dnsdist
in microseconds and was being stored unconverted as milliseconds, a ~1000x
inflation). This audit covered every remaining latency field end to end before
any cache-tuning work:

- Canonical unit: BindGuard stores latency as milliseconds (float) everywhere
  — `query_events.latency_ms`, `analytics_aggregate_buckets.latency_sum_ms` —
  and only ever converts once, at the single point microseconds enter the
  system (`stats["latency-avg100"] / 1000.0` in `collect_dnsdist_aggregate`).
  Templates render the stored millisecond value directly
  (`"%.1f ms"|format(...)`); there is no second API-layer unit conversion that
  could double-convert or omit a conversion.
- Per-query latency (`app/analytics.py:decode_dnsdist_message`) is computed
  entirely from timestamps dnsdist embeds in the protobuf payload itself
  (response message time vs. the original query time), never from when the
  collector happens to receive or process the frame. Analytics-queue backlog
  or delayed protobuf delivery therefore cannot inflate reported DNS latency;
  `test_telemetry_delivery_delay_not_counted_as_dns_latency` proves decoding
  the same frame later yields an identical latency.
- Negative latency from clock skew between dnsdist's internal timestamp reads
  is clamped to zero. Implausible values (a corrupted/misparsed timestamp
  producing a delta above `MAX_PLAUSIBLE_LATENCY_MS` = 30s, generous headroom
  above dnsdist's configured 5s TCP / 2s UDP upstream timeouts) are discarded
  rather than recorded, so a single bad frame cannot corrupt the aggregate
  average. The same plausibility bound applies to the polled
  `latency-avg100` value.
- `latency-avg100` is a live rolling average, not a monotonic counter, so a
  dnsdist restart naturally produces a fresh average with no delta/reset logic
  needed (unlike the monotonic counters in `COUNTER_MAP`, which are
  reset-safe via `test_counter_reset_never_negative`).
- Protocol classification (UDP/TCP/DoH/DoT/DoQ/DoH3, including the
  `DoH`+`http_version==3` → `DoH3` special case) is exercised for all six
  transports in `test_protocol_classification_across_transports`. dnsdist also
  exposes separate `latency-doh-avg100`/`latency-dot-avg100`/etc. stats;
  BindGuard does not blend these into the generic aggregate because real
  per-query events already carry accurate per-protocol latency in
  `query_events.protocol`, avoiding double-counting.
- Live controlled comparison on this VM: `dig @127.0.0.1 -p 5353` (direct BIND
  backend) showed 88ms for a cold query and 0ms for a cached repeat; dnsdist's
  own `jsonstat` reported `latency-avg100: 10330.87` (raw microseconds,
  i.e. ~10.3ms); the dashboard aggregate (`analytics.dashboard_data`) showed
  `avg_latency_ms: 52.08` over the trailing hour of mixed traffic; and
  individual query-log rows showed per-query values from 0.2ms to 111ms — all
  consistently millisecond-scale with no 1000x-style discrepancy between any
  of the four vantage points.
- `app/analytics.py` never reads dnsdist's `latency-sum` counter (documented
  in milliseconds, unlike the microsecond rolling averages), so the two
  differently-unit'd dnsdist fields are never mixed.
- New regression tests in `tests/test_analytics.py`: one-second response
  displays as 1000ms, no microsecond/millisecond multiplication error,
  negative latency clamp, implausible-latency discard, telemetry-delay
  independence, missing-stat poll safety, and per-protocol classification.

## Verified BIND cache management milestone

BIND already performs recursive caching; this milestone exposes and manages
that existing cache rather than adding a second one, per `app/dns_cache.py`.

- Settings (`dns_cache_settings` table, key/value like `local_dns_settings`):
  explicit max cache size, positive/negative min/max TTL, prefetch
  enable+trigger+eligibility, serve-stale enable+max-stale-ttl+client-timeout.
  Defaults for TTL/prefetch/serve-stale match BIND's own built-in defaults
  (not aggressively overridden); the one deliberately-chosen default is
  cache size, computed from `/proc/meminfo` as roughly an eighth of total RAM
  bounded to [64, 512]MB (490MB on this VM's 3.8GiB) instead of leaving
  BIND's much larger implicit ceiling in place. Validation rejects a
  configured size above 75% of total RAM and rejects inverted min/max TTL
  pairs.
- Generated cache tuning lives in its own include file
  (`/var/lib/bindguard/compiled/bind/cache-options.conf`), included from
  inside the `options {}` block of `/etc/bind/named.conf.options` by a
  one-time idempotent migration (`ensure_named_options_include`) that backs
  up the file before editing it, matching the "small package-independent
  include files" pattern already used for RPZ and Local DNS.
- `deploy_cache_options` follows the same staged/backup/atomic/health-check/
  rollback shape as RPZ and Local DNS deployment, and now runs automatically
  as part of every `bindguard_compiler.py deploy` (both download and
  no-download forms), so cache settings changes ride the same trusted
  deployment path Local DNS mutations already use.
- Cache flush (entire cache / one name / one subtree) is requested
  unprivileged (writes a `dns_cache_flushes` row) and applied by a new,
  narrowly-scoped, argument-free sudo entry
  (`bindguard_compiler.py cache-flush`) that reads the pending request from
  SQLite and runs the corresponding `rndc flush[name|tree]` — avoiding any
  sudoers argument-injection surface, consistent with the existing
  zero-argument-variability sudo design.
- Cache stats (hits, misses, hit percent, node count, tree+heap memory,
  LRU-eviction count, expired-TTL count) come from BIND's own
  `statistics-channels` JSON API (`views._default.resolver.cachestats`), not
  a second tracking mechanism. A new "Cache" page (`/dns-cache`,
  `web/templates/dns_cache.html`) exposes tuning, flush controls, last
  deployment status, and flush history; the dashboard's former placeholder
  "Top Upstream Resolvers"-adjacent panel was replaced with a real cache
  effectiveness panel.
- Live verification on this VM: deployed cache settings, confirmed
  `named-checkconf` accepted the merged config with `max-cache-size
  513802240` (490m) present, ran all three flush scopes successfully,
  deliberately corrupted a setting to prove the invalid-config path never
  touches the live `cache-options.conf` (fails before any file write) and
  that a failed post-deploy health check restores the prior good file and
  reconfigures BIND back to it, and ran a live cold/warm benchmark showing
  BIND's own `CacheMisses`/`CacheHits` counters increment correctly (92ms
  cold query, 0ms cached repeat) — see
  `tests/test_dns_cache_benchmark.sh`.
- `tests/test_dns_cache.py` (20 tests) covers default sizing, validation
  bounds (including the 75%-of-RAM ceiling and inverted min/max TTL
  rejection), rendered BIND syntax for both prefetch/serve-stale states, the
  idempotent named.conf.options migration, successful deploy, rollback on a
  failed post-deploy health check, invalid settings never touching the live
  file, all three flush scopes, newest-request-wins flush processing,
  flush-failure recording, and cache-stats hit-percent computation.
- Known limitation carried forward from `docs/adguard-parity.md`: dnsdist's
  separate packet cache (`packaging/dnsdist.conf`) is untouched by this
  milestone. It is safe today only because BindGuard v1 applies one global
  RPZ policy to every client — its cache key does not vary by client, so it
  must be disabled or re-keyed before any per-client/per-network policy
  (schema already exists, not yet enforced) is ever turned on at runtime, or
  one client's filtered/personalized answer could leak to another.

## Verified Upstream Resolvers milestone

The DNS Settings page now manages recursive upstream resolvers without manual
edits to BIND or dnsdist configuration.

- Current architecture confirmed: dnsdist is the client-facing listener and
  forwards to BIND; BIND performs recursion, DNSSEC validation, RPZ policy, and
  Local DNS authoritative answers. Managed upstreams preserve that split by
  adding a loopback dnsdist upstream pool (`127.0.0.1:5355`) that BIND uses as
  its forwarder target after validation.
- `app/upstream_dns.py` stores friendly name, protocol, address/DoH URL
  fields, port, DoH path, TLS hostname, bootstrap IPs, enabled state, order,
  and last health/latency. It imports the existing BIND `forwarders` block on
  first use so opening DNS Settings preserves the active configuration.
- Supported protocols are plain UDP/TCP DNS, DNS-over-TLS, and
  DNS-over-HTTPS. DoH hostnames require bootstrap IPs, DoH query strings and
  fragments are rejected, and deployment messages sanitize URL-shaped values.
- Deployment renders generated includes for both BIND and dnsdist, validates
  `dnsdist --check-config` and `named-checkconf`, restarts dnsdist, reloads
  BIND, performs a real post-deploy lookup through BIND, records resolver
  health/latency, and restores the prior generated files on failure.
- The DNS Settings UI supports add, inline edit, enable/disable, reordering,
  and delete through async forms with success/error feedback, without a manual
  browser refresh.
- Live verification on this VM migrated the four existing BIND forwarders
  (`1.1.1.2`, `1.0.0.2`, `4.2.2.1`, `4.2.2.2`) into managed resolver rows,
  deployed the dnsdist loopback upstream pool, and confirmed resolution through
  both BIND (`127.0.0.1:5353`) and dnsdist (`127.0.0.1:53`).
- Tests: `tests/test_upstream_dns.py` covers standard-DNS changes, DoH
  validation/rendering, failed connectivity rollback, multiple enabled
  resolvers, and persistence; `tests/test_web_smoke.sh` covers the UI and
  route presence.

## Verified navigation and global status milestone

- Primary navigation is grouped into Dashboard, DNS, Security, Operations, and
  System, preserving all existing primary URLs. Dashboard remains the first
  direct link; section parents and child pages expose active state.
- The grouped navigation uses native disclosure controls plus shared CSS/JS for
  desktop dropdowns, mobile stacked groups, Escape/outside-click closing, and
  non-hover keyboard/touch access.
- The upper-right service status is now a global shell component backed by
  `global_service_status()` and `/status/summary`; it renders accessible text
  and refreshed state consistently on every authenticated page.
- `tests/test_web_smoke.sh` inventories every primary nav href, checks active
  parent/child rendering, confirms protected route visibility, and exercises
  healthy/degraded/inactive/unknown global-status states.

## Verified Encryption Settings milestone

`app/encryption.py` adds a full Encryption Settings workflow on top of
dnsdist's existing DoH/DoH3/DoT/DoQ listeners. Plain UDP/TCP 53 is never
controlled from this page — it has no enable/disable control at all, so it
cannot be turned off from the UI.

- `packaging/dnsdist.conf` (and, via a one-time idempotent migration,
  `/etc/dnsdist/dnsdist.conf`) now reads certificate paths, the DoH path, and
  every protocol's port from environment variables instead of hardcoding
  them, defaulting to the original lab values so an unmigrated install
  behaves identically. The migration (`ensure_dnsdist_conf_parameterized`)
  extracts and preserves the currently-installed console key and webserver
  password/API key by regex rather than regenerating them, backs up the
  prior file first, and is marked idempotent by a comment so it only runs
  once.
- Settings (`encryption_settings` table) cover per-protocol enable + port,
  DoH path, server hostname, bootstrap IP, DNSCrypt port/provider name, and
  certificate mode (`self_signed`, `local_ca`, `uploaded`, `existing_path`).
- Deployment (`deploy_encryption`) regenerates
  `/etc/systemd/system/dnsdist.service.d/bindguard.conf` (the same drop-in
  that already controlled protocol enable flags), `daemon-reload`s,
  validates with `dnsdist --check-config` using the *pending* environment
  values (not the live ones), restarts dnsdist, waits for it to become
  active, then runs a real functional query per newly-enabled protocol
  before declaring success; any failure restores the previous drop-in,
  reconfigures, and restarts back to the last-good state. A deploy where
  nothing actually changed (env text identical, dnsdist.conf already
  migrated, no certificate regenerated) is a fast no-op recorded as
  `unchanged` rather than an unnecessary dnsdist restart; certificate
  regeneration at the same configured path is explicitly tracked so it still
  forces a redeploy even though the env var *value* didn't change.
- Real per-protocol tests: plain (`dig`), DoH and DoH3 and DoQ (`dnspython`'s
  `dns.query.https`/`dns.query.quic`, the latter requiring `python3-aioquic`
  which this milestone installed), and DoT (`kdig +tls`, note kdig's timeout
  flags are `+timeout=`/`+retry=`, not dig's `+time=`/`+tries=` — an early
  bug caught by live testing before it reached tests/). All four were
  verified against the live VM with real answers, not mocked.
- DNSCrypt is a known, disclosed limitation, not a fake completion.
  `generateDNSCryptProviderKeys`/`generateDNSCryptCertificate` are real
  dnsdist console Lua functions (confirmed via `help()` against the live
  console) that print a correct-looking provider fingerprint when invoked
  from this VM, in both live-console (`dnsdist -c`) and standalone one-shot
  (`dnsdist -l ... -e`) modes, but reliably fail to persist the requested
  key/cert files to disk in either mode — the live-console path is
  additionally blocked by `dnsdist.service`'s systemd sandboxing
  (`PrivateTmp=yes`, `ProtectSystem=full`, no `ReadWritePaths` covering
  `/etc/bindguard/certs`). Rather than fabricate DNSCrypt support,
  `deploy_encryption` catches generation failure, disables DNSCrypt for that
  deployment only (the stored setting is untouched so the admin's intent is
  preserved and retried next deploy), and records a clear message — proven
  by `test_deploy_encryption_dnscrypt_failure_does_not_block_other_protocols`
  not to affect DoH/DoH3/DoT/DoQ/plain.
- Certificates: self-signed generation and a local CA (issuing leaf certs
  signed by a persistent BindGuard CA) both use `openssl` directly.
  Cert/key match validation compares RSA moduli; SAN, validity window, days
  remaining, expiry/expiring-soon flags, and SHA-256 fingerprint are parsed
  from `openssl x509`. Upload and cert-generation actions run through the
  same privileged `bindguard_compiler.py encryption-deploy` sudo entry as
  settings changes (the web process cannot write to root:_dnsdist-owned
  `/etc/bindguard/certs` directly); uploads are staged to
  `/var/lib/bindguard/staging` (bindguard-writable) by the unprivileged web
  process and validated/installed by the privileged step. Private key
  contents are never rendered back to the browser; only the public
  certificate is downloadable.
- New enumerated sudo entry `bindguard_compiler.py encryption-deploy`
  (argument-free, like `cache-flush`) — kept as its own command rather than
  folded into the shared `deploy`/`deploy --no-download` path used by
  Local DNS and cache changes, since a dnsdist restart is a heavier,
  categorically different operation that should only happen when an admin
  actually changes Encryption Settings, not as a side effect of an
  unrelated Local DNS or blocklist change.
- Client connection info (ready-to-copy DoH/DoH3/DoT/DoQ/DNSCrypt strings)
  and Apple `.mobileconfig` generation for DoH/DoT (`com.apple.dnsSettings.managed`
  payload, verified against Apple's public configuration profile reference)
  are both implemented and tested.
- `tests/test_encryption.py` (29 tests) covers settings validation, real
  self-signed/local-CA certificate generation and matching, mismatched
  cert/key rejection, upload staging/consumption, the dnsdist.conf migration
  (including secret preservation and idempotency), env-override rendering,
  full deploy success/rollback/unchanged/cert-forces-redeploy paths, DNSCrypt
  graceful degradation, connection info, and Apple profile content.

## Verified Import and Migration milestone

`app/importer.py` adds a dedicated Import and Migration page (`/import`),
built to write only through the same unprivileged SQLite operations ordinary
Local DNS/blocklist edits already use, then trigger the existing
`sudo bindguard_compiler.py deploy --no-download` path — no new sudo entries
were needed for this milestone.

- Spreadsheet/text sources: CSV (arbitrary columns, with auto-detected +
  admin-editable column mapping to the required canonical field set —
  `hostname`, `fqdn`, `domain`, `ipv4`, `ipv6`, `record_type`, `target`,
  `create_ptr`, `ttl`, `comment`, `enabled`, `client_alias`,
  `client_id_or_cidr`), XLSX (via newly-installed `python3-openpyxl`), hosts
  files, a practical subset of BIND zone-file syntax (`name [ttl] [IN] TYPE
  data` lines for A/AAAA/CNAME/PTR, `$ORIGIN` support; SOA/NS/MX and
  multi-line records are explicitly out of scope, documented as such rather
  than silently mishandled), and BindGuard's own exported CSV format.
- Workflow matches the requested shape exactly: upload parses into an
  `import_jobs` row without touching live state → normalized preview
  classifies every row as valid / invalid (with a reason) / duplicate
  (within the file) / conflict (against existing Local DNS records, reusing
  `local_dns.record_warnings` rather than a second conflict-detection
  mechanism) → the admin picks skip / merge / replace, verified live against
  the real database: skip leaves the existing record untouched, merge adds a
  second record alongside it (round-robin), replace deletes the prior
  record(s) for that name+type first — proven by
  `test_apply_job_never_overwrites_existing_record_silently` and the
  merge/replace tests, not just asserted.
- Apply stages nothing new to disk (the "staging" is the in-memory/DB-row
  preview computed before any `local_dns_records` write) but does take an
  automatic pre-apply backup (`scripts/backup.sh`) before writing, tracks
  every inserted row's ID on the job record, and on
  `deploy --no-download` failure a caller can invoke `rollback_job()`, which
  deletes exactly those tracked rows and leaves an audit trail
  (`status='rolled_back'`) — verified live end-to-end on this VM: imported
  two real A records via CSV, ran the privileged deploy, confirmed both
  resolved from both BIND (`:5353`) and dnsdist (`:53`), rolled back, redeployed,
  and confirmed the records stopped resolving.
- AdGuard Home migration accepts either an uploaded `AdGuardHome.yaml` or a
  direct read-only API connection (`/control/filtering/status`,
  `/control/rewrite/list`, `/control/clients`, `/control/dns_info`, Basic
  Auth, credentials used for one request and never stored) — verified
  against AdGuard Home's actual documented top-level YAML schema (`filters`,
  `whitelist_filters`, `user_rules`, `filtering.rewrites`,
  `clients.persistent`) rather than assumed. Both paths funnel into the same
  translator: `filters` → blocklist `sources` rows; `user_rules` split into
  `@@||domain^` → custom allow, `||domain^`/plain-domain → custom block,
  anything else (regex, cosmetic `##`, modifiers) → `unsupported_rules`,
  shown but not imported; `filtering.rewrites` → Local DNS A/AAAA/CNAME
  records; `clients.persistent` → client aliases (display-only, matching
  BindGuard's current alias semantics; per-client filtering/SafeSearch/
  upstream/blocked-services settings have no runtime BindGuard equivalent
  yet and are listed under `untranslatable` rather than silently dropped).
  `whitelist_filters` (AdGuard allowlist-subscription URLs) are explicitly
  **not** auto-imported as anything, since BindGuard has no allowlist-
  subscription object (confirmed in `docs/adguard-parity.md`) and treating
  their URLs as ordinary block sources would be actively wrong — they are
  listed for manual review instead, per "display anything that cannot be
  translated."
- Never imports passwords, private keys, sessions, or AdGuard's own admin
  credentials — the translator only reads filtering/rewrite/client/dns_info
  data, nothing from AdGuard's user/auth configuration.
- `tests/test_importer.py` (17 tests) covers every parser (CSV, hosts, zone,
  BindGuard CSV), column-mapping auto-detection and pass-through, preview
  classification (valid/invalid/duplicate/conflict), all three conflict
  policies against a real SQLite-backed `local_dns` fixture, apply+rollback
  round-tripping, and AdGuard YAML translation including the
  comment/cosmetic-rule exclusion and the untranslatable-settings list.

## Verified Backup and Restore milestone

`app/backup.py` adds a dedicated Backup and Restore page (`/backup`)
producing versioned, checksummed archives and a preview-first, staged,
automatically-rolled-back restore path, following the same shape as
`app/dns_cache.py`/`app/encryption.py`. Built by a background agent working
in an isolated git worktree; merged and then verified/fixed against the
live VM in this session (see the two real bugs below — both were caught
live, not assumed fixed from a clean test run).

- Manifest (`manifest.json` at the archive root): `backup_format_version`,
  `bindguard_app_version` (derived from the current git commit,
  `unreleased+git.<short-sha>`, since there is no formal release versioning
  yet), `created_at`, `source_node_id`, `included_components`, and a
  `sha256_checksums` map for every archived file, verified on extraction
  before any restore step touches live state.
- The SQLite database is always captured through **SQLite's own online
  backup API**, not a raw copy of the live `.db`/`.db-wal`/`.db-shm` files,
  so a concurrently-writing web app or analytics collector can never produce
  a torn/inconsistent archive — verified by
  `test_sqlite_backup_copy_reflects_concurrent_writes_consistently`.
- Component design (documented in the module's own docstring, since the
  task asked for the reasoning behind this rather than a partial-SQLite-file
  hack): the database is always captured as one consistent online-backup
  copy; component selection controls two things instead — which *rows* get
  stripped from that copy before archiving (`analytics_history`,
  `user_auth_data`, off by default), and, at restore time, which *tables*
  from the backup get merged into live SQLite, gated per-table so a narrow
  restore (e.g. only `custom_rules`) never touches unrelated tables like
  `dns_cache_settings` or `encryption_settings`.
- Private key/credential material (TLS private keys, the DNSCrypt
  provider/resolver private keys, the web session-signing secret, dnsdist
  API/webserver credentials) is excluded from every backup by default and
  requires both checking "include private keys" and a separate explicit
  confirmation checkbox in the UI — not just a tooltip.
- Password encryption uses `openssl enc -aes-256-cbc -pbkdf2 -iter 200000
  -salt`, with the password piped via stdin (`-pass stdin`) rather than a
  command-line argument, so it never appears in `ps`/process listings — no
  hand-rolled crypto.
- The unprivileged web process cannot write to `/etc/bindguard`, `/etc/bind`,
  `/etc/dnsdist`, or arbitrary restore-target paths, so create/restore/
  preview/schedule-deploy all follow the same "unprivileged process writes
  an intent row (and, for passwords, a 0600 file consumed and deleted after
  one read) to SQLite, then a new argument-free
  `bindguard_compiler.py backup-{create,restore,preview,schedule-deploy}`
  sudo entry reads and executes it" pattern already established by
  `dns_cache.request_flush`/`process_pending_flush`.
- `preview_restore` extracts to a temp dir, verifies checksums, and reports
  a structured diff (per-table live-vs-backup row counts for tables mapped
  to a specific component, plus a file-content diff summary) without ever
  touching live state — verified live and by
  `test_preview_restore_never_touches_live_state`.
- `restore_backup` always takes a full safety backup of current state
  *before* changing anything (not just before a risky step), stages then
  atomically replaces each selected filesystem component, merges selected
  SQLite tables, validates (`named-checkconf`, `dnsdist --check-config`,
  `visudo -cf`), restarts only the services actually touched, runs a real
  post-restore `dig` functional test, and on any failure restores every
  replaced file/table from the safety backup and re-validates DNS before
  reporting `rolled_back` (or `rollback_failed` if even that doesn't
  recover, which never happened in live testing).
- **Two real bugs were found and fixed via live testing on this VM, not
  just unit tests** (both were caught safely by the rollback path itself —
  DNS never went down during either failure, which is itself a live proof
  the safety design works):
  1. `_replace_path`'s file installation used `shutil.copy2`, which copies
     content/mode/timestamps but — per Python's own documentation — *not*
     owner/group. After a restore, `/etc/dnsdist/dnsdist.conf` silently
     changed from `root:_dnsdist` (required for the `_dnsdist`-user dnsdist
     process to read its own config) to whatever the restore process's
     default group was, and `systemctl restart dnsdist` failed with
     `Unable to read configuration file`. Fixed by explicitly `os.chown`-ing
     every restored file/directory to match the staged copy's ownership
     (which extraction — run as root — does preserve correctly from the
     archive).
  2. The first fix's `shutil.copytree(..., copy_function=_copy_with_ownership)`
     then failed with `'str' object has no attribute 'stat'`, because
     `shutil.copytree` invokes its `copy_function` callback with plain
     string paths, not `Path` objects, contrary to the initial assumption.
     Fixed by using `os.stat`/`os.chown` (which accept both) instead of the
     `Path.stat()` method.
  Both fixes were verified with a real end-to-end cycle: create a real
  backup, mutate a real custom rule, restore, confirm the mutation reverted,
  confirm `/etc/dnsdist/dnsdist.conf` and `/etc/bind/named.conf` kept
  correct ownership, confirm DNS resolved throughout.
- Scheduled backups use a systemd timer (`packaging/bindguard-backup.timer`
  + `.service`), with the interval applied via a generated drop-in rather
  than editing the packaged timer file directly. Retention pruning keeps
  only the newest N archives (deleting both the file and its
  `backup_history` row) after each scheduled run.
- `tests/test_backup.py` (33 tests) covers settings validation, the real
  SQLite online-backup mechanism (including that it reflects concurrent
  writes consistently and correctly strips analytics/auth rows when those
  components are off), manifest/checksum generation, preview never touching
  live state, all three restore paths (component-scoped apply, full-database
  merge of unmapped tables, rollback on both a forced failure and a failed
  post-restore health check), retention pruning, and the
  request/process-pending-request handoff pattern including that a stored
  password file is consumed and deleted exactly once.
