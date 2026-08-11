# Changelog

All notable changes to Alderpoint DNS are documented in this file.

## v1.0.1 (2026-08-11)

A targeted bugfix release.

- Fixed a live-incident-derived bug where managed upstream DNS resolvers
  could silently diverge between the database and the live dnsdist/BIND
  config: `deploy()` ran the cache-options deployment stage before the
  upstream-resolvers deployment stage, so a stale/dead live upstream
  config could fail the cache stage's own health check and abort the
  whole deploy before the upstream stage -- which would have fixed it --
  ever ran. An ordinary upstream resolver edit through the UI could then
  commit to the database with no corresponding `upstream_deployments`
  record and no live effect, while the operator saw a misleading
  cache-related error. Upstream resolvers now deploy first.
- Restoring a backup now reconciles managed upstream resolvers against
  the live config whenever a restore could have changed either the
  database rows or the generated runtime/base config files that must
  match them, closing a restore-time divergence gap surfaced by the same
  incident.
- Replicated configuration now explicitly, defensively excludes managed
  upstream resolvers (they were already never replicated in practice) --
  upstream resolvers are appliance-local by design.
- Fixed a second live-incident-derived bug found during v1.0.1 RC
  acceptance: normal UI use -- toggling several upstream resolvers before
  each one's request had finished -- spawned multiple concurrent full
  `deploy()` pipelines. An OS-level lock already existed and prevented any
  actual runtime-file corruption, but had no visibility from the web
  layer, so overlapping requests each queued their own full 20-90s
  pipeline run: "database is locked", "post-deploy upstream resolution
  failed", repeated dnsdist restarts, and a UI that looked hung. The same
  lock previously only covered the full pipeline and `protection-enable-reuse`;
  the narrower single-stage cache/upstream/encryption CLI deploys -- which
  write the same live BIND/dnsdist files -- acquired no lock at all
  standing alone and could have raced a concurrent full deploy. Fixed by:
  (1) extending the shared deploy lock to those narrower deploys, and (2)
  adding an in-process coordinator in the web app that serializes and
  coalesces overlapping deploy requests into at most one extra trailing
  run instead of one queued run per click, with a clear "already in
  progress" response instead of a raw SQLite error for a caller that times
  out waiting.
- Upstream resolver add/edit/toggle/move/delete no longer invoke the full
  blocklist/RPZ deploy pipeline at all -- they now call
  `upstream_dns.deploy_upstreams()`'s own scoped deployment path directly,
  which already owned its own validation, restart/reload, health check,
  and last-good rollback/history end to end. Nothing else in the pipeline
  depends on upstream resolver state. On the reference lab appliance this
  took a single upstream toggle from ~8.8s (full deploy --no-download) to
  ~1.3s (scoped upstream-deploy); on a real appliance with a full-size
  blocklist, full deploys have been observed taking 20-90s.
- Fixed a packaging defect surfaced by live RC acceptance immediately after
  the fix above: the newly-added scoped `upstream-deploy` sudo invocation
  had no matching entry in `packaging/sudoers-alderpointdns`, so the
  `alderpointdns` service account could not run it non-interactively --
  clicking Disable (or any other upstream add/edit/toggle/move/delete
  action) on a packaged install failed with "sudo: a terminal is required
  to read the password; ... sudo: a password is required". Every other
  scoped/single-stage deploy command the web app calls (cache-deploy,
  cache-flush, encryption-deploy, etc.) was already correctly granted; only
  `upstream-deploy` was missing, because it was newly wired into the web
  layer rather than newly added to the compiler. Added the single missing
  NOPASSWD entry -- explicit, exact-match, no wildcards or broadened scope --
  and added `tests/test_sudoers_policy.py`, which (1) statically checks
  every literal `sudo .../alderpointdns_compiler.py <subcommand>` call in
  `app/webapp.py` against `packaging/sudoers-alderpointdns` so a future
  missing grant fails a test instead of live acceptance, and (2), on a real
  packaged install, uses `sudo -n -l` (an authorization check only, no
  privileged execution) as the real `alderpointdns` account to prove the
  *installed* policy matches too -- now part of the acceptance suite.
- Fixed a third live-incident-derived bug found during v1.0.1 RC acceptance:
  disabling the last enabled upstream resolver correctly showed "at least
  one upstream resolver must be enabled" (`upstream_dns.deploy_upstreams()`
  refuses to ever promote a zero-upstream config to the live runtime), but
  `set_enabled(resolver_id, False)` had already *committed* the
  all-disabled desired state to the database before `deploy_upstreams()`
  ever ran and rejected it. The runtime config stayed correct, but the
  database no longer matched it, and no future deploy of any kind (scoped
  or full) could ever succeed again without an admin re-enabling a resolver
  by hand first. `set_enabled()`, `delete_resolver()`, and
  `update_resolver()` now check, in the same transaction and before the
  mutating statement runs, whether the change they're about to commit would
  leave zero enabled resolvers, and refuse to commit it if so -- the
  invalid desired state can no longer be written at all, not merely
  rejected downstream. `deploy_upstreams()`'s own check remains as defense
  in depth for callers that mutate the table directly (backup restore,
  replication, the CLI). A related `systemctl restart dnsdist` failure
  reported from the same live session, seen only with a DoH-only enabled
  upstream set, could not be reproduced against this appliance's own
  network conditions after live investigation (an unreachable/firewalled
  DoH backend was confirmed, separately, to fail safely: dnsdist starts
  normally and simply marks that backend down); `deploy_upstreams()` now
  captures a `journalctl -u dnsdist` snapshot into the deployment's stored
  `validation_output` at the moment any deploy failure triggers a rollback,
  so a future occurrence is diagnosable from deployment history alone,
  without needing appliance shell access before the journal rotates. Added
  `tests/test_upstream_last_enabled_guard.py` (unit- and web-route-level:
  the guard rejects before any DB commit and before any `sudo` invocation
  is ever reached) and `tests/test_upstream_enabled_set_combinations.sh`
  (live-service acceptance coverage proving dnsdist actually starts and
  resolves for one/multiple plain, one/multiple DoH, and mixed plain+DoH
  enabled sets, and that an attempted zero-enabled deploy leaves the live
  runtime and DB state unchanged).
- Fixed the `systemctl restart dnsdist` failure from the same live session
  for real: dns1's own upstream_deployments history and dnsdist journal
  showed dnsdist repeatedly restarting *successfully* during a burst of
  ordinary sequential upstream UI changes, closely enough together to trip
  systemd's own start-rate crash-loop protection (`start-limit-hit`) --
  not a DoH-specific config defect. That protection is intentional and is
  left untouched. Instead, `app/webapp.py`'s upstream deploy coordinator
  now paces its own intentional restarts at least 3 seconds apart
  (comfortably under systemd's default 5-per-10s limit with margin); a
  rapid burst of clicks converges to the fewest actual restarts needed to
  reach the final desired state instead of one restart per click, and an
  isolated click is never delayed. Verified live: a burst of 10 rapid
  sequential calls against the real coordinator/dnsdist produced 3 actual
  restarts, no `start-limit-hit`, and a healthy, resolving service
  afterward (`tests/test_upstream_restart_rate_limiting.sh`, also covered
  at the coordinator level in `tests/test_deploy_coordinator.py`).
- Fixed a related correctness gap surfaced investigating the same session:
  `deploy_upstreams()`'s post-deploy functional check queried BIND, which
  could still answer from its own resolver cache -- a leftover answer from
  a prior, genuinely good deploy -- without ever actually asking the
  newly-staged upstream chain anything, so a deploy could be recorded
  'deployed' even though every enabled upstream was actually unreachable.
  The check now issues `rndc flushname` immediately before every
  resolution attempt, forcing a genuine cache miss every time, with a
  short bounded retry to tolerate dnsdist's own asynchronous backend
  health check not having completed its first round yet. Separately, a
  successful deploy used to blanket-mark every enabled resolver row
  `last_status='healthy'` off that one pool-level check, even when
  `firstAvailable` routing meant only some of them actually carried
  traffic; `deploy_upstreams()` now reads dnsdist's own per-backend
  up/down state (`showServers()`) and records each row's *own* truthful
  status, so a down DoH backend sitting alongside working plain resolvers
  shows as down in the database/UI instead of falsely healthy, while the
  overall deploy still succeeds (a single down backend has never required
  dnsdist itself to fail, and still doesn't). Added
  `tests/test_upstream_dns.py::test_post_deploy_check_forces_fresh_resolution_not_stale_cache`
  (proves an all-unreachable upstream set cannot inherit a prior deploy's
  cached success).
- Corrected the restart-rate-limit fix once dns1's *actual* dnsdist.service
  policy was confirmed: `StartLimitIntervalUSec=1min`, `StartLimitBurst=5`
  -- not systemd's generic 10s/5 default the first pass assumed. A 3s
  pacing interval was not safe against a 60s window (six restarts 3s apart
  still all land inside it), and simply widening the interval to 15-16s
  would have made every ordinary sequential upstream change wait that long
  for no functional reason, while leaving the deeper problem -- one
  dnsdist restart per desired-state change -- in place. Investigated
  whether dnsdist supports changing its backend set without a restart: it
  does, officially, over its own console (`newServer()`/`rmServer()`, the
  same Lua functions the static startup config uses -- dnsdist calls
  itself a "DNS Loadbalancer" and ships this mechanism for exactly this).
  `upstream_dns.deploy_upstreams()` now applies an ordinary upstream
  add/edit/toggle/move/delete to the already-running dnsdist over that
  console -- clearing and re-adding the full desired backend set as a
  single console round trip, typically sub-millisecond, with no frontend
  socket interruption -- instead of restarting the process at all. The
  static config files are still rendered, validated, and staged exactly as
  before (so a future real restart, e.g. a reboot or package upgrade,
  loads the identical state), and a real restart remains the fallback
  whenever live reconciliation isn't possible or doesn't verifiably
  succeed (console unreachable, the very first upstream deploy ever on a
  fresh install, or a post-check mismatch) -- itself still protected by
  the deploy coordinator's restart-rate pacing, now correctly scaled to
  dns1's real policy (16s spacing, keeping 5 restarts spread over more
  than 64s) and, after fixing a real bug caught while retesting, applied
  *only* when a run's own output confirms it actually restarted dnsdist --
  an earlier version of this fix paced every deploy unconditionally and
  turned 8 ordinary sequential toggles into a 123-second wait even though
  none of them ever restarted anything. Verified live: 8 genuine
  sequential upstream changes now complete in ~13 seconds total with 0
  dnsdist restarts, no `start-limit-hit`, truthful DB/runtime/deployment
  history throughout, and DNS available the whole time. Added
  `tests/test_deploy_coordinator.py::test_restart_fallback_pacing_alone_stays_under_dns1s_actual_start_limit`
  (replicates systemd's own start-limit algorithm against dns1's real
  60s/5 policy) and rewrote `tests/test_upstream_restart_rate_limiting.sh`
  to drive more than 5 genuine sequential desired-state changes (not
  idempotent re-deploys) through the real production coordinator and real
  dnsdist, verifying restart count, DB/runtime parity, deployment history
  truthfulness, and DNS availability together.

## v1.0.0 (2026-08-09)

The first stable release. See `docs/release-notes.md` for the equivalent
user-facing summary. Everything below this line, back through
`v0.4.0-beta.1`, was beta-cycle work; interfaces, on-disk formats, and
configuration from this release forward follow normal stable-release
compatibility expectations instead of beta-era churn.

- Fixed Dashboard **Top Clients** navigation: clicking it used to open the
  generic, unfiltered Query Log, which misrepresented the destination as
  client-specific. It now opens a new lightweight **Clients** view (`/clients`,
  also linked from the DNS nav section) showing every client seen in the
  selected time range, ranked by query volume, with alias display names where
  configured; each client row links to the Query Log pre-filtered to that
  client (`/query-log?client=...`), which the Query Log already supported.
- Added **System > Administration > Software Updates**: check for and
  install newer Alderpoint DNS releases from GitHub, or upload a `.deb`
  manually. Stable/prerelease channel filtering, SHA-256 + `dpkg-deb`
  package validation, `apt-get install -s` simulation, a mandatory
  pre-upgrade backup (install aborts if it fails -- no "install anyway"
  override), and a post-upgrade health check (services, `PRAGMA
  quick_check`, DNS resolution, a new local `/healthz` endpoint, and
  installed-version verification) all happen before/around the actual
  `apt` install. Installing runs as an independent systemd unit
  (`alderpointdns-software-update.service`, started via `systemctl start
  --no-block` through a fixed sudoers entry) rather than as a child of
  the web request, since the install restarts `alderpointdns.service`
  itself partway through; the browser polls durable job state
  (`software_update_jobs`/`software_update_events`) and survives that
  restart. (`--no-block` is required, not optional: `systemctl start` on
  a `Type=oneshot` unit is synchronous by default, which would have left
  the triggering HTTP request itself blocked -- and killed along with
  the rest of that request's process tree -- exactly when the install it
  kicked off restarts `alderpointdns.service`; found via a real
  disposable-VM install, not caught by any mocked unit test.) Automatic
  **checking** is on by default
  (`alderpointdns-software-update-check.timer`, every 6h); automatic
  **installation** is off by default and has no execution path yet. A
  private-repo GitHub credential, if configured, lives at
  `/etc/alderpointdns/software-updates.env` (root-owned, mode 0600) and
  is never readable by the web process, rendered in templates, or
  written to diagnostics/logs. See `docs/software-updates.md`.
- Established a canonical version model for update safety
  (`docs/versioning.md`): the development `VERSION` for this cycle is
  now `0.5.0-dev.1` (Debian form `0.5.0~dev1-1`), strictly newer than
  the published `0.4.0-beta.6` by SemVer core-version comparison alone
  and correctly ordered *older* than a future final `0.5.0` release via
  Debian's `~` pre-release convention. `scripts/build-deb.sh`'s and
  `app/backup.py`'s `-beta.N` &harr; `~betaN` substitution was
  generalized to any `-<tag>.<N>` pre-release tag (`beta`, `dev`, `rc`,
  ...), not just `beta`.
- Backup & Restore quality-of-life: backup creation/restore timestamps
  shown to administrators (Backup & Restore listing, restore preview,
  Last Backup/Last Restore cards) now display in the server's configured
  local timezone with a clear abbreviation/offset (e.g. "Aug 8, 2026 at
  6:47 PM MDT") via a new `local_time` Jinja filter
  (`webapp.format_local_datetime`), instead of raw UTC. Canonical
  timestamps (backup manifest `created_at`, `backup_history.created_at`,
  every other stored timestamp) remain UTC/ISO-8601 and are never parsed
  from the display string, so this cannot affect restore correctness.
  Archive filenames also now use the server's local date/time (still
  filesystem-safe -- numeric `+HHMM`/`-HHMM` offset, no colons) instead
  of a UTC `...Z` stamp, purely for human identification; restore/backup
  lookups always match by history id or the literal filename, never by
  parsing the stamp.
- Backup & Restore quality-of-life: a successful interactive **Create
  Backup** from the web UI now also automatically triggers a browser
  download of the newly created archive (via the same authenticated
  streamed `/backup/{id}/download` route the existing manual Download
  button already uses, through a hidden iframe so the page itself never
  buffers the file), while still retaining and listing the backup on the
  server exactly as before. The existing manual Download action remains
  available afterward for downloading the same backup again. A failed
  create never triggers a download.
- Fixed fresh-install default blocklist seeding never actually triggering
  on a real `apt install` of a genuinely fresh system, despite passing
  every unit test. Root cause: `analytics.py`'s `init-db` subcommand calls
  `alderpointdns_compiler.py`'s `init_db()` unconditionally, which on a
  genuinely fresh database applies the full schema and bumps `PRAGMA
  user_version` to `SCHEMA_VERSION` as a side effect; `postinst` (and
  `scripts/install.sh`) ran this call *before*
  `alderpointdns_compiler.py fresh-install-init`, so by the time
  fresh-install-init's own freshness check ran, the database already
  looked established and it silently skipped seeding the default
  blocklists and the initial deploy entirely (`fresh_install=0` on every
  install). Discovered installing a real combined development `.deb` on a
  disposable Debian 13 VM -- `sources` had zero rows after a clean
  install. Fixed by running `analytics.py init-db` after
  `fresh-install-init` in both `postinst` and `scripts/install.sh`
  (harmless reordering: it is idempotent `CREATE TABLE IF NOT EXISTS`
  either way).
- Fixed dnsdist failing to bind port 53 (`Fatal error: binding socket to
  0.0.0.0:53: Address already in use`) on an otherwise completely
  unmodified, default fresh install of Debian 12/13 or Ubuntu. Root cause:
  systemd-resolved's stub DNS listener is enabled by default and binds
  specific loopback aliases (127.0.0.53:53, sometimes also 127.0.0.54:53)
  without `SO_REUSEPORT`; Linux refuses a subsequent *wildcard* bind
  (0.0.0.0:53, what dnsdist needs) on a port already claimed by any
  non-`SO_REUSEPORT` socket, even one bound to a different, more specific
  address. `packaging/debian/postinst` now disables only
  systemd-resolved's stub *listener* (`DNSStubListener=no`, via a drop-in)
  when systemd-resolved is active, and repoints `/etc/resolv.conf` (only
  when it's still the default symlink -- a real administrator-owned file
  is left untouched) at this host's own Alderpoint DNS listener, since
  that's the intended end state for a host running Alderpoint DNS as its
  resolver anyway. Discovered during this pass's clean-VM install
  validation (see the completion report) -- this affected every fresh
  install on a stock Debian/Ubuntu host, not anything specific to this
  branch's other changes.
- Fixed `alderpointdns`/`alderpointdns-analytics` not actually restarting
  on upgrade. `packaging/debian/postinst` used `systemctl enable --now`
  for these two services, which -- unlike named/dnsdist, which already
  get an explicit `systemctl restart` -- only ensures an *already-active*
  unit stays enabled/running; it does not restart it. Every upgrade of
  this package was silently leaving the *previous* version's web
  app/analytics-collector process running (with the previous version's
  code, and, for the systemd sandboxing fix above, the previous version's
  `ReadWritePaths=`) until something else happened to restart it. Now
  `enable` (idempotent) is followed by an unconditional `restart`, the
  same pattern named/dnsdist already used. Discovered while verifying the
  `ReadWritePaths=` fix above actually took effect after a `dpkg -i`
  upgrade in this pass's real testing -- it silently didn't, for exactly
  this reason.
- Fixed native backup restore failing (`[Errno 30] Read-only file system:
  '/etc/systemd/system/dnsdist.service.d'`) for the `app_config`,
  `dnsdist_source_config`, and `bind_source_config` restore components --
  the same `ProtectSystem=full` root cause as the network Apply fix
  below, this time affecting `app/backup.py`'s restore path, which
  directly replaces live files under `/etc/bind`, `/etc/dnsdist`,
  `/etc/systemd/system/*.service[.d]`, and `/etc/sudoers.d`. Discovered
  restoring a real ~296 MiB backup (2.8M Analytics History rows) through
  the actual streamed restore path on a disposable Debian 13 VM.
  `packaging/alderpointdns.service`'s `ReadWritePaths=` now covers all of
  these.
- Fixed Network Configuration's Apply always failing (`[Errno 30]
  Read-only file system`) for every backend that writes its own
  persistent config file (netplan, systemd-networkd, ifupdown -- not
  NetworkManager, which goes through `nmcli`/D-Bus instead). Root cause:
  `alderpointdns.service` runs with `ProtectSystem=full`, which
  read-only-bind-mounts `/etc` for the unit's private mount namespace;
  since the privileged `alderpointdns_compiler.py network-apply` helper
  runs as a `sudo`-escalated *child* of that same process (without its
  own new mount namespace), it inherited the same read-only `/etc`, even
  running as root. `packaging/alderpointdns.service` now explicitly lists
  `/etc/netplan`, `/etc/systemd/network`, and `/etc/network` in
  `ReadWritePaths=`. Discovered via this pass's real Netplan-backend
  apply/rollback test on a disposable Debian 13 VM (see the completion
  report) -- every previous test of this feature had mocked the actual
  backend file writes, which is exactly the class of bug real-network
  testing was added to catch.
- Fixed `alderpointdns.service` failing to start after the
  `ReadWritePaths=` fix above (`Failed to set up mount namespacing:
  /etc/netplan: No such file or directory`, `status=226/NAMESPACE`) on any
  host where one of the three networking-backend directories isn't
  present -- `/etc/netplan` in particular is Ubuntu-centric and does not
  exist on a stock Debian install with no `netplan.io` package. Unlike
  `ReadOnlyPaths=`, a `ReadWritePaths=` entry for a path that does not
  exist is fatal to the whole unit's mount-namespace setup, not silently
  skipped -- and `app/network_config.py`'s `detect_backend()` only ever
  has one of Netplan/systemd-networkd/ifupdown active on a given host, so
  the other two are expected to be absent. `/etc/netplan`,
  `/etc/systemd/network`, and `/etc/network` are now each prefixed with
  `-` (`systemd.exec(5)`: a leading `-` makes a `ReadWritePaths=` entry a
  no-op instead of a startup failure when the path is absent); the other
  entries in the list are guaranteed present (this package's own postinst,
  or a hard package dependency) and are deliberately left unprefixed.
  Discovered via a real `0.4.0~beta6-1` -> `1.0.0-1` in-place upgrade on a
  disposable Debian appliance with no `/etc/netplan`.
- Fixed `named` failing to start (`/etc/bind/named.conf.options:N: parsing
  failed: file not found` for `cache-options.conf`) whenever
  `/var/lib/alderpointdns` is missing at postinst time but
  `/etc/bind/named.conf.options` already has the `include` line a prior
  successful install's DNS Cache Settings deploy added (that line is
  permanent once added; the template itself is only installed on first
  install and never rewritten). Reproduced by `apt purge alderpointdns`
  followed by reinstall without also resetting bind9's own
  `/etc/bind/named.conf.options`. `packaging/debian/postinst` now
  pre-creates an empty `cache-options.conf` bootstrap placeholder the same
  way it already did for `local-zones.conf`, so `named` can always start
  regardless of ordering; the real generated content replaces it in the
  same postinst run once `alderpointdns_compiler.py deploy` runs.
- Fixed native Alderpoint DNS backup restore rejecting large backups with
  "uploaded file exceeds 10 MiB limit". Root cause: the only 10 MiB cap in
  the codebase is `MAX_UPLOAD_BYTES` in `app/importer.py`, which exists for
  the Spreadsheet/Text Import page (CSV/XLSX/hosts/zone/Pi-hole/AdGuard
  YAML/"Alderpoint DNS native JSON" record exports -- all genuinely small,
  hand-editable data). Native `.tar.gz`/`.tar.gz.enc` backup archives were
  not clearly and separately surfaced as their own workflow, so a large,
  Analytics-History-inclusive backup could end up uploaded through that
  page and hit its limit; and the existing `/backup/import` route itself
  read the whole upload into memory (`await upload.read()`) with no
  independent size policy, free-space check, or archive-bomb protection of
  its own. Both are fixed:
  - System > Administration now has a dedicated **Backup & Restore**
    section (moved out of the Operations nav group) with explicit
    **Create Backup** and **Restore Alderpoint Backup** actions, entirely
    separate from Spreadsheet/Text Import.
  - `/backup/import` now streams the upload to a restrictive-permission
    (0600, IMPORTS_DIR-confined) staging file in bounded ~4 MiB chunks
    (`backup.begin_streamed_upload`/`finalize_streamed_upload`/
    `abort_streamed_upload`), so memory use is independent of archive
    size. A native backup upload is governed by its own, separately
    configurable `max_upload_mib`/`max_extracted_mib` policy
    (`backup.max_upload_bytes()`/`max_extracted_bytes_setting()`, default
    4 GiB upload / 16 GiB extracted, admin-adjustable up to a 50 GiB / 200
    GiB hard ceiling -- never unlimited), fully independent of
    `importer.MAX_UPLOAD_BYTES`.
  - Free disk space is checked before accepting an upload and again before
    extraction (using the archive's real scanned size), and periodically
    during a large streamed upload.
  - `backup.extract_backup()` now validates the archive is recognizably an
    Alderpoint DNS native backup (manifest.json present with required
    fields) before extracting anything, rejects absolute paths, `../`
    traversal, symlinks, hardlinks, and device/fifo members, enforces a
    total extracted-size ceiling (compressed-archive-bomb protection) via
    a pre-extraction member scan, and uses Python's `tarfile` `"data"`
    extraction filter as defense in depth instead of shelling out to
    `tar -xzf` directly. `restore_backup()` now also refuses a
    `backup_format_version` mismatch outright rather than only warning
    about it in the preview.
  - The restore preview now shows archive size and an explicit
    Included/Not Included status per component, matching the shape
    administrators need to confirm before restoring (configuration,
    blocklists/custom rules, DNS cache settings, analytics history,
    certificates, admin/auth data).

- Added a **Network Configuration** section under System > Administration
  for the Alderpoint server's own network interface (DHCP vs static IPv4/
  IPv6, gateway) -- separate from DNS upstream/resolver settings. New
  `app/network_config.py`:
  - Detects the actual networking backend in use (systemd-networkd,
    NetworkManager, Netplan, or classic ifupdown/`/etc/network/
    interfaces`) rather than assuming one; an unsupported or ambiguous
    setup (e.g. more than one backend simultaneously active) is shown
    read-only and every write path refuses outright.
  - Validates a proposed change (interface exists, IPv4/IPv6 syntax,
    prefix length, gateway syntax and subnet membership, rejects loopback/
    multicast/unspecified addresses and collisions with another local
    interface) before anything is written.
  - On Apply: snapshots the current persistent config (and, for
    NetworkManager, the connection profile via `nmcli`) to a root-only,
    group-readable rollback state file; stages the new persistent config
    in backend-isolated functions; arms an *independent* rollback watchdog
    via `systemd-run --on-active=120s ... network-rollback-check` (owned
    by PID 1, not this web process, request, or the administrator's
    browser); then actively reconfigures the live interface through the
    backend's own mechanism (`networkctl reload`+`reconfigure`, `netplan
    generate`+`apply`, `nmcli con mod`+`up`, or a controlled `ifdown`/
    `ifup` -- never a bare `ip link set ... up/down`, which does not
    itself apply a backend's persistent config).
  - If the administrator doesn't confirm within the countdown, the
    watchdog restores both the persistent config files and the live
    interface state -- no reboot required -- and logs the automatic
    rollback. Confirming cancels the watchdog and deletes the rollback
    state.
  - All privileged operations go through the same narrow, argument-free
    sudoers/`alderpointdns_compiler.py` pattern backup/replication already
    use (`network-apply`, `network-confirm`, `network-rollback-check`):
    the web process never gains general root, and no interface name, path,
    or shell fragment from a request ever reaches argv or a shell.
  - `audit_ip_references()`/`cert_covers_address()` support reporting
    (never silently rewriting) whether generated BIND/dnsdist config or
    the current TLS certificate still reference the old address after a
    confirmed change.
  - See `docs/network-configuration.md` for what has and has not yet been
    verified against a real interface (unit-tested with every backend
    command mocked; live reconfigure/rollback on real hardware/VM is
    outstanding -- see that doc's Limitations section).
- Fresh installations now seed three ordinary recommended blocklist sources
  (AdGuard DNS filter, StevenBlack Unified Hosts, and HaGeZi Multi Normal),
  then attempt the normal initial download, validation, compile, staged RPZ
  deployment, and health checks automatically. The seeded lists are normal
  editable/removable blocklist entries. Protection becomes active only after
  that initial deployment succeeds; download/deploy failures are reported
  without marking filtering active, and the administrator can retry through
  the existing update/deploy paths. Upgrades and reinstalls no longer alter
  existing blocklists, enabled states, or Protection state, and do not run
  the fresh-install seeding path.
  - AdGuard DNS filter:
    `https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt`;
    upstream `AdGuardTeam/AdGuardSDNSFilter`; EasyList/EasyPrivacy-derived
    DNS-compatible advertising and tracking coverage.
  - StevenBlack Unified Hosts:
    `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts`;
    upstream `StevenBlack/hosts`; unified adware and malware hosts coverage.
  - HaGeZi Multi Normal:
    `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt`;
    upstream `hagezi/dns-blocklists`; balanced ads, tracking, telemetry,
    device, mobile tracker, phishing, and malware coverage.

- Fixed the replication enrollment handoff (`replication.py::_handle_enroll`)
  holding no reservation across its privileged sudo subprocess: a token was
  only ever checked for validity (still 'pending'), never atomically
  reserved, before a single shared staging file handed its hash to the
  privileged `alderpointdns_compiler.py replication-consume-enrollment`
  step -- two concurrent `/replication/enroll` requests (even for two
  different tokens) could race on that shared file, and a failed privileged
  step never released anything back. Enrollment now goes through an
  explicit reserve / run-privileged-step / consume-or-release lifecycle:
  `request_enrollment_consumption()` atomically flips a token from
  unreserved-pending to reserved-pending in one short, already-committed
  transaction (a `reserved_at` column, additive so no destructive migration
  is needed); the reservation's hash is handed to the privileged subprocess
  over stdin (never argv, never a shared file) so concurrent requests for
  different tokens can never cross paths; a failing privileged step now
  explicitly releases the reservation (`release_enrollment_reservation()`)
  so the token remains retryable instead of stuck; and an orphaned
  reservation (the requester crashed before it could release or consume)
  recovers automatically after a short TTL. The reservation writes use the
  same shared bounded-retry helper as the web app fix, and a busy-exhausted
  write now returns a controlled HTTP 503 instead of leaking an internal
  error string built from a raw exception.

- Fixed a SQLite concurrency bug where a routine authenticated web request
  could fail with `sqlite3.OperationalError: database is locked` / HTTP 500.
  Root cause: `webapp.db()` ran `alderpointdns_compiler.init_db()` -- a
  `PRAGMA journal_mode=WAL`, several `CREATE TABLE`/`ALTER TABLE`-if-missing
  checks, and `INSERT OR IGNORE` category/policy-profile seeds -- on every
  single database connection request, including the session/CSRF lookups
  and the `last_seen_at` bookkeeping write that run on essentially every
  authenticated page load. If a concurrent long-running writer (a compiler
  deploy, backup/restore, or blocklist update) held SQLite's single writer
  lock past the 5s busy timeout, an ordinary request raised uncaught into a
  bare HTTP 500.
  - `webapp.db()` is now a pure connection factory: it opens a connection,
    sets `row_factory` and `busy_timeout`, and does nothing else. Schema
    creation and migration run exactly once per process, from a FastAPI
    startup hook, via `alderpointdns_compiler.init_db()`.
  - `init_db()` is now gated by a `PRAGMA user_version` schema-version check
    and an interprocess `flock`-based migration lock, so it is a cheap,
    idempotent no-op once already migrated and safe to call concurrently
    from multiple processes (CLI subcommands, package install/upgrade, and
    the webapp's own startup hook all still call it, unchanged).
  - The webapp's own auth tables (`admins`, `sessions`, `login_attempts`,
    `admin_audit_log`), previously recreated inline on every `db()` call,
    now migrate under the same schema-version gate and lock.
  - Added `app/db_retry.py`, a shared bounded-retry-with-jitter helper for
    `SQLITE_BUSY`/`SQLITE_LOCKED`. Session `last_seen_at` updates use it and
    are skipped (with a logged warning) rather than failing the request if
    the database is still busy after a few short retries -- authentication
    and CSRF enforcement are unaffected. Any other write that exhausts its
    retry budget now returns a controlled HTTP 503 instead of an unhandled
    traceback.
  - The compiler's `collect_rules()` no longer writes each source's
    download/parse result inside the per-source download loop; all writes
    for a compile run are now deferred to a single short transaction after
    every source has finished downloading and parsing, so a blocklist
    update no longer holds the database-wide writer lock across a sequence
    of network downloads (and, transitively, across `deploy()`'s later RPZ/
    BIND validation and service-reload subprocess calls).
  - No data reset, destructive migration, or table recreation; WAL mode and
    all existing data are preserved. Existing installations upgrading from
    beta.5 (which never set `PRAGMA user_version`) are migrated forward
    exactly once on the next `init_db()` call.
- Backup & Restore lifecycle hardening: a restore's `restore_history` row now
  records worker identity (PID, process-start-ticks, boot ID) and a periodic
  heartbeat/phase/progress instead of relying on elapsed time, so a restore
  whose worker actually died (killed process, OOM, host reboot) is reliably
  told apart from one that is simply still running a large, slow restore --
  the former is reaped and reported as interrupted, the latter is never
  killed just for taking a long time. Fixed a real large-analytics-restore
  slowdown found via profiling (chunked commits instead of one giant
  transaction, coordinated pausing of the analytics collector during the
  merge) and added a real multi-million-row restore validation.
- Native database restore is now staged and atomically promoted: the
  expensive merge work happens against a private working copy of the
  database (via SQLite's own online backup API), never directly against the
  live database, and is only ever swapped into place with a brief
  exclusive-lock-guarded atomic file replace once fully validated. A restore
  interrupted before that swap leaves the previously working live database
  completely untouched; one interrupted after it is reported honestly as
  requiring administrator verification rather than silently claimed as
  rolled back. Verified with real interruption testing (process kills at
  each stage) in addition to unit tests.
- Software Updates: an update job whose privileged runner
  (`alderpointdns-software-update.service`) died mid-install no longer gets
  stuck "in progress" forever -- the same worker-identity-based staleness
  detection used for Backup & Restore now applies to
  `software_update_jobs`, so a dead runner's job is reaped and future
  install attempts are not permanently blocked behind it.
- Software Updates: automatic **checking** now actually honors the
  configurable check interval (`check_interval_hours`, System >
  Administration > Software Updates) via a runtime systemd timer drop-in,
  the same mechanism already used for scheduled blocklist updates and
  backups; turning automatic checking off now actually stops the scheduled
  timer rather than only making a triggered check a no-op. Automatic
  **installation** remains off by default with no execution path.
- Filtering/deploy performance: added fast paths for the overwhelmingly
  common blocklist source-line shapes (`||domain^`, `@@||domain^`, plain
  hostnames), cheap IP-literal prechecks, and an ASCII-normalization
  shortcut that skips IDNA encoding for ordinary domains, plus a
  source-parse cache (keyed by content hash and parser version) so an
  unchanged blocklist source is never re-parsed. Turning **Protection**
  back on after it was off can now reuse a previously compiled policy
  (validated against a canonical hash of every input that could have
  changed it) instead of always rebuilding from scratch, refreshing the
  RPZ zone's SOA serial correctly either way; falls back to a full rebuild
  automatically whenever reuse cannot be proven safe.
- Navigation cleanup: **Backup & Restore** moved from System to
  **Operations** (Import, Backup & Restore, Replication), keeping its
  existing `/backup` route. **Administration** no longer carries launcher
  cards that only pointed at Network Configuration, Software Updates, or
  Backup & Restore -- each already has its own direct System/Operations
  submenu entry one level away -- while keeping its actual purpose
  (administrator password change, session management) unchanged.

## v0.4.0-beta.5 (2026-07-31)

- Fixed a false-positive in DoQ/DoH3 runtime status reporting: the DNS
  Settings protocol table could report DoQ/DoH3 as "listening" merely
  because a TCP DoH/DoT listener shared the same numeric port (443/853) as
  the UDP-only DoQ/DoH3 listener. Listener detection now checks transport
  and address together, "enabled" is read from Alderpoint's own encryption
  settings rather than grepping the generated dnsdist configuration, and
  the Protocol Status table now shows readable Build Support/Runtime
  Status/Verification columns instead of internal strings. Added an
  explicit, root-only, opt-in `alderpointdns install-enhanced-dnsdist` CLI
  command (and a read-only `alderpointdns dnsdist-capabilities` command)
  to install the official PowerDNS dnsdist 2.1 repository build with
  DoQ/DoH3 support; this only installs the capability -- DoQ/DoH3 remain
  disabled until turned on in Encryption Settings -- and is never done
  automatically by the package or the web process. DoH now advertises an
  active DoH3 endpoint via an Alt-Svc response header when DoH3 is enabled.
- Fixed a second, related false-negative discovered during live-system
  validation of the above: the shared `run()` helper used by
  `listener_addresses()` kept only the last 4000 characters of `ss -H
  -ltnup` output, silently dropping earlier lines -- including plain UDP 53
  -- once a host's socket table was long enough, which could report Plain
  DNS/DoQ/DoH3 as not listening when they genuinely were. Listener
  detection now reads the full, untruncated `ss` output.
- Added an idempotent, marker-delimited `dnsdist.conf` migration
  (`ensure_doh_altsvc_migration()`) so an already-migrated v0.4.0-beta.4
  install picks up the Alt-Svc managed block on upgrade -- the one-time
  base parameterization migration never re-templates the file again, so
  the Alt-Svc change above would otherwise never reach an existing
  install. Runs automatically from both the `.deb` postinst and
  `scripts/upgrade.sh` (new `alderpointdns_compiler.py dnsdist-conf-migrate`
  subcommand), validates with `dnsdist --check-config` and backs up/rolls
  back before ever touching the live file, only touches the exact known
  pre-migration DoH listener block (leaving any hand-edited block alone
  and reporting that it was skipped), and is a byte-stable no-op on every
  run after the first. Verified end-to-end on a disposable Debian 13
  clone: a real upgrade from the published `v0.4.0-beta.4` `.deb` to this
  build applied the migration automatically, and the live DoH response's
  `alt-svc` header was confirmed present/absent as DoH3 was enabled/disabled
  after installing DoQ/DoH3 capability via `install-enhanced-dnsdist`.
- Fixed the documented/embedded dnsdist rollback instructions
  (`docs/dnsdist.md`, `app/dnsdist_upgrade.py`'s failure-path message):
  `apt-get install --reinstall dnsdist` cannot reinstall a version that's
  no longer available once the PowerDNS repository is removed ("cannot be
  downloaded"), so it never actually rolled back to Debian's stock
  package. Both now use `apt-get install -y --allow-downgrades dnsdist`,
  confirmed to actually downgrade and restart cleanly.
- Fixed `scripts/build-deb.sh` (the script that actually builds the
  distributed `.deb`) writing its own hardcoded `Depends:` line that never
  received the `gnupg` dependency added to `packaging/debian/control` --
  found while verifying the final beta.5 package, since `gnupg` is
  required by `install-enhanced-dnsdist`'s signing-key verification.
- Fixed `scripts/backup.sh` hard-failing on any `.deb`-installed system:
  it unconditionally tarred `etc/systemd/system/alderpointdns.service` and
  `etc/systemd/system/alderpointdns-analytics.service`, which only exist
  at that path on a from-source `install.sh`/`upgrade.sh` install -- the
  `.deb` ships the base unit files under the Debian-standard
  `/usr/lib/systemd/system` instead, which dpkg already owns and restores
  on its own. `backup.sh` now includes each unit file only if present at
  the from-source path, found while running the full acceptance suite
  against the packaged beta.5 build.

## v0.4.0-beta.4

`v0.4.0-beta.3` was version-bumped, tag-created, and immediately withdrawn
before any GitHub Release was published (a first prerelease publish had to
be deleted and its tag name became permanently unusable due to GitHub's
immutable-releases policy); no `beta.3` artifact was ever distributed. All
of its changes are carried forward unchanged under `beta.4` below.

- Fixed filtering deployments incorrectly failing when a downloaded allow
  rule returned a valid DNS response without an IPv4 A record. Cache-only
  changes now report and roll back component state accurately.
- Fixed a production incident in which the analytics writer thread could
  die silently while its parent process kept reporting healthy: closed a
  SQLite connection-descriptor leak present across most of the web app's
  database call sites, added retry-with-backoff and an independent
  heartbeat to the analytics writer, and corrected System Status severity
  reporting (Warning/Error/Info) for these conditions.
- Fixed a blocklist zero-rule ambiguity: a source that legitimately
  compiles to zero rules is now distinguished from a fetch/parse failure,
  IPv6-only hosts-format sinkhole entries now compile correctly, AdGuard
  `$dnsrewrite` handling was corrected, and System Status now reports
  real, distinct blocklist health states instead of collapsing them
  together.
- Fixed the local test-deb builder silently omitting the new admin CLI
  entry point and the `alderpointdns-notify.timer` unit from built
  packages.
- Scrubbed a real home-LAN domain and IP addresses that had been
  reintroduced into test fixtures.
- Documented the recent Administration, Notifications, migration, and
  reliability work.

## v0.4.0-beta.2 (unreleased)

- Configured the BIND recursive backend on loopback with DNSSEC validation,
  RPZ-based filtering, RNDC control, statistics, and AppArmor confinement.
- Configured the dnsdist client-facing frontend with plain DNS, DoH, DoT,
  DoQ, access control lists, rate limits, a packet cache, and statistics.
- Added a blocklist downloader/parser/compiler with safe RPZ deployment and
  automatic rollback on failure.
- Added an authenticated FastAPI web interface with Argon2 password hashing,
  signed session cookies, CSRF protection, and rate-limited login.
- Added a native Backup and Restore page with preview-first restore,
  checksummed archives, scheduled backups, and rollback on failure.
- Added one-way primary-to-replica replication with token enrollment, mTLS,
  generation hashes, drift checks, failed-sync rollback, and revoked-peer
  enforcement.
- Added DNS Settings upstream resolver management for plain DNS, DoT, and
  DoH, backed by BIND plus a managed dnsdist loopback upstream pool with
  validation, health checks, latency tracking, and rollback.
- Added per-upstream resolver analytics from dnsdist's managed-backend
  counters, including dashboard ranking, success/failure/timeout counts,
  latency, and historical resolver snapshots.
- Added configurable client DNS listener IPv4/IPv6 addresses for Encryption
  Settings, with deployment validation and wildcard-listener warnings.
- Added Import and Migration with CSV/XLSX/hosts/zone-file parsing, Pi-hole
  text/list import, AdGuard Home YAML and live-API import (blocklists,
  custom rules, DNS rewrites, upstream resolvers), a native JSON export/
  import format, staged upload retention, and migration summaries covering
  adds, updates, conflicts, skipped items, and unsupported source features.
- Added reviewed install and safe-upgrade scripts with dry-run/test-root
  support, a sanitized diagnostics bundle command, version and dependency
  manifests, and Debian package scaffolding plus a local test `.deb`
  builder.
- Added BIND cache management: cache size, TTL, prefetch, and serve-stale
  tuning; a recursive client limit control; cache flush (all/name/subtree);
  and cache hit/miss statistics sourced from BIND's own statistics channel.
- Added a first-class custom filtering rule subsystem supporting exact and
  subdomain block/allow rules, hosts-style exact rewrites, POSIX-ERE regex
  rules (validated against catastrophic-backtracking patterns and compiled
  into dnsdist without ever interpolating rule text into generated Lua),
  and AdGuard `$` modifiers, with deterministic precedence and a compact
  Filters page supporting search/filter, bulk edit, and a "Test a Domain"
  panel.
- Added a configurable global Filter Update Interval on the Blocklists page,
  backed by a systemd timer and a fixed, server-validated allowlist of
  intervals.
- Added beta-readiness, versioning, release-note, supported-system,
  hardware, migration, recovery, troubleshooting, and feedback/bug-report/
  feature-request documentation, plus a hardening-review document and a
  corresponding automated test.
- Grouped primary navigation into Dashboard, DNS, Security, Operations, and
  System sections with active parent/page state and mobile/keyboard
  support, plus a collapsible desktop sidebar with persisted collapsed
  state.
- Made the top-right service status badge a global authenticated-shell
  component backed by a lightweight status-summary refresh endpoint.
- Redesigned Local DNS's record table to be compact and scannable, with a
  collapsed-by-default row editor and relationship badges in place of
  repetitive comment text.
- Reworked DNS Settings' upstream resolver actions into a clear hierarchy of
  primary inline actions and a compact overflow menu for less common or
  destructive actions.
- Replaced Blocklists' free-text category field with a managed category
  system: create/rename/merge/delete-with-reassignment, plus a compact
  source list with category/status/health badges, sorting, and filtering.
- Verified full reboot survival: services, listeners, DNS functionality,
  feature persistence, and the acceptance/smoke/hardening-doc test suites
  all pass after a full reboot, including a production-flow backup/restore
  round trip.
- Fixed a diagnostics bundle defect that leaked the live BIND RNDC/TSIG
  control-channel secret in plaintext; added a redaction pattern and a
  bundle-level regression test.
- Fixed a live-database backup race where `scripts/backup.sh` tarred the
  live WAL-mode SQLite database file directly, which could race a
  checkpoint and abort the backup. It now takes a transactionally
  consistent snapshot via SQLite's own online backup API first and archives
  that instead.
- Fixed unclosed SQLite connections in the backup test suite that produced
  `ResourceWarning` noise during test runs.
- Fixed System Status's Recent Logs, which previously ran `journalctl`
  directly as the unprivileged web user and could render raw
  permission-denied text into the page. It now goes through a narrowly
  scoped, sudoers-allowlisted helper that returns sanitized, structured log
  entries, with service/severity/line-count filters and a friendly empty
  state.
- Fixed Dashboard/System Status health cards splitting whole words
  mid-character on narrow layouts.
- Fixed the Encryption page's Certificate panel stretching to match an
  adjacent panel's height; the same fix was applied to the equivalent Cache
  Tuning and Backup/Restore panel pairs.
- Hardened custom regex rule validation to reject catastrophic-backtracking
  patterns that are valid POSIX ERE but could otherwise hang the
  admin-facing "Test a domain" evaluation panel indefinitely.
- Hardened migration report redaction to match credential-bearing field
  names by word-boundary/camelCase token instead of exact string, so
  compound field names are caught too.
- Fixed a first-clean-install failure where all four core services
  (`alderpointdns`, `alderpointdns-analytics`, `named`, `dnsdist`) crash-
  looped after a "successful" package install: `secrets.env`/dnsdist API
  and web credentials are now group-readable (0640) instead of 0600; the
  database is chowned to `alderpointdns` after generation; named's
  AppArmor local override is installed and reloaded; `packaging/dnsdist.conf`
  is fixed and made capability-aware for Debian 13's own (non-PowerDNS-repo)
  dnsdist build, and the package now requires `dnsdist (>= 2.0.0)` so
  installing without the documented PowerDNS repository fails cleanly at
  dependency resolution instead of silently pulling an incompatible
  version. dnsdist's web password and API key are now hashed with
  `hashPassword()` before being written into `dnsdist.conf`, eliminating
  the plaintext-credential warning without weakening authentication.
  `postinst` now validates configuration and verifies all four services
  actually reach the active state before reporting success, and
  `StartLimitBurst`/`StartLimitIntervalSec` caps prevent runaway restart
  loops if that ever fails again. Added a container-based clean-install
  regression test and a static built-package inspection test.
- Finalized Alderpoint DNS's license: source-available under the PolyForm
  Noncommercial License 1.0.0 (`LICENSE`), not open source; commercial use
  requires a separate license (`COMMERCIAL_LICENSING.md`). Added
  `COPYRIGHT`, `CONTRIBUTOR_LICENSE_AGREEMENT.md` (structured on the Apache
  Individual CLA, de-branded, contributors retain ownership and grant
  Alderpoint DNS broad reuse/relicensing rights), `TRADEMARKS.md`, and
  `THIRD_PARTY_NOTICES.md` (audit of BIND/dnsdist/Python/OS dependencies
  and their licenses; nothing third-party is vendored into the repo).
  Updated `README.md`/`CONTRIBUTING.md` accordingly and clarified that
  opening a pull request is not, by itself, CLA acceptance. The `.deb` now
  installs `LICENSE`/`copyright`/`COMMERCIAL_LICENSING.md`/
  `THIRD_PARTY_NOTICES.md` under `/usr/share/doc/alderpointdns/`. Added a
  permanent licensing-hygiene test.
- Fixed a second clean-install failure: requiring `dnsdist (>= 2.0.0)` made
  the package impossible to install on a genuinely fresh Debian 13 system
  at all, since a `.deb` cannot configure a third-party repository to
  satisfy its own dependency before apt resolves it, and that version is
  only available from the PowerDNS project's own repository. `Depends` now
  reads `dnsdist (>= 1.9.0)`, the lowest bound Debian 13's own archive
  `dnsdist` (1.9.x) satisfies, so `apt-get install -y ./alderpointdns_*.deb`
  resolves and installs cleanly from stock repositories alone. Debian's own
  `dnsdist` build supports plain DNS, DoH, DoT, DNSCrypt, and everything
  the BIND backend integration needs (packet cache, ACLs, analytics
  logging, authenticated web/API access), but not DNS-over-QUIC or
  DNS-over-HTTP/3; those two now ship disabled by default and
  `app/encryption.py` detects the installed `dnsdist`'s actual capabilities
  (from `dnsdist --version`'s feature list) to keep unsupported protocols
  out of a deployment -- degrading just that protocol with a clear message
  instead of failing or rolling back the whole deployment -- and to show
  them as unsupported, not enabled or broken, on the Encryption Settings
  page. The PowerDNS repository remains available as an optional upgrade
  path for DoQ/DoH3, detected automatically with no reinstall required.
  Rewrote the clean-install container regression test to install strictly
  from stock Debian 13 repositories, with no `repo.powerdns.com` reference
  permitted anywhere in the run.
- Fixed the Encryption Settings page (and the dashboard's System Health
  cert card) throwing a 500 on a genuinely fresh install: the TLS
  certificate directory (`/etc/alderpointdns/certs`) was created
  `root:_dnsdist` mode `0750`, so the unprivileged `alderpointdns` web
  process -- in neither group -- got `PermissionError` on a bare `stat()`
  of its own certificate, even though the certificate file itself is
  world-readable (`0644`). Changed the directory to mode `0751`: still no
  read/write for "other" (can't list the directory or open the `0640`
  private key), but traversable, which is all `os.stat()`/`Path.exists()`
  on the certificate needs. `scripts/ensure_tls_cert.sh` now applies this
  unconditionally, including when certificate material already exists, so
  upgrading an install that predates this fix also picks up the corrected
  mode. Also made the DoQ/DoH3 disabled-checkbox enforcement symmetric:
  `encryption.enforce_capabilities()` (factored out of
  `deploy_encryption()`) is now also applied when saving Encryption
  Settings, so a forged POST setting `doq_enabled=1`/`doh3_enabled=1`
  cannot persist an unsupported protocol as enabled, not just fail to
  render it checked.
- Web interface usability pass from beta feedback:
  - Added a reusable pending-action button state (`app.js`): the submitted
    button disables immediately, its label swaps to an in-progress gerund
    with a spinner, `aria-busy` is set, and it's restored automatically if
    an async action fails without navigating away -- applied globally to
    every form submit (DNS settings, Local DNS, blocklists, imports,
    custom rules, cache, backups, encryption) instead of one-off handlers.
  - Restructured status-tile cards (`.card`/`.card__head`): component name
    centered on top, status badge centered directly below it instead of
    beside the name at an arbitrary offset, applied consistently across
    System Health, System Status, Encryption, Replication, Backup, and DNS
    Settings summary cards; list-content cards (e.g. Allowed Clients) are
    explicitly excluded, not blindly centered.
  - Added a shared `.actions-col` table utility (centered header, buttons,
    status labels, and overflow menus) applied to Local DNS, Blocklists
    (both tables), Custom Rules, DNS Settings upstreams, Backup, and
    Replication, replacing inconsistent per-page alignment.
  - Gave the collapsed-sidebar Logout control a recognizable icon, an
    accessible name and tooltip ("Log out"), and a hover/focus state
    matching other collapsed nav buttons -- it no longer collapses down to
    an unlabeled, easy-to-misclick box.
  - Made sidebar nav sections (DNS/Security/Operations/System) collapsible
    again after opening, including a section containing the active page
    (which stays visually identifiable via its own styling regardless of
    expanded state); expand/collapse state now persists across ordinary
    navigation via `localStorage`.
- Added a first-class Pi-hole Migration panel to Import and Migration,
  alongside AdGuard Home's, explaining the supported Pi-hole text-export
  format (adlists.list, whitelist/blacklist, regex.list including the
  wildcard-block idiom, custom.list, dnsmasq `cname=` lines) and warning
  that group assignments have no Alderpoint DNS equivalent. The Pi-hole
  importer backend and preview/apply/rollback pipeline already existed and
  needed no changes; only the dedicated UI panel (previously just a
  dropdown option with no format explanation) and end-to-end route tests
  against the synthetic Pi-hole fixture were added.
- Closed import-idempotency gaps found by re-importing the same AdGuard/
  Pi-hole data against an install that already has it: blocklist sources
  are now also matched by URL (not just name), so the same feed re-added
  under a different name is recognized and skipped instead of creating a
  second subscription; comment and invalid/unsupported custom-rule entries
  (previously exempt from duplicate detection) are now deduplicated the
  same way active rules already were. Local DNS records, client aliases,
  and upstream resolvers were already correctly deduplicated. Added tests
  proving that applying the same AdGuard or Pi-hole import twice, as two
  separate jobs, does not increase any destination table's row count.
- Added password confirmation to first-run setup: a typo is now caught
  before the administrator account is created instead of only being
  discoverable at the next login. Validated both client-side (native form
  validation) and server-side; the entered username is preserved and
  neither password value is echoed back on a failed submission; added a
  CSRF token to `/setup` (previously unenforced, since no session existed
  yet to bind one to -- `render()` now mints and persists an anonymous
  pre-login session on first visit specifically so this token is real);
  added an accessible show/hide toggle for password fields.
- Added System > Administration: change the administrator password
  (requires the current password, revokes every other active session
  automatically), an explicit "revoke all other sessions" action that
  doesn't touch the password, and a session list (start time, last seen,
  IP, client) and recent audit log, without ever exposing a raw session
  token. Sessions are now server-side rows (`sessions` table) referenced by
  an opaque id in the signed cookie, not cookie-embedded state, so they can
  actually be revoked individually. Added a root-only local recovery
  command, `alderpointdns admin reset-password` (`scripts/alderpointdns-
  admin`, installed to `/usr/sbin/alderpointdns`), for a forgotten
  password with no web-reachable route and no email dependency; it shares
  the exact same Argon2 implementation (`app/auth.py`) as the web app and
  revokes the account's existing sessions. `admins`/`login_attempts`/
  `sessions`/`admin_audit_log` remain excluded from backup archives by
  default, gated behind the existing `user_auth_data` component.
- Added System > Notifications: a provider-neutral framework (SMTP email
  and generic HTTP webhook, with Discord/Slack/Microsoft Teams/ntfy/
  Gotify/Pushover as webhook presets sharing the same delivery path) with
  per-event-category subscriptions and severity thresholds, cooldown and
  duplicate suppression, recovery notices, a local delivery history, and a
  test-send action. Provider secrets (SMTP passwords, webhook URLs -- most
  of these presets embed a bearer-equivalent token directly in the URL)
  are masked, write-only, and never rendered back, and are excluded from
  backup archives by default like other credential material. A new
  `alderpointdns-notify.timer` polls every 5 minutes and fires real,
  edge-detected notifications for service up/down/recovered, repeated
  restarts, blocklist/deploy failure, backup failure, upstream resolver
  degraded/all-unavailable, and replication delayed/failed; TLS
  expiry/low disk space/abnormal SERVFAIL rate are defined as subscribable
  categories but not yet evaluated (see `docs/known-limitations.md`).
- Fixed the AdGuard/Pi-hole importer reporting intentional public-IP Local
  DNS records (e.g. a VPN/WireGuard host record) under `Conflicts`, with
  the misleading final result `Applied with conflicts`, even though the
  record imported successfully and nothing actually conflicted. Local DNS
  data-quality findings are now severity-tagged (`local_dns.
  record_findings()`): genuine incompatibilities (duplicate hostname,
  CNAME clash, conflicting PTR, missing PTR target) remain conflicts and
  still require an explicit override; a public IP outside common private
  ranges is now a warning, shown separately, imported as requested, and
  never blocks creation -- including through the plain manual Local DNS
  "add record" form, which previously also wrongly required overriding a
  public IP. Import previews and job results now distinguish Conflicts,
  Warnings, and Unsupported as separate counts/sections instead of folding
  warnings into conflicts.
- Fixed a blocklist-source ambiguity where a subscription that legitimately
  compiles to zero active rules (e.g. an AdGuard-style source consisting
  entirely of `$dnsrewrite` rules Alderpoint DNS cannot express as RPZ
  block rules, or an IPv6-only hosts-format source) was indistinguishable
  from a fetch/parse failure. Health/status reporting for each source now
  reflects its actual state (real zero-rule vs. failed) instead of always
  reading as a generic failure, and IPv6 sinkhole-style hosts entries are
  recognized and compiled correctly rather than silently skipped.
- Fixed a production incident where the analytics writer thread could
  silently die (e.g. after a transient SQLite `database is locked` error)
  while the parent `alderpointdns-analytics` process kept running, so
  systemd and System Status both reported "active" with no query events
  actually being recorded. Root cause was a database-connection-handling
  defect shared across most of the web app's SQLite call sites: Python's
  `sqlite3.Connection` context manager only commits or rolls back on exit,
  it never closes the connection, so long-lived request handlers were
  quietly accumulating open file descriptors against the same database
  file. Every affected `connect()`/`db()` helper (web app, notifications,
  encryption, DNS cache, importer, upstream resolvers, blocklist
  categories, local DNS) now closes deterministically on exit, with an
  explicit `busy_timeout` and short-lived transactions. The analytics
  writer now retries transient lock errors with backoff, isolates
  retention-cleanup failures to a single cycle instead of ever giving up
  entirely, publishes an independent file-based heartbeat so its health can
  be read even when the database itself is unavailable, terminates and
  lets systemd restart it only after sustained, unrecoverable failure, and
  fires a notification and a correctly severity-tagged System Status entry
  (Warning for a recovered transient lock, Error for a terminated writer,
  Info for recovery) instead of misreporting a real failure as routine
  informational logging. Added deterministic connection-lifecycle tests,
  an end-to-end web-traffic file-descriptor regression test, and a
  concurrency test exercising real web requests against the live database
  while the analytics writer is simultaneously writing events and running
  retention cleanup under lock contention.
