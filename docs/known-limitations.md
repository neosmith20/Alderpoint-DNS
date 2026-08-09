# Known limitations

- The management UI and DNS listeners intentionally bind to VM interfaces.
  Your network firewall (VLAN/segmentation rules) must restrict who can
  reach them.
- The automatically generated self-signed certificate is not publicly trusted.
  Replace `/etc/alderpointdns/certs/alderpointdns-lab.crt` and
  `/etc/alderpointdns/certs/alderpointdns-lab.key` together when production TLS
  material is available.
- Per-network policy profiles and SafeSearch enforcement are modeled but not
  fully enforced at runtime yet.
- Import compatibility is intentionally conservative. Pi-hole text/list import
  covers adlist URLs, exact allow/block domains (bare or keyword form), regex
  block and regex allow lists (POSIX-ERE-compatible patterns, including the
  `(\.|^)domain$` wildcard idiom), custom.list hosts records, and
  `cname=alias,target[,ttl]` lines; gravity database internals are not read
  directly, and anything unrecognized is previewed as an explicit unsupported
  finding, not executed. Pi-hole group assignments and AdGuard client-scoped
  rules/settings ($client, per-client filtering, SafeSearch, upstreams) are
  preserved as explicit inactive findings because Alderpoint DNS has no
  per-client or per-group policy enforcement yet. AdGuard domain-specific
  upstream routing and encrypted upstream schemes that cannot be mapped
  directly are also reported rather than fabricated.
- System Status's Recent Logs is intentionally scoped to Alderpoint DNS's own
  four service units (`alderpointdns`, `alderpointdns-analytics`, `named`,
  `dnsdist`); it is not a general journal viewer and cannot show logs for
  other host services by design.
- System > Administration supports changing the administrator's password and
  revoking sessions, but not renaming the administrator account. Deferred
  deliberately: a rename would need to reconcile in-flight sessions and the
  audit log's `username` column (a point-in-time label, not a live foreign
  key) with the new name, and the local recovery CLI's `--username` targeting.
  Single-admin deployments are unaffected; revisit if multi-admin support is
  added.
- System > Notifications' event catalog includes TLS certificate expiry, low
  disk space, and abnormal SERVFAIL rate as subscribable categories, but no
  detector evaluates them yet -- only service up/down/recovered, repeated
  restarts, blocklist/deploy failure, backup failure, upstream resolver
  degraded/all-unavailable, and replication delayed/failed are actually
  wired to fire. Real detectors for the remaining three are follow-up work.
- Software Updates supports automatic *checking* only, on a
  configurable interval (`System > Software Updates`, default every 6
  hours). Unattended automatic *installation* is intentionally off by
  default and has no execution path in this release; every install
  requires an explicit administrator action (Download & Install Update,
  or a manual `.deb` upload). Automatic package rollback on a failed
  install is not implemented -- recovery after a failed install (past the
  install step) is via the mandatory pre-upgrade backup, which is always
  retained. A signed apt repository is not published; releases are
  distributed as checksummed `.deb` assets on GitHub Releases. See
  `docs/software-updates.md`.
- A native database restore is staged and atomically promoted against a
  private working copy, so an interrupted restore never leaves the live
  database partially applied -- but there is still no automatic *data*
  rollback for a restore interrupted *after* that atomic promotion point;
  such a case is reported honestly as requiring administrator
  verification rather than claimed as rolled back. See
  `docs/backup-recovery.md`.
