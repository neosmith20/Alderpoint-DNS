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
- Clients & Access (`docs/clients-and-access.md`) enforces DNS
  allow/deny per IPv4/IPv6/CIDR/persistent-client/ClientID at dnsdist. It
  does not (yet) support per-client SafeSearch, per-client filter/blocklist
  profiles, per-client upstream resolver selection, schedules/bedtimes, or
  filtering groups -- those remain future work, same as the broader
  per-network policy profiles above. A ClientID is a strong identifier, not
  an authentication credential: high entropy makes it very hard to guess,
  but it is not proof of possession, and DoH/DoT/DoQ ClientID identification
  requires dnsdist's SNI (DoT/DoQ) or HTTP path (DoH) support -- see
  `docs/clients-and-access.md` for exactly what this dnsdist build supports.
- Import compatibility is intentionally conservative. Pi-hole text/list import
  covers adlist URLs, exact allow/block domains (bare or keyword form), regex
  block and regex allow lists (POSIX-ERE-compatible patterns, including the
  `(\.|^)domain$` wildcard idiom), custom.list hosts records, and
  `cname=alias,target[,ttl]` lines; gravity database internals are not read
  directly, and anything unrecognized is previewed as an explicit unsupported
  finding, not executed. Alderpoint DNS's Clients & Access (see
  `docs/clients-and-access.md`) enforces per-client/per-network DNS
  allow/deny at dnsdist, and AdGuard persistent clients/allowed_clients/
  disallowed_clients migrate into it (weak ClientIDs under the 192-bit
  minimum are preserved as an inactive finding, never silently activated).
  Pi-hole group assignments and AdGuard's remaining client-scoped settings
  ($client rules, per-client filtering, SafeSearch, per-client upstreams)
  have no Alderpoint DNS equivalent yet and are preserved as explicit
  inactive findings, not executed. AdGuard domain-specific upstream routing
  and encrypted upstream schemes that cannot be mapped directly are also
  reported rather than fabricated.
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
