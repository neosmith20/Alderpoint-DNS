# Live issues

- Management CIDR has not been provided or safely inferred. Web access remains
  loopback-only.
- Allowed DNS client networks have not been provided. Client DNS access remains
  loopback-only.
- DNS hostname and production certificate data have not been provided.
- `systemd-resolved` is absent; explicit maintenance resolvers are used instead.
  Independence has been verified with BIND stopped.
- DoQ and DoH3 are unavailable in Debian dnsdist `1.9.15-0+deb13u1`; the
  binary contains the functions but reports DNS-over-QUIC and DNS-over-HTTP/3
  support is not present. DoH and DoT are operational.
- Web cookies are not marked `Secure` in current lab HTTP mode. They must be
  marked `Secure` when the admin interface is served over HTTPS.
- Query statistics are aggregate-only for v1. Full recent-query ingestion,
  top clients, top domains, and searchable history remain future work.
- Per-network policy runtime enforcement is not enabled yet; v1 now has the
  database and compiler-visible profile/category model needed to add it without
  a schema rewrite.

## Resolved during post-reboot recovery

- Full VM reboot survival is verified for the combined stack. After reboot,
  `bindguard.service`, `dnsdist.service`, and `named.service` were active,
  loopback listeners matched the intended topology, and the full acceptance
  suite passed with strengthened dnsdist protocol/security assertions.

## Resolved during public catalog preparation

- A curated 19-source public blocklist catalog is available through
  `/opt/bindguard/app/bindguard_compiler.py seed-public`. The catalog assigns
  categories and includes both `adguardteam.github.io` and GitHub raw URLs while
  preserving the faster one-source lab seed for routine acceptance runs.

## Resolved during policy preparation

- Policy categories, built-in trusted/standard/IoT/restricted profiles,
  profile-category mappings, and CIDR-to-profile network policy storage are
  initialized in SQLite and covered by unit tests.

## Resolved during BIND milestone

- Debian's `named` AppArmor profile initially denied the BindGuard log path.
  A narrow local profile permits only generated RPZ reads and BindGuard BIND
  log/statistics writes; confinement was not disabled.
