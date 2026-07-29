# Live issues

- Management UI exposure now relies on pfSense VLAN/firewall policy. Verify the
  VM is reachable only from the intended management VLAN before production use.
- DNS listeners now bind to all interfaces. dnsdist allows RFC1918 private
  networks by default; verify pfSense rules before enabling allow-all mode.
- DNS hostname and production certificate data have not been provided.
- `systemd-resolved` is absent; explicit maintenance resolvers are used instead.
  Independence has been verified with BIND stopped.
- The Debian dnsdist package must be replaced by the official PowerDNS package;
  acceptance requires `dnsdist --version` to report `dns-over-quic`.
- Web cookies are not marked `Secure` in current lab HTTP mode. They must be
  marked `Secure` when the admin interface is served over HTTPS.
- Per-network policy runtime enforcement is not enabled yet; v1 now has the
  database and compiler-visible profile/category model needed to add it without
  a schema rewrite.

## Resolved during analytics implementation

- The dashboard now uses native SQLite-backed analytics with real dnsdist
  protobuf response events and aggregate dnsdist stats. Query log, top clients,
  top domains, top blocked domains, protocol usage, response-code tables,
  privacy modes, retention cleanup, database-size protection, and statistics
  settings are implemented without Prometheus, Grafana, Elasticsearch, or
  unbounded text logs.

## Resolved during post-reboot recovery

- Full VM reboot survival is verified for the combined stack. After reboot,
  `bindguard.service`, `dnsdist.service`, and `named.service` were active,
  listeners matched the intended topology, and the full acceptance
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
