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
