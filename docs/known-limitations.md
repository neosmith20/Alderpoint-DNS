# Known limitations

- The management UI and DNS listeners intentionally bind to VM interfaces.
  pfSense VLAN/firewall rules must restrict who can reach them.
- The automatically generated self-signed certificate is not publicly trusted.
  Replace `/etc/alderpointdns/certs/alderpointdns-lab.crt` and
  `/etc/alderpointdns/certs/alderpointdns-lab.key` together when production TLS
  material is available.
- Per-network policy profiles and SafeSearch enforcement are modeled but not
  fully enforced at runtime yet.
- Import compatibility is intentionally conservative. Pi-hole text/list import
  covers adlist URLs, plain allow/block domains, and hosts-style local rewrites;
  unsupported regex/gravity database internals are previewed as skipped or
  unsupported, not executed. AdGuard domain-specific upstream routing and
  encrypted upstream schemes that cannot be mapped directly are also reported
  rather than fabricated.
- System Status's Recent Logs is intentionally scoped to Alderpoint DNS's own
  four service units (`alderpointdns`, `alderpointdns-analytics`, `named`,
  `dnsdist`); it is not a general journal viewer and cannot show logs for
  other host services by design.
