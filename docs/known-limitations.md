# Known limitations

- The management UI and DNS listeners intentionally bind to VM interfaces.
  pfSense VLAN/firewall rules must restrict who can reach them.
- The automatically generated self-signed certificate is not publicly trusted.
  Replace `/etc/bindguard/certs/bindguard-lab.crt` and
  `/etc/bindguard/certs/bindguard-lab.key` together when production TLS
  material is available.
- Per-network policy profiles and SafeSearch enforcement are modeled but not
  fully enforced at runtime yet.
- Import compatibility is intentionally conservative. Pi-hole text/list import
  covers adlist URLs, plain allow/block domains, and hosts-style local rewrites;
  unsupported regex/gravity database internals are previewed as skipped or
  unsupported, not executed. AdGuard domain-specific upstream routing and
  encrypted upstream schemes that cannot be mapped directly are also reported
  rather than fabricated.
