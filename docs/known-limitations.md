# Known limitations

- The management UI and DNS listeners intentionally bind to VM interfaces.
  pfSense VLAN/firewall rules must restrict who can reach them.
- The automatically generated self-signed certificate is not publicly trusted.
  Replace `/etc/bindguard/certs/bindguard-lab.crt` and
  `/etc/bindguard/certs/bindguard-lab.key` together when production TLS
  material is available.
- Query statistics are aggregate-only; full query history and top-client/domain
  views are future work.
- Per-network policy profiles and SafeSearch enforcement are modeled as future
  work but not fully implemented.
