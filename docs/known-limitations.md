# Known limitations

- The management UI and DNS listeners intentionally bind to VM interfaces.
  pfSense VLAN/firewall rules must restrict who can reach them.
- The automatically generated self-signed certificate is not publicly trusted.
  Replace `/etc/bindguard/certs/bindguard-lab.crt` and
  `/etc/bindguard/certs/bindguard-lab.key` together when production TLS
  material is available.
- Per-network policy profiles and SafeSearch enforcement are modeled but not
  fully enforced at runtime yet.
- Local DNS hosts import currently provides preview support for hosts-style
  input. CSV import is the deployment-capable bulk import path.
