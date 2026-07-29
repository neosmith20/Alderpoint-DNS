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
- Full VM reboot survival remains pending for the combined stack.
- Only one public blocklist is seeded for lab validation. The UI and importer
  can add the user's remaining public URLs once the web interface exists.

## Resolved during BIND milestone

- Debian's `named` AppArmor profile initially denied the BindGuard log path.
  A narrow local profile permits only generated RPZ reads and BindGuard BIND
  log/statistics writes; confinement was not disabled.
