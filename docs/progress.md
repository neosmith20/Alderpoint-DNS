# Progress

- [x] Baseline inspection captured
- [x] Required project/state/log directory skeleton created
- [x] Local Git repository initialized on `main`
- [x] Baseline and architecture commit (`aaefc75`)
- [x] BIND backend installed, validated, and tested on `127.0.0.1:5353`
- [x] dnsdist plain DNS
- [x] Encrypted DNS where supported by installed package
- [ ] Blocklist compiler
- [ ] Safe deployment and rollback
- [ ] Web interface
- [ ] Authentication
- [ ] v1 acceptance suite

## Verified BIND milestone

- BIND 9.20.26 installed from Debian security packages.
- UDP and TCP recursion pass on `127.0.0.1:5353`.
- Listener audit confirms BIND has no non-loopback socket and does not occupy 53.
- DNSSEC-valid response has the AD flag.
- DNSSEC-invalid test returns `SERVFAIL`.
- Empty RPZ validates with `named-checkzone`.
- Configuration validates with `named-checkconf`.
- RNDC is restricted to loopback and returns healthy status.
- JSON statistics channel responds only on `127.0.0.1:8053`.
- AppArmor remains enabled with narrow BindGuard path rules.
- Service is enabled and survives a stop/start cycle.
- With BIND stopped, host resolution and an HTTPS download succeeded via
  `/etc/resolv.conf`; BIND was restarted and the complete suite passed again.

## Verified dnsdist milestone

- dnsdist 1.9.15 installed from Debian security packages and enabled.
- Client-facing listeners are lab-safe loopback only until allowed client
  networks are supplied:
  - UDP/TCP DNS on `127.0.0.1:53`
  - DoH on `127.0.0.1:443` path `/dns-query`
  - DoT on `127.0.0.1:853`
- BIND backend health check marks `127.0.0.1:5353` up.
- Access ACL is loopback only.
- Private-resolver dynamic rate limits are configured.
- Packet cache and local dnsdist stats API are configured.
- Temporary self-signed lab certificate validates against its private key.
- DoH and DoT pass with the lab CA explicitly trusted by the test client.
- DoQ and DoH3 are not present in the Debian package build; capability tests
  confirm dnsdist rejects those listeners with explicit unsupported-feature
  errors.
- Backend outage behavior is tested: stopping BIND prevents frontend
  resolution, restarting BIND restores dnsdist service.
- dnsdist restart test passes.
- Integrated BIND and dnsdist automated tests pass.
