# Progress

- [x] Baseline inspection captured
- [x] Required project/state/log directory skeleton created
- [x] Local Git repository initialized on `main`
- [x] Baseline and architecture commit (`aaefc75`)
- [x] BIND backend installed, validated, and tested on `127.0.0.1:5353`
- [ ] dnsdist plain DNS
- [ ] Encrypted DNS
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
